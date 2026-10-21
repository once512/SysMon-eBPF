#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One combined service: repeated canary response/release, scoped writer and fanotify audit."""
import argparse
from contextlib import ExitStack
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
from canary_response import ResponseProcess
from management_harness import call
from response_map import ResponseMap, response_ids


def hashes(repo, build):
    paths = [repo / 'CMakeLists.txt']
    for directory in ('src', 'eBPF', 'include', 'tests', 'tools'):
        paths += [path for path in (repo / directory).rglob('*')
                  if path.is_file() and path.suffix in ('.c', '.cpp', '.h', '.py', '.dict')]
    paths += [build / name for name in ('secmon', 'secmon-response-scenario', 'secmon-analyzer',
                                      'secmon-policyctl', 'secmon-vault-session', 'secmon.bpf.o', 'secmon.skel.h')]
    return {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(set(paths))}


def last_counter(diagnostics, name):
    values = re.findall(r'(?<![a-z_])' + re.escape(name) + r'=(\d+)', diagnostics)
    assert values, name
    return int(values[-1])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, default=Path('build'))
    parser.add_argument('--duration', type=int, default=900)
    parser.add_argument('--artifact-dir', type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and __debug__
    assert 5 <= args.duration <= 1800
    build = args.build_dir.resolve()
    repo = Path(__file__).resolve().parent.parent
    artifact = args.artifact_dir.resolve()
    artifact.mkdir(exist_ok=True)
    before_hashes = hashes(repo, build)
    (artifact / 'source_sha256.json').write_text(json.dumps(before_hashes, indent=2) + '\n')
    fd_start = len(os.listdir('/proc/self/fd'))
    started = time.monotonic()
    cycles = starts = commands = failures = reloads = 0
    epoch = revision = 1
    with tempfile.TemporaryDirectory(prefix='secmon-canary-soak-live-') as tmp, ExitStack() as stack:
        root = Path(tmp)
        program = root / 'client'
        shutil.copyfile(build / 'secmon-response-scenario', program)
        program.chmod(0o755)
        trap, victim, ordinary, policy = [root / name for name in ('trap', 'victim', 'ordinary', 'policy')]
        for path in (trap, victim, ordinary):
            path.write_bytes(b'original' + b'\0' * 8192)
        actor = stack.enter_context(ResponseProcess(program, trap, victim))
        outsider = stack.enter_context(ResponseProcess(program, trap, victim))
        plain = stack.enter_context(ResponseProcess(program, ordinary, victim))
        actors = (actor, outsider, plain)
        reference = os.pidfd_open(actor.process.pid)
        actor_inode = os.fstat(reference).st_ino
        os.close(reference)
        management = root / 'management'
        management.mkdir(mode=0o700)
        control = management / 'control'
        def publish(config_epoch, duration=5000, extra='', enabled=True):
            text = f'revision {revision}\n' + ('canary' if enabled else 'protect') + f' "{trap}"\n'
            text += f'protect "{victim}"\nprotect "{ordinary}"\n'
            text += f'allow-writer "{program}" 0 "{victim}" all\n'
            text += f'fanotify-file "{victim}"\nfanotify-decision allow\n'
            if enabled:
                text += f'canary-response {config_epoch} {duration}\n'
            stage = root / 'stage'
            stage.write_text(text + extra)
            stage.chmod(0o600)
            stage.replace(policy)
        publish(epoch)
        output = stack.enter_context((artifact / 'audit.jsonl').open('w+'))
        errors = stack.enter_context((artifact / 'diagnostics.log').open('w+'))
        before_maps = response_ids()
        process = subprocess.Popen([str(build / 'secmon'), '--policy', str(policy), '--control', str(control),
                         '--audit-permissions', '--requester-pidfd', '--run-for', str(args.duration + 120)],
                         stdout=output, stderr=errors)
        stopped = False
        def stop():
            nonlocal stopped
            if process.poll() is None:
                call(build / 'secmon', 'stop', control)
                process.wait(timeout=10)
            assert process.returncode == 0
            stopped = True
        stack.callback(stop)
        until = time.monotonic() + 10
        while True:
            errors.seek(0)
            diagnostic = errors.read()
            if 'Service active; bpf=1 fanotify=1' in diagnostic:
                break
            assert process.poll() is None and time.monotonic() < until, diagnostic
            time.sleep(0.02)
        created = response_ids() - before_maps
        assert len(created) == 1
        mapping = stack.enter_context(ResponseMap(next(iter(created))))
        initial = call(build / 'secmon', 'status', control)
        assert initial['backend'] == 'combined' and initial['requester_pidfd'] and initial['canary_paths'] == 1
        baseline = len(os.listdir(f'/proc/{process.pid}/fd'))
        def expect(client, operations, result):
            nonlocal commands
            for operation in operations:
                actual = client.request(operation)
                commands += 1
                assert actual == result, (cycles, operation, actual, result)
        def reload(expected='ok'):
            nonlocal reloads, failures
            reply = call(build / 'secmon', 'reload', control, expected)
            if expected == 'ok':
                reloads += 1
                assert reply['revision'] == revision
            else:
                failures += 1
            return reply
        stop_at = time.monotonic() + args.duration
        journal = stack.enter_context((artifact / 'cycles.jsonl').open('w'))
        while time.monotonic() < stop_at:
            epoch += 1; revision += 1
            publish(epoch); reload()
            expect(actor, 'wWotm', 0)
            expect(outsider, 'ow', 0)
            expect(plain, 'c', errno.EACCES)
            expect(plain, 'w', 0)
            expect(actor, 'k', errno.EACCES)
            starts += 1
            current = mapping.entries()
            assert set(current) == {actor_inode} and current[actor_inode][0] == epoch, current
            expect(actor, 'wWofFxXtmM', errno.EACCES)
            expect(actor, 'rRhHaA', 0)
            expect(outsider, 'w', 0)
            revision += 1
            publish(epoch); reload()  # Unrelated revision never renews.
            assert mapping.entries() == current
            if cycles % 7 == 0:
                revision += 1
                publish(epoch + 1, extra=f'protect "{root / "missing"}"\n')
                reload('prepare_failed')
                assert mapping.entries() == current
                expect(actor, 'wW', errno.EACCES)
            if cycles % 9 == 0:
                revision += 1
                publish(epoch, duration=6000); reload('prepare_failed')
                expect(actor, 'w', errno.EACCES)
            if cycles % 25 == 0:
                epoch += 1; revision += 1
                publish(epoch, duration=200); reload()
                expect(actor, 'k', errno.EACCES)
                starts += 1
                deadline = mapping.entries()[actor_inode][1]
                expect(actor, 'w', errno.EACCES)
                time.sleep(max(0, (deadline + 30_000_000 - time.clock_gettime_ns(time.CLOCK_BOOTTIME)) / 1e9))
                expect(actor, 'wW', 0)
                assert mapping.entries()[actor_inode][1] == deadline
            if cycles % 50 == 0:
                revision += 1
                publish(0, enabled=False); reload()
                expect(actor, 'w', 0)
                expect(actor, 'c', errno.EACCES)
                revision += 1
                publish(epoch); reload('prepare_failed')  # Retired token cannot reopen.
            state = call(build / 'secmon', 'status', control)
            assert state['response_started'] == starts and state['response_failed'] == 0, state
            assert state['reloads'] == reloads and state['rejections'] == failures, state
            assert len(os.listdir(f'/proc/{process.pid}/fd')) == baseline
            cycles += 1
            journal.write(json.dumps({'cycle': cycles, 'epoch': epoch, 'revision': state['revision'],
                    'response_started': starts, 'response_denied': state['response_denied'],
                    'reloads': reloads, 'rejections': failures, 'commands': commands,
                    'service_fds': baseline, 'elapsed': round(time.monotonic() - started, 3)}) + '\n')
            journal.flush()
            if cycles % 100 == 0:
                print(f'cycle={cycles} starts={starts} commands={commands} seconds={time.monotonic()-started:.1f}', flush=True)
        final_status = call(build / 'secmon', 'status', control)
        for client in actors:
            client.process.stdin.write('q\n'); client.process.stdin.flush()
            client.process.wait(timeout=5)
            assert client.process.returncode == 0
        mapping.wait_keys([])
        stop()
        errors.seek(0); diagnostic = errors.read()
        output.seek(0); events = [json.loads(line) for line in output]
        files = [event for event in events if event['event'] == 'file_denied']
        tasks = [event for event in events if event['event'] == 'process_response_denied']
        permissions = [event for event in events if event['event'] == 'fanotify_decision']
        assert sum(event.get('response_started', False) for event in files) == starts
        assert not any(event.get('response_failed') for event in files)
        assert last_counter(diagnostic, 'response_started') == starts
        assert last_counter(diagnostic, 'response_failed') == 0
        assert last_counter(diagnostic, 'response_denied') == sum(event.get('response_blocked', False) for event in files) + len(tasks)
        assert last_counter(diagnostic, 'policy_denied') == len(files)
        for name in ('ringbuf_dropped', 'baseline_update_failed', 'audit_dropped', 'audit_invalid', 'audit_queued', 'audit_errno'):
            assert last_counter(diagnostic, name) == 0, (name, diagnostic)
        assert last_counter(diagnostic, 'audit_written') == len(events)
        assert len(permissions) == final_status['allowed'] + final_status['denied'] and not final_status['denied']
        assert permissions and all(event['requester_process_inode'] for event in permissions)
        assert all(event['process_inode'] == actor_inode for event in files if event.get('response_started'))
        after_hashes = hashes(repo, build)
        assert before_hashes == after_hashes, 'source/binary changed during sustained validation'
        summary = {'passed': True, 'elapsed_seconds': round(time.monotonic() - started, 3),
                   'cycles': cycles, 'commands': commands, 'response_started': starts,
                   'file_denied': len(files), 'task_denied': len(tasks), 'permission_decisions': len(permissions),
                   'audit_records': len(events), 'reloads': reloads, 'rejections': failures,
                   'service_fd_baseline': baseline, 'source_binary_hashes': len(before_hashes),
                   'final_status': final_status}
    summary['controller_fds_start'] = fd_start
    summary['controller_fds_end'] = len(os.listdir('/proc/self/fd'))
    assert summary['controller_fds_start'] == summary['controller_fds_end']
    (artifact / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    manifest = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in sorted(artifact.iterdir()) if path.is_file()}
    (artifact / 'artifact_sha256.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(summary), flush=True)


if __name__ == '__main__':
    main()
