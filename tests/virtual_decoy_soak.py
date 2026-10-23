#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One 64-file synthetic view and one combined service, bounded response churn."""
import argparse
from contextlib import ExitStack
import errno
import hashlib
import json
import os
import re
import signal
from pathlib import Path
import subprocess
import tempfile
import time
from canary_soak import hashes
from decoy_harness import DecoyView, mounted
from management_harness import call
from response_map import ResponseMap, response_ids
from virtual_decoy import DecoyActor


def snapshots(repo, build):
    result = hashes(repo, build)
    for name in ('secmon-decoyfs', 'secmon-virtual-decoy-scenario'):
        path = build / name
        result[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, default=Path('build'))
    parser.add_argument('--duration', type=int, default=1800)
    parser.add_argument('--artifact-dir', type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and __debug__ and 5 <= args.duration <= 3480
    build, repo, artifact = args.build_dir.resolve(), Path(__file__).resolve().parent.parent, args.artifact_dir.resolve()
    artifact.mkdir()  # Never overwrite a prior evidence directory.
    before_hashes = snapshots(repo, build)
    (artifact / 'source_sha256.json').write_text(json.dumps(before_hashes, indent=2) + '\n')
    fd_start = len(os.listdir('/proc/self/fd'))
    started = time.monotonic()
    cycles = commands = starts = reloads = failures = sweeps = sweep_permissions = 0
    revision = epoch = 1
    with tempfile.TemporaryDirectory(prefix='secmon-virtual-soak-') as tmp, ExitStack() as stack:
        root = Path(tmp); root.chmod(0o755)
        mountpoint = root / 'view'; mountpoint.mkdir(mode=0o755)
        names = tuple(f'file-{i:02d}.csv' for i in range(64))
        provider = stack.enter_context(DecoyView(build / 'secmon-decoyfs', mountpoint, names, allow_other=True))
        targets = [mountpoint / name for name in names]
        identities = {(os.major(path.stat().st_dev), os.minor(path.stat().st_dev), path.stat().st_ino) for path in targets}
        content_hashes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in targets}
        victim, policy = root / 'victim', root / 'policy'
        victim.write_bytes(b'original' + b'\0' * 8192); victim.chmod(0o666)
        actors, actor_inodes = [], {}
        for index in range(8):
            prefix = [] if index % 2 == 0 else ['setpriv', '--reuid=65534', '--regid=65534', '--clear-groups']
            actor = stack.enter_context(DecoyActor(build / 'secmon-virtual-decoy-scenario', targets[index * 9], victim, prefix))
            actors.append(actor)
            reference = os.pidfd_open(actor.process.pid)
            actor_inodes[actor.process.pid] = os.fstat(reference).st_ino
            os.close(reference)
        management = root / 'management'; management.mkdir(mode=0o700)
        control = management / 'control'
        def publish(config_epoch, duration=30000, extra='', enabled=True):
            text = f'revision {revision}\n'
            for path in targets:
                text += ('canary' if enabled else 'protect') + f' "{path}"\n'
                text += f'fanotify-file "{path}"\n'
            text += 'fanotify-event access\nfanotify-decision allow\n'
            if enabled: text += f'canary-response {config_epoch} {duration}\n'
            stage = root / 'stage'; stage.write_text(text + extra); stage.chmod(0o600); stage.replace(policy)
        publish(epoch)
        output = stack.enter_context((artifact / 'audit.jsonl').open('w+'))
        errors = stack.enter_context((artifact / 'diagnostics.log').open('w+'))
        previous_maps = response_ids()
        process = subprocess.Popen([str(build / 'secmon'), '--policy', str(policy), '--control', str(control),
                                    '--audit-permissions', '--requester-pidfd',
                                    '--run-for', str(args.duration + 120)], stdout=output, stderr=errors)
        def stop():
            if process.poll() is None:
                call(build / 'secmon', 'stop', control); process.wait(timeout=10)
            assert process.returncode == 0
        stack.callback(stop)
        until = time.monotonic() + 10
        while True:
            errors.seek(0); diagnostic = errors.read()
            if 'Service active; bpf=1 fanotify=1' in diagnostic: break
            assert process.poll() is None and time.monotonic() < until, diagnostic
            time.sleep(.02)
        created = response_ids() - previous_maps
        assert len(created) == 1
        mapping = stack.enter_context(ResponseMap(created.pop()))
        initial = call(build / 'secmon', 'status', control)
        assert initial['fanotify_targets'] == initial['canary_paths'] == 64 and initial['requester_pidfd']
        baseline = len(os.listdir(f'/proc/{process.pid}/fd'))
        provider_baseline = len(os.listdir(f'/proc/{provider.process.pid}/fd'))
        def rss(pid):
            for line in Path(f'/proc/{pid}/status').read_text().splitlines():
                if line.startswith('VmRSS:'):
                    return int(line.split()[1])
            raise AssertionError('missing resident memory measurement')
        initial_rss = rss(process.pid), rss(provider.process.pid)
        peak_rss = list(initial_rss)
        (artifact / 'identities.json').write_text(json.dumps({'actors': actor_inodes, 'targets': sorted(identities),
                   'actor_uids': {actor.process.pid: 0 if index % 2 == 0 else 65534 for index, actor in enumerate(actors)},
                   'controller_pid': os.getpid(), 'provider_pid': provider.process.pid, 'service_pid': process.pid}, indent=2) + '\n')
        def expect(client, operations, result):
            nonlocal commands
            for operation in operations:
                actual = client.request(operation); commands += 1
                assert actual == result, (cycles, operation, actual, result)
        def reload(expected='ok'):
            nonlocal reloads, failures
            reply = call(build / 'secmon', 'reload', control, expected)
            if expected == 'ok':
                reloads += 1; assert reply['revision'] == revision
            else: failures += 1
            return reply
        stop_at = time.monotonic() + args.duration
        journal = stack.enter_context((artifact / 'cycles.jsonl').open('w'))
        while time.monotonic() < stop_at:
            actor, outsider = actors[cycles % 8], actors[(cycles + 1) % 8]
            epoch += 1; revision += 1; publish(epoch); reload()
            expect(actor, 'srw', 0)
            expect(actor, 'i', errno.EACCES)  # unknown ioctl never starts a response.
            expect(actor, 'w', 0)
            expect(actor, 'ctunladmk'[cycles % 9], errno.EACCES); starts += 1
            current = mapping.entries()
            active = current[actor_inodes[actor.process.pid]]
            assert active[0] == epoch and set(current) <= set(actor_inodes.values())
            expect(actor, 'wfx', errno.EACCES)
            expect(actor, 'rs', 0)
            expect(outsider, 'w', 0)
            revision += 1; publish(epoch); reload()
            assert mapping.entries() == current
            if cycles % 7 == 0:
                revision += 1; publish(epoch + 1, extra=f'protect "{root / "missing"}"\n')
                reload('prepare_failed'); assert mapping.entries() == current
                expect(actor, 'w', errno.EACCES)
            expiry_deadline = 0
            if cycles % 11 == 0:
                epoch += 1; revision += 1; publish(epoch, duration=100); reload()
                expect(actor, 'c', errno.EACCES); starts += 1
                deadline = expiry_deadline = mapping.entries()[actor_inodes[actor.process.pid]][1]
                expect(actor, 'w', errno.EACCES)
                time.sleep(max(0, (deadline + 20_000_000 - time.clock_gettime_ns(time.CLOCK_BOOTTIME)) / 1e9))
                expect(actor, 'w', 0)
            if cycles % 23 == 0:
                revision += 1; publish(0, enabled=False); reload()
                expect(actor, 'c', errno.EACCES); expect(actor, 'w', 0)
                revision += 1; publish(epoch); reload('prepare_failed')
            if cycles % 50 == 0:
                before = call(build / 'secmon', 'status', control)['allowed']
                assert sorted(os.listdir(mountpoint)) == list(names)
                for path in targets:
                    assert hashlib.sha256(path.read_bytes()).hexdigest() == content_hashes[path.name]
                after = call(build / 'secmon', 'status', control)['allowed']
                sweep_permissions += after - before; sweeps += 1
            state = call(build / 'secmon', 'status', control)
            assert state['response_started'] == starts and state['response_failed'] == 0, state
            assert state['reloads'] == reloads and state['rejections'] == failures
            assert state['allowed'] == 2 * (cycles + 1) + sweep_permissions and state['denied'] == state['pending'] == 0
            assert len(os.listdir(f'/proc/{process.pid}/fd')) == baseline
            assert len(os.listdir(f'/proc/{provider.process.pid}/fd')) == provider_baseline
            memory = rss(process.pid), rss(provider.process.pid)
            peak_rss = [max(old, new) for old, new in zip(peak_rss, memory)]
            cycles += 1
            journal.write(json.dumps({'cycle': cycles, 'actor_pid': actor.process.pid, 'epoch': epoch,
                'revision': state['revision'], 'response_started': starts, 'response_deadline_boot_ns': active[1],
                'expiry_deadline_boot_ns': expiry_deadline,
                'response_denied': state['response_denied'], 'reloads': reloads, 'rejections': failures,
                'commands': commands, 'service_fds': baseline, 'provider_fds': provider_baseline,
                'service_rss_kib': memory[0], 'provider_rss_kib': memory[1], 'response_entries': len(current),
                'permissions': state['allowed'], 'sweep_permissions': sweep_permissions,
                'elapsed': round(time.monotonic() - started, 3)}) + '\n'); journal.flush()
            if cycles % 100 == 0:
                print(f'cycle={cycles} starts={starts} commands={commands} seconds={time.monotonic()-started:.1f}', flush=True)
        final_status = call(build / 'secmon', 'status', control)
        for name in ('diagnostic_dropped', 'diagnostic_invalid', 'diagnostic_errno', 'overflow', 'backend_error_requests'):
            assert final_status[name] == 0, name
        for actor in actors:
            actor.process.stdin.write('q\n'); actor.process.stdin.flush(); actor.process.wait(timeout=5)
            assert actor.process.returncode == 0
        mapping.wait_keys([])
        stop()
        errors.seek(0)
        diagnostic_counters = {}
        pattern = re.compile(r'(?<![a-z_])([a-z_]+)=(\d+)')
        for line in errors:
            for match in pattern.finditer(line):
                diagnostic_counters[match[1]] = int(match[2])
        # Stream the raw audit: a one-hour run must not retain every JSON
        # object in RAM just to count and verify it at shutdown.
        files = tasks = permissions = total = observed_starts = blocked = 0
        output.seek(0)
        for line in output:
            event = json.loads(line); total += 1
            if event['event'] == 'file_denied':
                files += 1
                observed_starts += event.get('response_started', False)
                blocked += event.get('response_blocked', False)
                assert not event.get('response_failed')
                assert event['process_inode'] == actor_inodes[event['pid']]
                if event.get('canary_hit'):
                    assert (event['dev_major'], event['dev_minor'], event['ino']) in identities
            elif event['event'] == 'process_response_denied':
                tasks += 1
                assert event['process_inode'] == actor_inodes[event['pid']]
            elif event['event'] == 'fanotify_decision':
                permissions += 1
                assert event['requester_process_inode'] and event['decision'] == 'allow'
                assert (event['major'], event['minor'], event['inode']) in identities
        extra7, extra11, extra23 = ((cycles + divisor - 1) // divisor for divisor in (7, 11, 23))
        assert commands == 12 * cycles + extra7 + 3 * extra11 + 2 * extra23
        assert files == 3 * cycles + extra7 + 2 * extra11 + extra23
        assert tasks == 2 * cycles
        assert starts == cycles + extra11 == observed_starts
        assert permissions == final_status['allowed'] == 2 * cycles + sweep_permissions
        assert diagnostic_counters['response_started'] == starts
        assert diagnostic_counters['response_denied'] == blocked + tasks
        assert diagnostic_counters['policy_denied'] == files
        assert diagnostic_counters['audit_written'] == total
        for name in ('response_failed', 'ringbuf_dropped', 'baseline_update_failed', 'audit_dropped', 'audit_invalid', 'audit_queued', 'audit_errno'):
            assert diagnostic_counters[name] == 0, name
        assert before_hashes == snapshots(repo, build), 'source/binary changed during sustained validation'
        summary = {'passed': True, 'elapsed_seconds': round(time.monotonic() - started, 3), 'cycles': cycles,
                   'commands': commands, 'response_started': starts, 'file_denied': files, 'task_denied': tasks,
                   'permission_decisions': permissions, 'audit_records': total, 'reloads': reloads,
                   'rejections': failures, 'sweeps': sweeps, 'sweep_permissions': sweep_permissions,
                   'service_fd_baseline': baseline, 'provider_fd_baseline': provider_baseline,
                   'service_rss_initial_kib': initial_rss[0], 'provider_rss_initial_kib': initial_rss[1],
                   'service_rss_peak_kib': peak_rss[0], 'provider_rss_peak_kib': peak_rss[1],
                   'source_binary_hashes': len(before_hashes), 'response_map_empty_after_exit': True, 'final_status': final_status}
    assert not mounted(mountpoint)
    summary['controller_fds_start'] = fd_start
    summary['controller_fds_end'] = len(os.listdir('/proc/self/fd'))
    assert summary['controller_fds_start'] == summary['controller_fds_end']
    (artifact / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    manifest = {}
    for path in sorted(artifact.iterdir()):
        if path.is_file():
            digest = hashlib.sha256()
            with path.open('rb') as source:
                for block in iter(lambda: source.read(1024 * 1024), b''):
                    digest.update(block)
            manifest[path.name] = digest.hexdigest()
    (artifact / 'artifact_sha256.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(summary), flush=True)


if __name__ == '__main__':
    def interrupted(signum, _frame):
        raise KeyboardInterrupt(f'sustained test interrupted by signal {signum}')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    main()
