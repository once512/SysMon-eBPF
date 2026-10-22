#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One frozen instance: metadata/alternate-I/O triggers, native+compat and policy churn."""
import argparse
from collections import Counter
from contextlib import ExitStack
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from canary_soak import hashes, last_counter
from file_metadata import ACL, OPERATIONS, MetadataProcess, snapshot
from management_harness import call
from response_map import ResponseMap, response_ids


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, default=Path('build'))
    parser.add_argument('--duration', type=int, default=1800)
    parser.add_argument('--artifact-dir', type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and __debug__ and 5 <= args.duration <= 3000
    build = args.build_dir.resolve(); repo = Path(__file__).resolve().parent.parent
    artifact = args.artifact_dir.resolve(); artifact.mkdir(exist_ok=True)
    def source_hashes():
        result = hashes(repo, build)
        for name in ('secmon-metadata-scenario', 'secmon-metadata-compat'):
            p = build / name; result[str(p)] = hashlib.sha256(p.read_bytes()).hexdigest()
        return result
    before_hashes = source_hashes()
    (artifact / 'source_sha256.json').write_text(json.dumps(before_hashes, indent=2) + '\n')
    fd_start = len(os.listdir('/proc/self/fd'))
    cycles = commands = expected_denials = starts = reloads = rejections = 0
    revision = epoch = 1
    trigger_counts = Counter()
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='secmon-metadata-soak-live-') as temporary, ExitStack() as stack:
        root = Path(temporary)
        programs = [root / n for n in ('native', 'compat', 'outsider')]
        for program, name in zip(programs, ('secmon-metadata-scenario', 'secmon-metadata-compat', 'secmon-metadata-scenario')):
            shutil.copyfile(build / name, program); program.chmod(0o755)
        trap, victim, donor = [root / n for n in ('trap', 'victim', 'donor')]
        for path in (trap, victim, donor):
            path.write_bytes(b'A' * 8192)
            os.setxattr(path, 'user.secmon', b'original')
            os.setxattr(path, 'system.posix_acl_access', ACL)
        original = snapshot(trap)
        native = stack.enter_context(MetadataProcess(programs[0], (trap, victim, donor)))
        compat = stack.enter_context(MetadataProcess(programs[1], (trap, victim)))
        outsider = stack.enter_context(MetadataProcess(programs[2], (trap, victim, donor)))
        clients = (native, compat, outsider)
        identities = {}
        for name, client in zip(('native', 'compat', 'outsider'), clients):
            fd = os.pidfd_open(client.process.pid)
            identities[name] = os.fstat(fd).st_ino; os.close(fd)
        policy, control = root / 'policy', root / 'control'
        def publish(token, duration=5000, enabled=True, extra=''):
            rows = f'revision {revision}\n' + ('canary' if enabled else 'protect') + f' "{trap}"\nprotect "{victim}"\n'
            for program in programs: rows += f'allow-writer "{program}" 0 "{victim}" all\n'
            if enabled: rows += f'canary-response {token} {duration}\n'
            stage = root / 'stage'; stage.write_text(rows + extra); stage.chmod(0o600); stage.replace(policy)
        publish(epoch)
        output = stack.enter_context((artifact / 'audit.jsonl').open('w+'))
        errors = stack.enter_context((artifact / 'diagnostics.log').open('w+'))
        journal = stack.enter_context((artifact / 'journal.jsonl').open('w+'))
        before_maps = response_ids()
        process = subprocess.Popen([str(build / 'secmon'), '--bpf-only', '--policy', str(policy), '--control', str(control),
                                    '--run-for', str(args.duration + 120)], stdout=output, stderr=errors)
        def stop():
            if process.poll() is None:
                call(build / 'secmon', 'stop', control); process.wait(timeout=10)
            assert process.returncode == 0
        stack.callback(stop)
        deadline = time.monotonic() + 10
        while True:
            errors.seek(0); diagnostic = errors.read()
            if 'Service active; bpf=1 fanotify=0' in diagnostic: break
            assert process.poll() is None and time.monotonic() < deadline, diagnostic
            time.sleep(0.02)
        maps = response_ids() - before_maps; assert len(maps) == 1
        mapping = stack.enter_context(ResponseMap(next(iter(maps))))
        baseline = len(os.listdir(f'/proc/{process.pid}/fd'))
        def expect(client, command, expected=0):
            nonlocal commands, expected_denials
            result = client.request(command); commands += 1
            assert result == expected, (cycles, command, result, expected)
            if expected == errno.EACCES: expected_denials += 1
        def reload(token, duration=5000, enabled=True, extra='', code='ok'):
            nonlocal revision, reloads, rejections
            revision += 1; publish(token, duration, enabled, extra)
            result = call(build / 'secmon', 'reload', control, code)
            if code == 'ok': reloads += 1
            else: rejections += 1
            return result
        triggers = {**OPERATIONS, **{c: ('write', 2) for c in 'vfbenpt'}}
        blocked = [c + '1' for c in triggers] + ['g1', 'h1', 'u1', 'w1']
        until = time.monotonic() + args.duration
        while time.monotonic() < until:
            duration = 250 if cycles % 17 == 0 else 5000
            epoch += 1; reload(epoch, duration)
            for command in ('g', 'h'): expect(native, command)
            expect(compat, 'g')
            expect(native, 'u', errno.EACCES); expect(compat, 'u', errno.EACCES)
            command = tuple(triggers)[cycles % len(triggers)]
            expect(native, command, errno.EACCES); starts += 1; trigger_counts[command] += 1
            for denied in blocked: expect(native, denied, errno.EACCES)
            expect(compat, 'v'); expect(outsider, 'w1')
            expect(compat, 'i', errno.EACCES); starts += 1
            for denied in 'gvwu': expect(compat, denied, errno.EACCES)
            if cycles % 3 == 0:
                reload(epoch, duration)
                expect(native, 'w1', errno.EACCES); expect(compat, 'v', errno.EACCES)
            if cycles % 7 == 0:
                reload(epoch, duration + 1, code='prepare_failed')
                expect(native, 'w1', errno.EACCES)
            if cycles % 11 == 0:
                reload(epoch + 1, duration, extra=f'protect "{root / "missing"}"\n', code='prepare_failed')
                expect(compat, 'v', errno.EACCES)
            if cycles % 17 == 0:
                time.sleep(0.32)
                expect(native, 'w1'); expect(compat, 'v')
                expect(native, 'x', errno.EACCES); starts += 1; trigger_counts['expiry-x'] += 1
                expect(native, 'w1', errno.EACCES); expect(compat, 'v')
            if cycles % 29 == 0:
                reload(epoch, enabled=False)
                expect(native, 'w1'); expect(compat, 'v')
                reload(epoch, duration, code='prepare_failed')
                expect(native, 'w1')
            state = call(build / 'secmon', 'status', control)
            assert state['response_started'] == starts and state['response_failed'] == 0, state
            assert state['reloads'] == reloads and state['rejections'] == rejections, state
            assert len(os.listdir(f'/proc/{process.pid}/fd')) == baseline
            assert snapshot(trap) == original, 'trap modified'
            mapping.wait_keys([identities['native'], identities['compat']])
            cycles += 1
            journal.write(json.dumps(dict(cycle=cycles, trigger=command, epoch=epoch, duration_ms=duration,
                         revision=state['revision'], commands=commands, file_denied=expected_denials,
                         response_started=starts, reloads=reloads, rejections=rejections,
                         service_fds=baseline, elapsed=round(time.monotonic()-started, 3))) + '\n'); journal.flush()
            if cycles % 100 == 0: print(f'cycle={cycles} starts={starts} commands={commands} seconds={time.monotonic()-started:.1f}', flush=True)
        final_status = call(build / 'secmon', 'status', control)
        for client in clients:
            client.process.stdin.write('q\n'); client.process.stdin.flush(); client.process.wait(timeout=5)
            assert client.process.returncode == 0
        mapping.wait_keys([]); stop()
        errors.seek(0); diagnostic = errors.read()
        counts = Counter(); observed_starts = Counter(); operations = Counter(); blocked_count = 0
        output.seek(0)
        for line in output:
            event = json.loads(line); counts[event['event']] += 1
            if event['event'] == 'file_denied':
                operations[event['operation']] += 1
                assert not event['response_failed']
                if event['response_started']: observed_starts[event['process_inode']] += 1
                blocked_count += event['response_blocked']
                if event['operation'] == 21: assert not event['canary_hit']
        assert counts['file_denied'] == expected_denials
        assert sum(observed_starts.values()) == starts
        assert set(observed_starts) == {identities['native'], identities['compat']}
        assert last_counter(diagnostic, 'response_started') == starts
        assert last_counter(diagnostic, 'policy_denied') == expected_denials
        assert last_counter(diagnostic, 'response_denied') == blocked_count
        assert last_counter(diagnostic, 'audit_written') == sum(counts.values())
        for name in ('response_failed', 'ringbuf_dropped', 'baseline_update_failed', 'audit_dropped', 'audit_invalid', 'audit_queued', 'audit_errno'):
            assert last_counter(diagnostic, name) == 0, (name, diagnostic)
        assert source_hashes() == before_hashes, 'source/binary changed during sustained validation'
        summary = dict(passed=True, requested_seconds=args.duration, elapsed_seconds=round(time.monotonic()-started, 3),
                       cycles=cycles, commands=commands, file_denied=expected_denials, response_started=starts,
                       response_blocked=blocked_count, reloads=reloads, rejections=rejections,
                       identities=identities, trigger_counts=dict(trigger_counts), denial_operations=dict(operations),
                       audit_counts=dict(counts), audit_records=sum(counts.values()), service_fd_baseline=baseline,
                       source_binary_hashes=len(before_hashes), final_status=final_status)
    summary['controller_fds_start'] = fd_start; summary['controller_fds_end'] = len(os.listdir('/proc/self/fd'))
    assert summary['controller_fds_start'] == summary['controller_fds_end']
    (artifact / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    manifest = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(artifact.iterdir()) if p.is_file()}
    (artifact / 'artifact_sha256.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(summary), flush=True)

if __name__ == '__main__': main()
