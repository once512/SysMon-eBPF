#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One persistent daemon: repeated scoped sessions, kernel expiry, close, rollback and FD accounting."""
import argparse
from contextlib import ExitStack
import errno
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

from file_policy_map import policy_outer_ids, PolicyMapView
from management_harness import call
from monitor_harness import MonitorRun
from writer_harness import WriterProcess
from writer_lease import wait_expired


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, default=Path('build'))
    parser.add_argument('--duration', type=int, default=900)
    parser.add_argument('--artifact-dir', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or sys.flags.optimize or not 5 <= args.duration <= 1200:
        parser.error('requires root, assertions and duration 5..1200')
    build, artifact = args.build_dir.resolve(), args.artifact_dir.resolve()
    artifact.mkdir(parents=True, exist_ok=True)
    before_fds = len(os.listdir('/proc/self/fd'))
    started = time.monotonic()
    cycles = expiries = rejected = reloads = operations = 0
    binaries = {name: hashlib.sha256((build / name).read_bytes()).hexdigest()
                for name in ('secmon', 'secmon-vault-session', 'secmon-writer-scenario')}
    with tempfile.TemporaryDirectory(prefix='secmon-vault-soak-') as tmp, ExitStack() as stack:
        root = Path(tmp)
        root.chmod(0o755)
        private = root / 'management'
        private.mkdir(mode=0o700)
        program, other = root / 'client', root / 'outsider'
        for path in (program, other):
            shutil.copyfile(build / 'secmon-writer-scenario', path)
            path.chmod(0o755)
        target, second = root / 'secret', root / 'second'
        for path in (target, second):
            path.write_bytes(b'secret' + b'\0' * 4096)
            path.chmod(0o666)
        alias = root / 'alias'
        os.link(target, alias)
        actor = stack.enter_context(WriterProcess(program, target))
        alias_actor = stack.enter_context(WriterProcess(program, alias))
        reader = stack.enter_context(WriterProcess(program, target, uid=65534))
        second_actor = stack.enter_context(WriterProcess(program, second))
        outsider = stack.enter_context(WriterProcess(other, target))
        policy, control = root / 'policy', private / 'control'
        revision = 1
        def publish(revision, lines=(), missing=False):
            text = f'revision {revision}\nvault "{target}"\nvault "{second}"\n' + ''.join(lines)
            if missing:
                text += f'protect "{root / "missing"}"\n'
            stage = root / 'stage'
            stage.write_text(text)
            stage.chmod(0o600)
            stage.replace(policy)
        publish(revision)
        old = policy_outer_ids()
        monitor = stack.enter_context(MonitorRun(build / 'secmon', ['--policy', str(policy), '--control', str(control)],
                                               seconds=args.duration + 120))
        def cleanup():
            if monitor.process.poll() is None:
                call(build / 'secmon', 'stop', control)
                monitor.process.wait(timeout=10)
        stack.callback(cleanup)
        created = policy_outer_ids() - old
        assert len(created) == 1
        outer = next(iter(created))
        pid = monitor.process.pid
        def fds():
            return len(list(Path(f'/proc/{pid}/fd').iterdir()))
        baseline = fds()
        controller = len(os.listdir('/proc/self/fd'))
        def check_fds(expected):
            until = time.monotonic() + 2
            while True:
                observed = fds()
                if observed == expected:
                    return
                assert time.monotonic() < until, (observed, expected)
                time.sleep(0.01)
        def expect(client, commands, expected):
            nonlocal operations
            for command in commands:
                result = client.request(command)
                operations += 1
                assert result == expected, (cycles, command, client.process.pid, result, expected)
        def declare(identity, uid, path, mode, duration):
            return subprocess.check_output([str(build / 'secmon-vault-session'), '--id', str(identity),
                         '--program', str(program), '--uid', str(uid), '--target', str(path),
                         '--mode', mode, '--duration-ms', str(duration)], text=True, timeout=5)
        with (artifact / 'cycles.jsonl').open('w') as records:
            while time.monotonic() - started < args.duration:
                cycle_start = time.monotonic()
                base = cycles * 3 + 1
                lines = [declare(base, 0, target, 'read-write', 750),
                         declare(base + 1, 65534, target, 'read', 3000),
                         declare(base + 2, 0, second, 'read-write', 3000)]
                deadline = int(lines[0].split()[-1]) + 750_000_000
                revision += 1
                publish(revision, lines)
                status = call(build / 'secmon', 'reload', control)
                reloads += 1
                assert status['vault_live_sessions'] == 3 and status['vault_session_history'] == (cycles + 1) * 3
                assert status['vault_next_deadline_boot_ns'] == deadline
                check_fds(baseline + 3)
                expect(actor, 'rhw', 0)
                expect(alias_actor, 'rh', 0)
                expect(reader, 'rh', 0)
                expect(reader, 'wo', errno.EACCES)
                expect(second_actor, 'rhw', 0)
                expect(outsider, 'rhw', errno.EACCES)
                if cycles % 5 == 0:
                    revision += 1
                    publish(revision, list(reversed(lines)))
                    status = call(build / 'secmon', 'reload', control)
                    reloads += 1
                    assert status['vault_next_deadline_boot_ns'] == deadline
                    with PolicyMapView(outer) as view:
                        value = view.vault_entry(target)
                        assert sorted(g.deadline_boot_ns for g in value.vault_sessions if g.access)[0] == deadline
                if cycles % 7 == 0:
                    publish(revision + 1, lines, missing=True)
                    status = call(build / 'secmon', 'reload', control, 'prepare_failed')
                    rejected += 1
                    assert status['revision'] == revision and status['vault_next_deadline_boot_ns'] == deadline
                wait_expired(deadline)
                expect(actor, 'rhw', errno.EACCES)
                expect(alias_actor, 'rh', errno.EACCES)
                expect(reader, 'rh', 0)
                expect(reader, 'w', errno.EACCES)
                expect(second_actor, 'hw', 0)
                status = call(build / 'secmon', 'status', control)
                assert status['vault_live_sessions'] == 2 and status['vault_sessions'] == 3
                expiries += 1
                revision += 1
                publish(revision)
                status = call(build / 'secmon', 'reload', control)
                reloads += 1
                assert status['vault_live_sessions'] == status['vault_sessions'] == 0
                assert status['vault_session_history'] == (cycles + 1) * 3
                expect(actor, 'hw', errno.EACCES)
                expect(reader, 'hw', errno.EACCES)
                expect(second_actor, 'hw', errno.EACCES)
                check_fds(baseline)
                assert len(os.listdir('/proc/self/fd')) == controller + 1  # cycle log is open.
                cycles += 1
                row = dict(cycle=cycles, pid=pid, revision=revision, history=cycles * 3,
                           deadline_boot_ns=deadline, operations=operations, seconds=round(time.monotonic() - started, 3))
                records.write(json.dumps(row) + '\n')
                records.flush()
                if cycles % 30 == 0:
                    print(json.dumps(row), flush=True)
                # Keep one daemon and remain below the 4096-ID history bound.
                remaining = 1.1 - (time.monotonic() - cycle_start)
                if remaining > 0:
                    time.sleep(remaining)
        cleanup()
        monitor.stop()
        events = monitor.events()
        denials = [e for e in events if e['event'] == 'file_denied']
        expired = [e for e in denials if e['vault_session_expired']]
        assert len(expired) == cycles * 5
        assert all(e['pid'] in (actor.process.pid, alias_actor.process.pid) for e in expired)
        diagnostics = monitor.diagnostics()
        for name in ('ringbuf_dropped', 'baseline_update_failed', 'audit_dropped', 'audit_invalid', 'audit_errno'):
            values = [int(value) for value in re.findall(r'\b' + name + r'=(\d+)', diagnostics)]
            assert values and not any(values), (name, values)
        assert int(re.findall(r'\baudit_written=(\d+)', diagnostics)[-1]) == len(events)
        assert int(re.findall(r'\bpolicy_denied=(\d+)', diagnostics)[-1]) == len(denials)
        assert status['audit_dropped'] == status['audit_invalid'] == 0
        monitor.output.seek(0)
        (artifact / 'audit.jsonl').write_text(monitor.output.read())
        (artifact / 'diagnostics.log').write_text(diagnostics)
    assert len(os.listdir('/proc/self/fd')) == before_fds
    assert all(hashlib.sha256((build / name).read_bytes()).hexdigest() == digest for name, digest in binaries.items())
    summary = dict(passed=True, cycles=cycles, single_daemon_pid=pid, expiry_checks=expiries,
                   operations=operations, successful_reloads=reloads, rejected_candidates=rejected,
                   history=cycles * 3, daemon_uptime_ms=status['uptime_ms'], denial_records=len(denials), expired_denial_records=len(expired),
                   controller_initial_fds=before_fds, controller_final_fds=len(os.listdir('/proc/self/fd')),
                   seconds=round(time.monotonic() - started, 3), executable_sha256=binaries)
    (artifact / 'summary.json').write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary), flush=True)


if __name__ == '__main__':
    main()
