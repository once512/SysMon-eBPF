#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Persisted boot-bound expiry: reload, restart before/after expiry and stale boots."""
import argparse
from contextlib import ExitStack
import errno
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

from management_harness import call
from monitor_harness import MonitorRun
from writer_harness import WriterProcess
from writer_lease import wait_expired


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, default=Path('build'))
    args = parser.parse_args()
    if os.geteuid() != 0 or sys.flags.optimize:
        parser.error('run as root without Python optimization')
    build = args.build_dir.resolve()
    baseline = len(os.listdir('/proc/self/fd'))
    with tempfile.TemporaryDirectory(prefix='secmon-vault-restart-') as tmp, ExitStack() as stack:
        root = Path(tmp)
        program, target, policy, control = [root / name for name in ('client', 'secret', 'policy', 'control')]
        shutil.copyfile(build / 'secmon-writer-scenario', program)
        program.chmod(0o755)
        target.write_bytes(b'secret' + b'\0' * 4096)
        actor = stack.enter_context(WriterProcess(program, target))
        declaration = subprocess.check_output([str(build / 'secmon-vault-session'), '--id', '101',
                         '--program', str(program), '--uid', '0', '--target', str(target),
                         '--mode', 'read-write', '--duration-ms', '10000'], text=True, timeout=5)
        fields = declaration.split()
        issued, duration = int(fields[-1]), int(fields[-3])
        deadline = issued + duration * 1_000_000
        def publish(revision, line):
            stage = root / 'stage'
            stage.write_text(f'revision {revision}\nvault "{target}"\n' + line)
            stage.chmod(0o600)
            stage.replace(policy)
        def run_instance(check):
            with MonitorRun(build / 'secmon', ['--policy', str(policy), '--control', str(control)], seconds=30) as monitor:
                try:
                    check(monitor)
                finally:
                    call(build / 'secmon', 'stop', control)
                    monitor.process.wait(timeout=5)
        publish(1, declaration)
        def first(monitor):
            status = call(build / 'secmon', 'status', control)
            assert status['vault_next_deadline_boot_ns'] == deadline and status['vault_live_sessions'] == 1, (status, deadline)
            assert actor.request('h') == actor.request('w') == actor.request('c') == 0
        run_instance(first)
        def second(monitor):
            status = call(build / 'secmon', 'status', control)
            assert status['vault_next_deadline_boot_ns'] == deadline and status['vault_live_sessions'] == 1, (status, deadline)
            assert actor.request('h') == 0
            # A root edit with a future issuance is rejected atomically.
            future = declaration.rsplit(' ', 1)[0] + ' ' + str(time.clock_gettime_ns(time.CLOCK_BOOTTIME) + 10**12) + '\n'
            publish(2, future)
            result = call(build / 'secmon', 'reload', control, 'prepare_failed')
            assert result['vault_next_deadline_boot_ns'] == deadline
            publish(2, declaration)
            assert call(build / 'secmon', 'reload', control)['vault_next_deadline_boot_ns'] == deadline
            wait_expired(deadline)
            assert actor.request('h') == actor.request('w') == errno.EACCES
            # Explicit boundary: an already established mapping remains usable.
            assert actor.request('g') == actor.request('d') == actor.request('z') == 0
        run_instance(second)
        def expired(monitor):
            status = call(build / 'secmon', 'status', control)
            assert status['vault_next_deadline_boot_ns'] == deadline and status['vault_live_sessions'] == 0
            assert actor.request('h') == actor.request('w') == errno.EACCES
        run_instance(expired)
        assert target.read_bytes()[0:1] == b'M'
        # Old-boot configuration keeps the target locked, even if its old
        # executable no longer exists. It cannot reactivate at low new uptime.
        old_boot = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
        stale = (f'vault-session 202 "{root / "missing-client"}" 0 "{target}" '
                 f'read-write 10000 {old_boot} 1\n')
        publish(3, stale)
        def stale_boot(monitor):
            status = call(build / 'secmon', 'status', control)
            assert (status['vault_sessions'], status['vault_stale_sessions'], status['vault_live_sessions'],
                    status['vault_session_history'], status['vault_next_deadline_boot_ns']) == (1, 1, 0, 0, 0)
            assert actor.request('h') == actor.request('w') == errno.EACCES
        run_instance(stale_boot)
        fresh = subprocess.check_output([str(build / 'secmon-vault-session'), '--id', '303',
                         '--program', str(program), '--uid', '0', '--target', str(target),
                         '--mode', 'read', '--duration-ms', '10000'], text=True, timeout=5)
        publish(4, stale + fresh)
        def mixed_boot(monitor):
            status = call(build / 'secmon', 'status', control)
            assert (status['vault_sessions'], status['vault_stale_sessions'], status['vault_live_sessions'],
                    status['vault_session_history']) == (2, 1, 1, 1)
            assert actor.request('h') == 0 and actor.request('w') == errno.EACCES
        run_instance(mixed_boot)
        result = subprocess.run([str(build / 'secmon'), '--fanotify-only', '--policy', str(policy)],
                                capture_output=True, text=True, timeout=5)
        assert result.returncode and 'Vault/canary policy requires the BPF module' in result.stderr
    assert len(os.listdir('/proc/self/fd')) == baseline
    print('PASS absolute expiry survives restart; stale boots stay locked; existing mapping limitation proven; cleanup')


if __name__ == '__main__':
    main()
