#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Kernel-enforced, policy-wide bounded maintenance-write grants."""
import argparse
from contextlib import ExitStack
import errno
import os
from pathlib import Path
import shutil
import signal
import sys
import tempfile
import time

from file_policy_map import PolicyMapView, policy_outer_ids, key_for
from management_harness import call
from monitor_harness import MonitorRun
from writer_harness import WriterProcess


def boot_ns():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def wait_expired(deadline):
    # Use the same clock as the kernel policy, never wall time or process CPU time.
    while boot_ns() <= deadline + 20_000_000:
        time.sleep(min(0.02, max(0.001, (deadline + 20_000_000 - boot_ns()) / 1e9)))


def experiment(build, paused=False):
    with tempfile.TemporaryDirectory(prefix='secmon-lease-') as temporary, ExitStack() as stack:
        root = Path(temporary)
        program, other = root / 'maintenance', root / 'other'
        for path in (program, other):
            shutil.copyfile(build / 'secmon-writer-scenario', path)
            path.chmod(0o755)
        target, unselected = root / 'data', root / 'unselected'
        for path in (target, unselected):
            path.write_bytes(b'original' + b'\0' * 4096)
        actor = stack.enter_context(WriterProcess(program, target))
        outsider = stack.enter_context(WriterProcess(other, target))
        wrong_target = stack.enter_context(WriterProcess(program, unselected))
        policy, control = root / 'policy', root / 'control'
        def publish(revision, duration=1200, missing=False, writers=True):
            text = (f'revision {revision}\nprotect "{target}"\nprotect "{unselected}"\n' +
                    (f'protect "{root / "missing"}"\n' if missing else ''))
            if writers:
                text += f'allow-writer "{program}" 0 "{target}" open-write,write,mmap-write\n'
                if duration:
                    text += f'writer-lease-ms {duration}\n'
            stage = root / 'staging'
            stage.write_text(text)
            stage.chmod(0o600)
            stage.replace(policy)
        publish(1)
        old_ids = policy_outer_ids()
        flags = ['--policy', str(policy)] + ([] if paused else ['--control', str(control)])
        monitor = stack.enter_context(MonitorRun(build / 'secmon', flags, seconds=60))
        def emergency_cleanup():
            if monitor.process.poll() is None:
                if paused:
                    os.kill(monitor.process.pid, signal.SIGCONT)
                else:
                    call(build / 'secmon', 'stop', control)
                    monitor.process.wait(timeout=5)
        stack.callback(emergency_cleanup)
        created = policy_outer_ids() - old_ids
        assert len(created) == 1
        outer = next(iter(created))
        def deadline():
            with PolicyMapView(outer) as view:
                entries = view.entries(full=True, with_deadlines=True)
                expiry = entries[key_for(program)][-1]
                assert all(value[-1] == (expiry if key == key_for(program) else 0)
                           for key, value in entries.items())
                return expiry
        initial = deadline()
        assert 0 < initial - boot_ns() <= 1_200_000_000
        assert actor.request('w') == actor.request('o') == 0
        assert actor.request('m') == actor.request('p') == 0
        assert outsider.request('w') == wrong_target.request('w') == errno.EACCES
        stopped = False
        try:
            if paused:
                os.kill(monitor.process.pid, signal.SIGSTOP)
                stopped = True
            else:
                publish(2, missing=True)
                call(build / 'secmon', 'reload', control, 'prepare_failed')
                assert deadline() == initial
                publish(1)
                call(build / 'secmon', 'reload', control, 'not_newer')
                assert deadline() == initial
            protected_bytes = target.read_bytes()
            wait_expired(initial)
            for command in ('w', 'o', 'm', 'p'):
                assert actor.request(command) == errno.EACCES, (paused, command)
            assert target.read_bytes() == protected_bytes
            assert unselected.read_bytes() == b'original' + b'\0' * 4096
            assert actor.request('r') == actor.request('v') == 0
            assert outsider.request('w') == errno.EACCES
            assert wrong_target.request('w') == errno.EACCES
            if paused:
                os.kill(monitor.process.pid, signal.SIGCONT)
                stopped = False
            else:
                # A new committed revision explicitly starts a fresh lease.
                publish(2, duration=600)
                call(build / 'secmon', 'reload', control)
                renewed = deadline()
                assert renewed > initial and actor.request('w') == 0
                wait_expired(renewed)
                assert actor.request('w') == errno.EACCES
                # Explicitly omitting the lease restores the existing unbounded-grant contract.
                publish(3, duration=0)
                call(build / 'secmon', 'reload', control)
                assert deadline() == 0 and actor.request('w') == 0
                # Remove all grants: a read remains allowed, including via old FD.
                publish(4, writers=False)
                call(build / 'secmon', 'reload', control)
                assert actor.request('w') == errno.EACCES and actor.request('r') == 0
                call(build / 'secmon', 'stop', control)
                monitor.process.wait(timeout=5)
            monitor.stop()
            events = monitor.events()
            denials = [r for r in events if r['event'] == 'file_denied']
            expired = [r for r in denials if r['writer_lease_expired']]
            assert len(expired) >= 4
            assert all(r['pid'] == actor.process.pid and r['ino'] == target.stat().st_ino
                       for r in expired)
            assert any(not r['writer_lease_expired'] for r in denials if r['pid'] == outsider.process.pid)
            assert all(not r['writer_lease_expired'] for r in denials if r['pid'] == wrong_target.process.pid)
            diagnostics = monitor.diagnostics()
            assert 'ringbuf_dropped=0' in diagnostics and 'baseline_update_failed=0' in diagnostics
        finally:
            if stopped:
                os.kill(monitor.process.pid, signal.SIGCONT)
            if not paused and monitor.process.poll() is None:
                call(build / 'secmon', 'stop', control)
                monitor.process.wait(timeout=5)
    print(f'PASS kernel writer lease: paused_service={paused}, expiry/identity/scope/old-FD/mmap/audit/cleanup')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, default=Path('build'))
    args = parser.parse_args()
    if os.geteuid() != 0 or sys.flags.optimize or os.environ.get('PYTHONOPTIMIZE'):
        parser.error('run as root without Python optimization')
    baseline = len(os.listdir('/proc/self/fd'))
    for paused in (False, True):
        experiment(args.build_dir.resolve(), paused)
        assert len(os.listdir('/proc/self/fd')) == baseline


if __name__ == '__main__':
    main()
