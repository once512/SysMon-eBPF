#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Scoped vault sessions: read/write, kernel expiry, close, immutable IDs and rollback."""
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

from file_policy_map import PolicyMapView, policy_outer_ids
from management_harness import call
from monitor_harness import MonitorRun
from writer_harness import WriterProcess
from writer_lease import wait_expired


def experiment(build, paused=False):
    with tempfile.TemporaryDirectory(prefix='secmon-vault-') as temporary, ExitStack() as stack:
        root = Path(temporary)
        root.chmod(0o755)
        program, other = root / 'client', root / 'outsider'
        for path in (program, other):
            shutil.copyfile(build / 'secmon-writer-scenario', path)
            path.chmod(0o755)
        target, second = root / 'secret', root / 'second'
        for path in (target, second):
            path.write_bytes(b'secret' + b'\0' * 4096)
            path.chmod(0o666)  # DAC permits wrong UID; BPF must enforce the denial.
        alias = root / 'alias'
        os.link(target, alias)
        actor = stack.enter_context(WriterProcess(program, target))
        alias_actor = stack.enter_context(WriterProcess(program, alias))
        outsider = stack.enter_context(WriterProcess(other, target))
        wrong_uid = stack.enter_context(WriterProcess(program, target, uid=65534))
        second_actor = stack.enter_context(WriterProcess(program, second))
        management = root / 'management'
        management.mkdir(mode=0o700)
        policy, control = root / 'policy', management / 'control'
        issuance = {}
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        def publish(revision, sessions=(), missing=False, extra=''):
            text = f'revision {revision}\nvault "{target}"\nvault "{second}"\n' + extra
            if missing:
                text += f'protect "{root / "missing"}"\n'
            for session in sessions:
                ident, path, mode, duration, uid = session
                issued = issuance.setdefault(session, time.clock_gettime_ns(time.CLOCK_BOOTTIME))
                text += f'vault-session {ident} "{program}" {uid} "{path}" {mode} {duration} {boot} {issued}\n'
            staging = root / 'stage'
            staging.write_text(text)
            staging.chmod(0o600)
            staging.replace(policy)
        publish(1)
        old_maps = policy_outer_ids()
        monitor = stack.enter_context(MonitorRun(build / 'secmon', ['--policy', str(policy)] +
                                                  ([] if paused else ['--control', str(control)]), seconds=60))
        stopped = False
        def cleanup():
            nonlocal stopped
            if stopped:
                os.kill(monitor.process.pid, signal.SIGCONT)
                stopped = False
            if not paused and monitor.process.poll() is None:
                call(build / 'secmon', 'stop', control)
                monitor.process.wait(timeout=5)
        stack.callback(cleanup)
        maps = policy_outer_ids() - old_maps
        assert len(maps) == 1
        outer = next(iter(maps))
        def deadlines():
            with PolicyMapView(outer) as view:
                return tuple(grant.deadline_boot_ns for grant in view.vault_entry(target).vault_sessions)
        def expect(client, commands, expected):
            for command in commands:
                actual = client.request(command)
                assert actual == expected, (client.process.pid, command, actual, expected)
        expect(actor, 'rhowamvpbtunl', errno.EACCES)
        expect(outsider, 'rh', errno.EACCES)
        # The controller's root UID does not give it implicit read access.
        try:
            target.read_bytes()
            raise AssertionError('controller unexpectedly read a locked vault')
        except PermissionError:
            pass
        if paused:
            # Start a fresh service with explicit configured sessions to test
            # deadline enforcement without a management loop.
            monitor.stop()
            publish(2, [(1, target, 'read-write', 1200, 0)])
            monitor = stack.enter_context(MonitorRun(build / 'secmon', ['--policy', str(policy)], seconds=60))
            expect(actor, 'rhowamvpbt', 0)
            os.kill(monitor.process.pid, signal.SIGSTOP)
            stopped = True
            time.sleep(1.35)
            expect(actor, 'rhowamvpbt', errno.EACCES)
            cleanup()
            monitor.stop()
        else:
            read = (1, target, 'read', 4000, 0)
            write = (2, second, 'read-write', 10000, 0)
            publish(2, [read, write])
            call(build / 'secmon', 'reload', control)
            opened = call(build / 'secmon', 'status', control)
            assert (opened['vault_paths'], opened['vault_sessions'], opened['vault_live_sessions'],
                    opened['vault_session_history'], opened['vault_clock_valid']) == (2, 2, 2, 2, True)
            first = deadlines()[0]
            assert opened['vault_next_deadline_boot_ns'] == first
            assert 0 < first - time.clock_gettime_ns(time.CLOCK_BOOTTIME) <= 4_000_000_000
            expect(actor, 'rhabv', 0)
            expect(alias_actor, 'rh', 0)
            expect(actor, 'womptunl', errno.EACCES)
            expect(second_actor, 'rhowamvpbt', 0)
            expect(second_actor, 'unl', errno.EACCES)
            expect(outsider, 'rh', errno.EACCES)
            expect(wrong_uid, 'rh', errno.EACCES)
            # Reorder slots and increase unrelated revision, preserving deadline.
            publish(3, [write, read])
            call(build / 'secmon', 'reload', control)
            assert deadlines()[1] == first
            # Same ID cannot silently change permission, TTL, UID or inode.
            for changed in ((1, target, 'read-write', 4000, 0), (1, target, 'read', 5000, 0),
                            (1, target, 'read', 4000, 65534), (1, second, 'read', 4000, 0)):
                publish(4, [write, changed])
                call(build / 'secmon', 'reload', control, 'prepare_failed')
                assert deadlines()[1] == first
            publish(4, [write, read], missing=True)
            call(build / 'secmon', 'reload', control, 'prepare_failed')
            assert deadlines()[1] == first
            wait_expired(first)
            expect(actor, 'rhowamvpbt', errno.EACCES)
            expect(second_actor, 'rhw', 0)  # Independent longer session survives.
            expired = call(build / 'secmon', 'status', control)
            assert expired['vault_sessions'] == 2 and expired['vault_live_sessions'] == 1
            # Expired ID cannot be renewed by merely changing the revision.
            publish(4, [read, write])
            call(build / 'secmon', 'reload', control)
            assert deadlines()[0] == first
            expect(actor, 'rh', errno.EACCES)
            # A distinct explicit session opens access; removing it closes old FDs.
            fresh = (3, target, 'read-write', 10000, 0)
            publish(5, [fresh, write])
            call(build / 'secmon', 'reload', control)
            expect(actor, 'rhowamvpbt', 0)
            publish(6, [write])
            call(build / 'secmon', 'reload', control)
            expect(actor, 'rhowamvpbt', errno.EACCES)
            closed = call(build / 'secmon', 'status', control)
            assert (closed['vault_sessions'], closed['vault_live_sessions'], closed['vault_session_history']) == (1, 1, 3)
            publish(7, [fresh, write])
            call(build / 'secmon', 'reload', control, 'prepare_failed')
            expect(actor, 'rh', errno.EACCES)
            # An allow-writer alias cannot bypass vault session locking.
            publish(7, [write], extra=f'protect "{alias}"\nallow-writer "{program}" 0 "{alias}" all\n')
            call(build / 'secmon', 'reload', control, 'prepare_failed')
            expect(actor, 'rh', errno.EACCES)
            # Overlapping sessions on one executable/target must keep UID,
            # access and deadline in the same slot, never merge their powers.
            overlap = [(4, target, 'read', 4000, 0), (5, target, 'read-write', 1500, 0),
                       (6, target, 'read-write', 4000, 65534)]
            publish(7, overlap)
            call(build / 'secmon', 'reload', control)
            expect(actor, 'rhw', 0)
            expect(wrong_uid, 'rhw', 0)
            wait_expired(deadlines()[1])
            expect(actor, 'rh', 0)
            expect(actor, 'wo', errno.EACCES)
            expect(wrong_uid, 'rhw', 0)
            publish(8)
            call(build / 'secmon', 'reload', control)
            expect(actor, 'rhw', errno.EACCES)
            expect(wrong_uid, 'rhw', errno.EACCES)
            cleanup()
            monitor.stop()
        denials = [e for e in monitor.events() if e['event'] == 'file_denied']
        assert any(e['vault_session_expired'] for e in denials)
        assert any(e['operation'] in (11, 12, 13) for e in denials)
        assert not any(e['vault_session_expired'] for e in denials if e['pid'] == outsider.process.pid)
        assert 'ringbuf_dropped=0' in monitor.diagnostics()
    print(f'PASS vault scoped sessions, read/write/old-FD/mmap/expiry/reload/close/rollback paused={paused}')


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
