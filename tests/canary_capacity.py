#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""No eviction at response capacity; group lifetime cleanup; audited admission failure."""
import argparse
from contextlib import ExitStack
import errno
import os
from pathlib import Path
import tempfile
import time
from canary_response import ResponseProcess
from management_harness import call
from monitor_harness import MonitorRun
from response_map import ResponseMap, response_ids


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, default=Path('build'))
    args = parser.parse_args()
    assert os.geteuid() == 0 and __debug__
    build = args.build_dir.resolve()
    with tempfile.TemporaryDirectory(prefix='secmon-canary-capacity-') as tmp, ExitStack() as stack:
        root = Path(tmp)
        trap, victim, policy = [root / name for name in ('trap', 'victim', 'policy')]
        for path in (trap, victim):
            path.write_bytes(b'original' + b'\0' * 8192)
        management = root / 'management'
        management.mkdir(mode=0o700)
        control = management / 'control'
        policy.write_text(f'revision 1\ncanary "{trap}"\ncanary-response 1 60000\n')
        policy.chmod(0o600)
        first = stack.enter_context(ResponseProcess(build / 'secmon-response-scenario', trap, victim))
        second = stack.enter_context(ResponseProcess(build / 'secmon-response-scenario', trap, victim))
        before = response_ids()
        monitor = stack.enter_context(MonitorRun(build / 'secmon', ['--policy', str(policy), '--control', str(control)], seconds=120))
        def cleanup():
            if monitor.process.poll() is None:
                call(build / 'secmon', 'stop', control)
                monitor.process.wait(timeout=5)
        stack.callback(cleanup)
        created = response_ids() - before
        assert len(created) == 1
        mapping = stack.enter_context(ResponseMap(next(iter(created))))
        mapping.wait_keys([])
        pidfd = os.pidfd_open(first.process.pid)
        try:
            inode = os.fstat(pidfd).st_ino
        finally:
            os.close(pidfd)
        assert first.request('c') == first.request('w') == errno.EACCES
        mapping.wait_keys([inode])
        original = mapping.entries()[inode]
        assert first.request('L') == 0
        assert first.request('w') == errno.EACCES
        mapping.wait_keys([inode])  # Exiting leader did not delete worker's restriction.
        fake = [(1 << 63) + i for i in range(4095)]
        inserted = []
        try:
            for key in fake:
                mapping.insert(key, 1, time.clock_gettime_ns(time.CLOCK_BOOTTIME) + 60_000_000_000)
                inserted.append(key)
            assert len(mapping.entries()) == 4096
            assert second.request('c') == errno.EACCES
            assert second.request('w') == 0  # Cannot claim admission if HASH is full.
            assert first.request('w') == errno.EACCES
            assert mapping.entries()[inode] == original  # No eviction or renewal.
            status = call(build / 'secmon', 'status', control)
            assert (status['response_started'], status['response_failed']) == (1, 1), status
        finally:
            for key in inserted:
                mapping.delete(key)
        assert second.request('c') == second.request('w') == errno.EACCES
        first.process.stdin.write('q\n'); first.process.stdin.flush()
        first.process.wait(timeout=5)
        assert first.process.returncode == 0
        remaining = set(mapping.entries())
        assert inode not in remaining and len(remaining) == 1, remaining
        second.process.stdin.write('q\n'); second.process.stdin.flush()
        second.process.wait(timeout=5)
        mapping.wait_keys([])
        # Repeated real process/thread lifecycles leave no retained entries.
        identities = set()
        for _ in range(200):
            with ResponseProcess(build / 'secmon-response-scenario', trap, victim, late=True) as actor:
                assert actor.request('k') == actor.request('w') == errno.EACCES
                current = mapping.entries()
                assert len(current) == 1
                identities.update(current)
            mapping.wait_keys([])
        assert len(identities) == 200
        cleanup()
        hits = [event for event in monitor.events() if event.get('canary_hit')]
        failed = [event for event in hits if event.get('response_failed')]
        assert len(failed) == 1 and failed[0]['pid'] == second.process.pid
        assert not failed[0]['response_started'] and failed[0]['response_deadline_boot_ns'] == 0
        assert 'response_failed=1' in monitor.diagnostics()
        assert 'audit_invalid=0' in monitor.diagnostics()
    print('PASS response HASH capacity4096, no eviction/renewal, failure evidence, leader/last-thread cleanup and 200 pidfs lifecycles')


if __name__ == '__main__':
    main()
