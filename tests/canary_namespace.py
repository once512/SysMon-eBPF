#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Distinct PID=1 processes; actor/service clock offsets cannot change kernel expiry."""
import argparse
from contextlib import ExitStack
import errno
import os
from pathlib import Path
import shlex
import tempfile
import time
from canary_response import ResponseProcess
from management_harness import call
from monitor_harness import MonitorRun
from response_map import ResponseMap, response_ids


def experiment(build, service_offset=0, actor_offset=0, pid_namespaces=False):
    with tempfile.TemporaryDirectory(prefix='secmon-canary-ns-') as tmp, ExitStack() as stack:
        root = Path(tmp)
        trap, victim, policy = [root / name for name in ('trap', 'victim', 'policy')]
        for path in (trap, victim):
            path.write_bytes(b'original' + b'\0' * 8192)
        policy.write_text(f'revision 1\ncanary "{trap}"\ncanary-response 1 1200\n')
        policy.chmod(0o600)
        management = root / 'management'
        management.mkdir(mode=0o700)
        control = management / 'control'
        prefix = ['unshare', '--fork', '--kill-child']
        if pid_namespaces:
            prefix += ['--pid']
        else:
            prefix += ['--time', '--boottime', str(actor_offset), '--monotonic', str(actor_offset)]
        prefix += ['--']
        actor = stack.enter_context(ResponseProcess(build / 'secmon-response-scenario', trap, victim, prefix=prefix))
        other = stack.enter_context(ResponseProcess(build / 'secmon-response-scenario', trap, victim, prefix=prefix))
        if pid_namespaces:
            assert actor.request('i') == other.request('i') == 1
        executable = build / 'secmon'
        if service_offset:
            executable = root / 'service-wrapper'
            executable.write_text('#!/bin/sh\nexec unshare --time --boottime ' + str(service_offset) +
                ' --monotonic ' + str(service_offset) + ' --fork --kill-child -- ' + shlex.quote(str(build / 'secmon')) + ' "$@"\n')
            executable.chmod(0o700)
        before = response_ids()
        monitor = stack.enter_context(MonitorRun(executable, ['--policy', str(policy), '--control', str(control)]))
        def cleanup():
            if monitor.process.poll() is None:
                call(build / 'secmon', 'stop', control)
                monitor.process.wait(timeout=5)
        stack.callback(cleanup)
        created = response_ids() - before
        assert len(created) == 1
        with ResponseMap(next(iter(created))) as mapping:
            initial = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
            assert actor.request('c') == actor.request('w') == errno.EACCES
            first = mapping.entries()
            assert len(first) == 1
            deadline = next(iter(first.values()))[1]
            now = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
            assert initial + 1_200_000_000 <= deadline <= now + 1_200_000_000
            assert other.request('w') == 0
            assert other.request('C') == errno.EACCES
            assert len(mapping.entries()) == 2
            until = deadline + 50_000_000
            time.sleep(max(0, (until - time.clock_gettime_ns(time.CLOCK_BOOTTIME)) / 1e9))
            assert actor.request('w') == actor.request('W') == 0
            assert call(build / 'secmon', 'status', control)['response_started'] == 2
        cleanup()
        hits = [event for event in monitor.events() if event.get('response_started')]
        assert len(hits) == 2 and len({event['process_inode'] for event in hits}) == 2
        assert all(event['process_inode'] and event['response_epoch'] == 1 for event in hits)
        assert 'response_failed=0' in monitor.diagnostics()
        print(f'PASS PID namespaces={pid_namespaces} service_offset={service_offset} actor_offset={actor_offset}, distinct TGIDs and outside-clock expiry')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, default=Path('build'))
    args = parser.parse_args()
    assert os.geteuid() == 0 and __debug__
    build = args.build_dir.resolve()
    experiment(build, pid_namespaces=True)
    experiment(build, 3600, -60)
    experiment(build, -60, 3600)


if __name__ == '__main__':
    main()
