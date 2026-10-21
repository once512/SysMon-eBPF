#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Kernel response survives actual ring-buffer exhaustion with stopped consumer."""
import argparse
from contextlib import ExitStack
import errno
import os
from pathlib import Path
import re
import signal
import tempfile
from canary_response import ResponseProcess
from monitor_harness import MonitorRun
from response_map import ResponseMap, response_ids


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, default=Path('build'))
    args = parser.parse_args()
    assert os.geteuid() == 0 and __debug__
    build = args.build_dir.resolve()
    with tempfile.TemporaryDirectory(prefix='secmon-canary-pressure-') as tmp, ExitStack() as stack:
        root = Path(tmp)
        trap, victim, policy = [root / name for name in ('trap', 'victim', 'policy')]
        for path in (trap, victim):
            path.write_bytes(b'original' + b'\0' * 8192)
        actor = stack.enter_context(ResponseProcess(build / 'secmon-response-scenario', trap, victim))
        policy.write_text(f'revision 1\ncanary "{trap}"\ncanary-response 1 60000\n')
        policy.chmod(0o600)
        before = response_ids()
        monitor = stack.enter_context(MonitorRun(build / 'secmon', ['--policy', str(policy)]))
        paused = False
        def cleanup():
            nonlocal paused
            if paused:
                os.kill(monitor.process.pid, signal.SIGCONT)
                paused = False
        stack.callback(cleanup)
        created = response_ids() - before
        assert len(created) == 1
        with ResponseMap(next(iter(created))) as mapping:
            os.kill(monitor.process.pid, signal.SIGSTOP)
            paused = True
            assert actor.request('k') == errno.EACCES
            initial = mapping.entries()
            assert len(initial) == 1
            assert actor.request('s') == 0  # 10000 actual mutation denials.
            assert actor.request('w') == errno.EACCES
            assert actor.request('f') == errno.EACCES
            assert mapping.entries() == initial  # No renewal and no audit dependency.
            cleanup()
            monitor.stop()
        drops = [int(value) for value in re.findall(r'ringbuf_dropped=(\d+)', monitor.diagnostics())]
        assert drops and drops[-1] > 0, monitor.diagnostics()
        assert 'response_started=1' in monitor.diagnostics()
        assert 'response_failed=0' in monitor.diagnostics()
        assert any(event.get('response_started') for event in monitor.events())
        print(f'PASS stopped consumer, 10000 mutation denials, ringbuf_dropped={drops[-1]}, unchanged response deadline')


if __name__ == '__main__':
    main()
