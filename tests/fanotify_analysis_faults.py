#!/usr/bin/env python3
# 使用故障分析器验证协议错误隔离、请求取消、启动失败和 FD 所有权，失败场景必须有界结束。
# SPDX-License-Identifier: MIT
"""Validate malformed/stale replies cannot authorize a permission request."""
import argparse
import errno
import os
import subprocess
from pathlib import Path
import tempfile
import time
from fanotify_harness import GateRun, open_errno, begin_open, finish_open


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', default='build')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('requires root/fanotify permissions')
    build = Path(args.build_dir).resolve()
    with tempfile.TemporaryDirectory(prefix='secmon-analysis-faults-') as temporary:
        target = Path(temporary) / 'target'
        target.write_bytes(b'clean')
        for mode in ('wrong-id', 'wrong-version', 'wrong-size', 'wrong-bytes', 'wrong-verdict',
                     'short', 'extra-fds', 'exit', 'late', 'duplicate'):
            run = GateRun(build / 'secmon-fanotify', target, None,
                          ['--analyzer', str(build / 'secmon-analysis-fault-worker'), '--deny-marker', mode,
                           '--request-timeout-ms', '100' if mode == 'late' else '1000'])
            baseline = len(list(Path(f'/proc/{run.process.pid}/fd').iterdir()))
            try:
                assert open_errno(target) == (0 if mode == 'duplicate' else errno.EPERM)
                assert open_errno(target) == errno.EPERM
                time.sleep(0.02)
                # On quarantine, IPC closes; no received ancillary FDs may remain.
                assert len(list(Path(f'/proc/{run.process.pid}/fd').iterdir())) <= baseline - 1
                assert run.process.poll() is None
            finally:
                stats = run.finish()
            assert stats['analyzer_failures'] == 1 and stats['overflow'] == 0
            assert stats['analyzed'] == (1 if mode == 'duplicate' else 0)
            assert stats['timed_out'] == (1 if mode == 'late' else 0)
            assert stats['analyzer_error'] == (1 if mode in ('late', 'duplicate') else 2)
            assert stats['denied'] == (1 if mode == 'duplicate' else 2)
            print(f'PASS {mode}: bounded quarantine, no unauthorized allow or leaked reply FDs')
        run = GateRun(build / 'secmon-fanotify', target, None,
                      ['--analyzer', str(build / 'secmon-analysis-fault-worker'), '--deny-marker', 'delay',
                       '--request-timeout-ms', '2000'])
        opener = None
        try:
            opener = begin_open(target)
            time.sleep(0.08)
            assert opener.poll() is None
            opener.kill()
            opener.communicate(timeout=3)
            time.sleep(0.3)
            assert run.process.poll() is None, 'cancelled permission request killed the gate'
            assert open_errno(target) == 0
        finally:
            stats = run.finish()
            if opener is not None and opener.poll() is None:
                opener.kill()
                opener.wait(timeout=3)
        assert stats['analyzer_failures'] == stats['analyzer_error'] == stats['timed_out'] == 0
        print('PASS requester cancellation: late valid reply does not disrupt unrelated permission requests')
        for mode in ('no-ready', 'bad-ready', 'ready-fds'):
            started = time.monotonic()
            result = subprocess.run([str(build / 'secmon-fanotify'), '--file', str(target), '--run-for', '5',
                                     '--analyzer', str(build / 'secmon-analysis-fault-worker'),
                                     '--deny-marker', mode], capture_output=True, text=True, timeout=3)
            assert result.returncode == 1 and 'Fanotify active;' not in result.stderr
            assert time.monotonic() - started < 2.5
            assert open_errno(target) == 0
            print(f'PASS {mode}: reject startup before marking target')
        assert open_errno(target) == 0


if __name__ == '__main__':
    main()
