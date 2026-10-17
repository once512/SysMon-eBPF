#!/usr/bin/env python3
# 真实权限事件连接降权扫描器，验证 FD 传递、避免递归通知、内容裁决及后端死亡/卡住时回退。
# SPDX-License-Identifier: MIT
"""Real content worker, transferred event FD, deadlines and process failure."""
import argparse
import errno
import os
from pathlib import Path
import re
import signal
import shutil
import tempfile
import time
from fanotify_harness import GateRun, open_errno, start, stop, begin_open, finish_open
from fanotify_events import operation, execute


def worker_pid(run):
    run.errors.seek(0)
    matched = re.search(r'analyzer_pid=(\d+)', run.errors.read())
    assert matched, 'missing worker identity'
    return int(matched.group(1))


def wait_status(pid, predicate):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        try:
            status = Path(f'/proc/{pid}/status').read_text()
        except FileNotFoundError:
            status = ''
        if predicate(status):
            return status
        time.sleep(0.01)
    raise RuntimeError('worker status did not reach expected state')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', default='build')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('requires root/fanotify permissions')
    build = Path(args.build_dir).resolve()
    config = ['--analyzer', str(build / 'secmon-analyzer'), '--deny-marker', 'SECMON_BLOCK',
              '--request-timeout-ms', '1000']
    with tempfile.TemporaryDirectory(prefix='secmon-analysis-') as temporary:
        target = Path(temporary) / 'target'
        target.write_bytes(b'clean content')
        existing = os.open(target, os.O_RDWR | os.O_CLOEXEC)
        run = GateRun(build / 'secmon-fanotify', target, None, config)
        pid = worker_pid(run)
        try:
            status = wait_status(pid, lambda text: 'Uid:\t65534\t65534\t65534\t65534' in text)
            assert 'NoNewPrivs:\t1' in status
            assert 'CapEff:\t0000000000000000' in status
            assert 'CapPrm:\t0000000000000000' in status
            assert 'CapInh:\t0000000000000000' in status
            assert 'CapAmb:\t0000000000000000' in status
            assert open_errno(target) == 0
            os.pwrite(existing, b'SECMON_BLOCK!', 0)
            assert open_errno(target) == errno.EPERM
        finally:
            stats = run.finish()
            os.close(existing)
        assert stats['analyzed'] == 2 and stats['allowed'] == stats['denied'] == 1
        assert stats['timed_out'] == stats['analyzer_error'] == stats['analyzer_failures'] == 0
        wait_status(pid, lambda text: not text)
        print('PASS independent dropped-UID worker, real contents changed on same inode, clean shutdown')
        target.write_bytes(b'clean content')
        for event in ('open', 'access'):
            run = GateRun(build / 'secmon-fanotify', target, None, [*config, '--event', event])
            try:
                assert operation(target, 'read') == 0
            finally:
                stats = run.finish()
            assert stats['analyzed'] == 1 and stats['analyzer_failures'] == 0
            assert stats['timed_out'] == stats['analyzer_error'] == 0
            print(f'PASS {event}: scanner reads transferred FD without recursive permission event')
        for blocked in (False, True):
            executable = Path(temporary) / ('blocked-exec' if blocked else 'clean-exec')
            shutil.copyfile('/usr/bin/true', executable)
            if blocked:
                with executable.open('ab') as stream:
                    stream.write(b'SECMON_BLOCK')
            executable.chmod(0o755)
            run = GateRun(build / 'secmon-fanotify', executable, None,
                          [*config, '--event', 'exec', '--scan-limit-bytes', '1048576'])
            try:
                assert execute([str(executable)]) == (errno.EPERM if blocked else 0)
            finally:
                stats = run.finish()
            assert stats['analyzed'] >= 1 and stats['analysis_denied'] == (1 if blocked else 0)
            assert stats['analyzer_error'] == stats['analyzer_failures'] == 0
            print(f'PASS executable content scan: {"marker denied" if blocked else "clean ELF allowed"}')
        for fallback in ('deny', 'allow'):
            run = GateRun(build / 'secmon-fanotify', target, None,
                          [*config, '--scan-limit-bytes', '4', '--analyzer-error-decision', fallback])
            try:
                assert open_errno(target) == (errno.EPERM if fallback == 'deny' else 0)
            finally:
                stats = run.finish()
            assert stats['analyzer_error'] == 1 and stats['analyzed'] == 0
            assert stats['scan_error_counts']['oversized'] == 1 and stats['backend_error_requests'] == 0
            assert stats['last_scan_error'] == 'oversized' and stats['last_scan_errno'] == 0
            assert stats['analyzer_failures'] == 0
            print(f'PASS oversized-file analysis error uses {fallback} fallback')
        for fallback in ('deny', 'allow'):
            run = GateRun(build / 'secmon-fanotify', target, None,
                          [*config, '--analyzer-error-decision', fallback])
            pid = worker_pid(run)
            try:
                os.kill(pid, signal.SIGKILL)
                assert open_errno(target) == (errno.EPERM if fallback == 'deny' else 0)
            finally:
                stats = run.finish()
            assert stats['analyzer_failures'] == stats['analyzer_error'] == 1
            assert stats['backend_error_requests'] == 1 and sum(stats['scan_error_counts'].values()) == 0
            print(f'PASS worker crash: {fallback} fallback while fanotify gate remains active')
        fast_timeout = ['--analyzer', str(build / 'secmon-analyzer'), '--deny-marker', 'SECMON_BLOCK',
                        '--request-timeout-ms', '100']
        run = GateRun(build / 'secmon-fanotify', target, None, fast_timeout)
        pid = worker_pid(run)
        try:
            os.kill(pid, signal.SIGSTOP)
            wait_status(pid, lambda text: 'State:\tT' in text)
            started = time.monotonic()
            assert open_errno(target) == errno.EPERM
            assert 0.08 <= time.monotonic() - started < 1
            assert open_errno(target) == errno.EPERM
        finally:
            stats = run.finish()
        assert stats['timed_out'] == stats['analyzer_failures'] == stats['analyzer_error'] == 1
        wait_status(pid, lambda text: not text)
        print('PASS stalled worker: deadline, pidfd termination, bounded offline fallback')
        # Prove the worker did not inherit the fanotify group: even a stopped
        # worker cannot keep permission requests blocked after the gate dies.
        with tempfile.TemporaryFile(mode='w+') as output, tempfile.TemporaryFile(mode='w+') as errors:
            gate = start(build / 'secmon-fanotify', target, None, output, errors, extra=config)
            errors.seek(0)
            pid = int(re.search(r'analyzer_pid=(\d+)', errors.read()).group(1))
            opener = None
            try:
                os.kill(pid, signal.SIGSTOP)
                wait_status(pid, lambda text: 'State:\tT' in text)
                opener = begin_open(target)
                time.sleep(0.1)
                assert opener.poll() is None
                gate.kill()
                gate.wait(timeout=5)
                assert finish_open(opener) == 0
                wait_status(pid, lambda text: not text or 'State:\tZ' in text)
                print('PASS gate crash releases permission request despite stopped worker')
            finally:
                stop(gate)
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                if opener is not None and opener.poll() is None:
                    opener.kill()
                    opener.wait(timeout=5)
        assert open_errno(target) == 0


if __name__ == '__main__':
    main()
