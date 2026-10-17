#!/usr/bin/env python3
# 同时启用 BPF 只读与 fanotify 打开门，证明允许不能覆盖另一层拒绝，且两个后端可以独立关闭。
# SPDX-License-Identifier: MIT
"""Demonstrate independent BPF read-only and fanotify open-permission layers."""
import argparse
import errno
import os
from pathlib import Path
import subprocess
import tempfile
from fanotify_harness import GateRun
from monitor_harness import MonitorRun


def attempt(path, operation):
    code = '''import os, sys
try:
    if sys.argv[2] == 'read':
        fd = os.open(sys.argv[1], os.O_RDONLY)
    else:
        fd = os.open(sys.argv[1], os.O_WRONLY)
    os.close(fd)
except OSError as error:
    print(error.errno)
else:
    print(0)
'''
    result = subprocess.run(['python3', '-c', code, str(path), operation],
                            capture_output=True, text=True, check=True, timeout=5)
    return int(result.stdout)


def expect_denied(operation, expected):
    try:
        operation()
    except OSError as error:
        assert error.errno == expected, error
    else:
        raise AssertionError('operation unexpectedly allowed')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', default='build')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('requires root/BPF and fanotify permissions')
    build = Path(args.build_dir).resolve()
    with tempfile.TemporaryDirectory(prefix='secmon-layers-') as temporary:
        target = Path(temporary) / 'target'
        target.write_bytes(b'original')
        identity = target.stat()
        existing = os.open(target, os.O_RDWR | os.O_CLOEXEC)
        try:
            with MonitorRun(build / 'secmon', ['--protect-file', str(target)]) as audit:
                gate = GateRun(build / 'secmon-fanotify', target, 'allow', [])
                try:
                    assert attempt(target, 'read') == 0
                    assert attempt(target, 'write') == errno.EACCES
                    expect_denied(lambda: os.pwrite(existing, b'X', 0), errno.EACCES)
                    expect_denied(lambda: os.unlink(target), errno.EACCES)
                    print('PASS fanotify allow preserves BPF denials for write/open, existing FD and unlink')
                finally:
                    allow_stats = gate.finish()
                # BPF denied the write-open before fanotify was asked for a decision.
                assert allow_stats['allowed'] == 1 and allow_stats['denied'] == 0
                assert attempt(target, 'write') == errno.EACCES
                assert attempt(target, 'read') == 0
                print('PASS closing fanotify does not remove the BPF policy')
                gate = GateRun(build / 'secmon-fanotify', target, 'deny', [])
                try:
                    assert attempt(target, 'read') == errno.EPERM
                    assert attempt(target, 'write') == errno.EACCES
                    expect_denied(lambda: os.pwrite(existing, b'X', 0), errno.EACCES)
                    audit.stop()
                    events = audit.events()
                    denials = [event for event in events if event['event'] == 'file_denied']
                    assert len(denials) >= 5
                    assert all(event['ino'] == identity.st_ino and
                               event['dev_major'] == os.major(identity.st_dev) and
                               event['dev_minor'] == os.minor(identity.st_dev) for event in denials)
                    assert 'ringbuf_dropped=0' in audit.diagnostics()
                    assert 'baseline_update_failed=0' in audit.diagnostics()
                    # Only the open gate remains: it cannot revoke the pre-opened writable FD.
                    assert attempt(target, 'read') == errno.EPERM
                    assert attempt(target, 'write') == errno.EPERM
                    assert os.pwrite(existing, b'X', 0) == 1
                    print('PASS closing BPF leaves fanotify active but permits existing-FD writes')
                finally:
                    deny_stats = gate.finish()
                assert deny_stats['denied'] == 3 and deny_stats['allowed'] == 0
                assert allow_stats['overflow'] == deny_stats['overflow'] == 0
            assert attempt(target, 'read') == attempt(target, 'write') == 0
            assert target.read_bytes() == b'Xriginal'
            print('PASS independent layer cleanup, file identity and zero failure counters')
        finally:
            os.close(existing)


if __name__ == '__main__':
    main()
