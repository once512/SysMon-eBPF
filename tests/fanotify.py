#!/usr/bin/env python3
# 真实单 inode 打开裁决测试，包含别名、已有 FD 和崩溃释放；仅允许打开不能证明其他操作全部受控。
"""Privileged, temporary-file tests for the single-inode permission experiment."""
import argparse
import concurrent.futures
import errno
import json
import os
from pathlib import Path
import signal
import select
import subprocess
import tempfile
import time
from fanotify_harness import start, open_errno, stop



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', default='build')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('requires root/CAP_SYS_ADMIN')
    binary = (Path(args.build_dir) / 'secmon-fanotify').resolve()
    with tempfile.TemporaryDirectory(prefix='secmon-fanotify-') as temporary:
        directory = Path(temporary)
        target = directory / 'target'
        alias = directory / 'alias'
        other = directory / 'other'
        target.write_bytes(b'original')
        os.link(target, alias)
        other.write_bytes(b'other')
        for decision in ('allow', 'deny'):
            with tempfile.TemporaryFile(mode='w+') as output, tempfile.TemporaryFile(mode='w+') as errors:
                # Existing descriptors demonstrate the open-only coverage boundary.
                with target.open('r+b') as existing:
                    process = start(binary, target, decision, output, errors)
                    try:
                        expected = 0 if decision == 'allow' else errno.EPERM
                        assert open_errno(target) == expected
                        assert open_errno(alias) == expected
                        assert open_errno(other) == 0
                        assert existing.read() == b'original'
                        existing.seek(0)
                        existing.write(b'original')
                        existing.flush()
                        print(f'PASS {decision}: target/hardlink, unrelated file and pre-opened FD')
                        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                            results = list(pool.map(open_errno, [target] * 24))
                        assert all(result == expected for result in results)
                        print(f'PASS {decision}: concurrent permission requests')
                    finally:
                        stop(process)
                assert process.returncode == 0
                output.seek(0)
                stats = json.load(output)
                assert stats['overflow'] == 0
                assert stats['allowed' if decision == 'allow' else 'denied'] == 26
                assert stats['denied' if decision == 'allow' else 'allowed'] == 0
                assert open_errno(target) == 0
                print(f'PASS {decision}: response counters and policy removal')
        # Rename follows the inode, and a replacement at the original path is unmarked.
        with tempfile.TemporaryFile(mode='w+') as output, tempfile.TemporaryFile(mode='w+') as errors:
            process = start(binary, target, 'deny', output, errors)
            try:
                moved = directory / 'moved'
                target.rename(moved)
                target.write_bytes(b'replacement')
                assert open_errno(moved) == errno.EPERM
                assert open_errno(target) == 0
                assert open_errno(alias) == errno.EPERM
                print('PASS inode mark follows rename and permits replacement inode')
            finally:
                stop(process)
        # Stop event handling, prove an open is pending, then kill the listener.
        with tempfile.TemporaryFile(mode='w+') as output, tempfile.TemporaryFile(mode='w+') as errors:
            process = start(binary, target, 'deny', output, errors)
            opener = None
            try:
                process.send_signal(signal.SIGSTOP)
                waited, status = os.waitpid(process.pid, os.WUNTRACED)
                assert waited == process.pid and os.WIFSTOPPED(status)
                opener = subprocess.Popen(['python3', '-c',
                    'import sys; print("ready", flush=True); f = open(sys.argv[1]); print(f.read())', str(target)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                readable, _, _ = select.select([opener.stdout], [], [], 5)
                assert readable and opener.stdout.readline().strip() == 'ready', 'opener did not start'
                time.sleep(0.3)
                assert opener.poll() is None, 'open did not wait for a permission response'
                process.kill()
                process.wait(timeout=5)
                content, error = opener.communicate(timeout=5)
                assert opener.returncode == 0, error
                assert content.strip() == 'replacement'
                assert open_errno(target) == 0
                print('PASS listener crash releases pending open and removes mark')
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
                if opener is not None and opener.poll() is None:
                    opener.kill()
                    opener.wait(timeout=5)
        with tempfile.TemporaryFile(mode='w+') as output, tempfile.TemporaryFile(mode='w+') as errors:
            process = start(binary, target, 'deny', output, errors, seconds=1)
            try:
                assert open_errno(target) == errno.EPERM
                process.wait(timeout=5)
                assert process.returncode == 0
                assert open_errno(target) == 0
                print('PASS internal deadline releases mark')
            finally:
                stop(process)
        link = directory / 'symlink'
        link.symlink_to(target)
        for invalid in (link, directory, directory / 'missing'):
            result = subprocess.run([str(binary), '--file', str(invalid), '--decision', 'deny',
                                     '--run-for', '1'], capture_output=True, text=True, timeout=5)
            assert result.returncode == 1
        print('PASS reject symlink, directory and missing target')


if __name__ == '__main__':
    main()
