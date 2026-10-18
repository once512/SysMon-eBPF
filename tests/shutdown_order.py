#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# 填满诊断 stderr 后授权停止：不消费诊断也须完成退出并释放权限组。
import argparse
import errno
import fcntl
import os
from pathlib import Path
import select
import subprocess
import tempfile
import time
from fanotify_harness import open_errno
from management_harness import call


def drain(fd):
    while True:
        try:
            if not os.read(fd, 65536):
                return
        except BlockingIOError:
            return


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', default='build')
    args = parser.parse_args()
    assert os.geteuid() == 0
    binary = Path(args.build_dir).resolve() / 'secmon'
    with tempfile.TemporaryDirectory(prefix='secmon-shutdown-order-') as temporary:
        root = Path(temporary)
        target, policy, control = [root / name for name in ('target', 'policy', 'control')]
        target.write_bytes(b'data')
        policy.write_text(f'revision 1\nfanotify-file "{target}"\nfanotify-decision deny\n')
        policy.chmod(0o600)
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        fcntl.fcntl(write_fd, fcntl.F_SETPIPE_SZ, 4096)
        flags = fcntl.fcntl(write_fd, fcntl.F_GETFL)
        fcntl.fcntl(write_fd, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)
        # 单独打开父进程填充引用，不改变服务共享描述上的阻塞状态。
        filler = os.open(f'/proc/self/fd/{write_fd}', os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        with tempfile.TemporaryFile(mode='w+') as output:
            process = subprocess.Popen([str(binary), '--policy', str(policy), '--control', str(control), '--run-for', '20'],
                                       stdout=output, stderr=write_fd)
            try:
                deadline = time.monotonic() + 10
                diagnostics = bytearray()
                while b'Service active;' not in diagnostics:
                    assert process.poll() is None and time.monotonic() < deadline, diagnostics
                    ready, _, _ = select.select([read_fd], [], [], 0.05)
                    if ready:
                        diagnostics.extend(os.read(read_fd, 65536))
                assert open_errno(target) == errno.EPERM
                drain(read_fd)
                while True:
                    try:
                        os.write(filler, b'X' * 4096)
                    except BlockingIOError:
                        break
                call(binary, 'stop', control)
                # 不消费 stderr；权限组必须已释放，诊断线程有限等待后退出。
                assert open_errno(target) == 0
                process.wait(timeout=3)
                assert process.returncode == 0
                assert not control.exists()
                print('PASS full stderr does not block authorized shutdown; fanotify group released without draining diagnostics')
            finally:
                drain(read_fd)
                if process.poll() is None:
                    # 失败清理仍排空诊断，保留对旧产物/异常路径的退出保障。
                    deadline = time.monotonic() + 5
                    while process.poll() is None and time.monotonic() < deadline:
                        drain(read_fd)
                        time.sleep(0.01)
                    assert process.poll() is not None, 'shutdown diagnostics did not drain'
                os.close(filler)
                os.close(write_fd)
                os.close(read_fd)


if __name__ == '__main__':
    main()
