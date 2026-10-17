#!/usr/bin/env python3
# 直接驱动内部分析器验证 Ready、请求格式及附带 FD 数量，属于协议测试，不证明 fanotify 已挂载。
# SPDX-License-Identifier: MIT
"""Unprivileged worker wire-contract tests, including malformed incoming requests."""
import argparse
import array
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile

MAGIC = 0x53434D41
VERSION = 3
REQUEST = struct.Struct('<IHHQ')
RESPONSE = struct.Struct('<IHHQIIIi')


def run_worker(binary, payload, files, expect_success):
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    process = None
    try:
        process = subprocess.Popen([str(binary), '--fd', str(child.fileno()), '--deny-marker', 'BLOCK',
                                    '--scan-limit-bytes', '65536', '--parent-pid', str(os.getpid())],
                                   pass_fds=(child.fileno(),), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        child.close()
        ancillary = []
        if files:
            ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', files))]
        parent.settimeout(3)
        initialized = RESPONSE.unpack(parent.recv(128))
        assert initialized == (MAGIC, VERSION, 32, 0, 4, 0, 0, 0)
        parent.sendmsg([payload], ancillary)
        try:
            reply = parent.recv(128)
        except ConnectionResetError:
            reply = b''
        if expect_success:
            assert len(reply) == RESPONSE.size
            magic, version, size, request_id, result, scanned, error, system_errno = RESPONSE.unpack(reply)
            assert (magic, version, size, request_id, result, scanned, error, system_errno) == (MAGIC, VERSION, 32, 42, 1, 5, 0, 0)
            parent.close()
            process.wait(timeout=3)
            assert process.returncode == 0
        else:
            assert not reply, reply
            process.wait(timeout=3)
            assert process.returncode == 1, process.stderr.read().decode(errors='replace')
    finally:
        parent.close()
        child.close()
        if process is not None:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=3)
            process.stdout.close()
            process.stderr.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', default='build')
    args = parser.parse_args()
    binary = (Path(args.build_dir) / 'secmon-analyzer').resolve()
    with tempfile.NamedTemporaryFile() as source:
        source.write(b'clean')
        source.flush()
        fd = os.open(source.name, os.O_RDONLY | os.O_CLOEXEC)
        try:
            good = REQUEST.pack(MAGIC, VERSION, 16, 42)
            run_worker(binary, good, [fd], True)
            for payload, fds in (
                (REQUEST.pack(0, VERSION, 16, 42), [fd]),
                (REQUEST.pack(MAGIC, VERSION + 1, 16, 42), [fd]),
                (REQUEST.pack(MAGIC, VERSION, 15, 42), [fd]),
                (REQUEST.pack(MAGIC, VERSION, 16, 0), [fd]),
                (good, []), (good, [fd, fd]), (good, [fd] * 9),
                (good + b'extra payload', [fd]), (good[:3], [fd]),
            ):
                run_worker(binary, payload, fds, False)
        finally:
            os.close(fd)
    print('PASS worker wire protocol, malformed payloads and ancillary FD budget')


if __name__ == '__main__':
    main()
