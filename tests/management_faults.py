#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# 伪 root 对端注入错误响应，验证管理客户端先检查帧、枚举、身份和 FD，避免把异常内容当成活动状态。
import argparse
import array
import ctypes
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile


class Reply(ctypes.Structure):
    _fields_ = [('magic', ctypes.c_uint32), ('abi', ctypes.c_uint16), ('size', ctypes.c_uint16),
                *[(name, ctypes.c_uint32) for name in ('command', 'code', 'backend', 'flags')],
                *[(name, ctypes.c_uint64) for name in ('revision', 'last_attempt_revision', 'instance_ns', 'uptime_ms',
                  'reloads', 'rejections', 'allowed', 'denied', 'analysis_errors', 'analysis_failures', 'overflow')],
                *[(name, ctypes.c_uint32) for name in ('pid', 'protected_paths', 'pending', 'peak_pending', 'event', 'mode',
                  'delay_ms', 'timeout_ms', 'max_pending', 'fallbacks')], ('worker_pid', ctypes.c_int32),
                ('scan_limit', ctypes.c_uint32), ('last_code', ctypes.c_uint32), ('reserved', ctypes.c_uint32), ('source_digest', ctypes.c_uint8 * 32), ('last_scan_error', ctypes.c_uint32),
                ('last_scan_errno', ctypes.c_int32), ('backend_error_requests', ctypes.c_uint64),
                ('scan_errors', ctypes.c_uint64 * 9), ('writer_paths', ctypes.c_uint32), ('reserved_tail', ctypes.c_uint32)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', default='build')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('requires root to emulate a root control peer')
    assert ctypes.sizeof(Reply) == 296
    binary = Path(args.build_dir).resolve() / 'secmon'
    with tempfile.TemporaryDirectory(prefix='secmon-management-fault-') as temporary:
        path = Path(temporary) / 'fake.sock'
        cases = ['valid', 'magic', 'abi', 'size', 'command', 'code', 'last_code', 'backend', 'flags',
                 'pid', 'instance_ns', 'event', 'mode', 'fallbacks', 'reserved', 'scan-reason', 'scan-errno',
                 'writer-count', 'reserved-tail', 'text-response', 'error-accounting', 'short', 'long', 'fds', 'extra-fds']
        held = os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC)
        try:
            for command, command_id in (('status', 3), ('reload', 2), ('stop', 1)):
                for case in cases:
                    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as server:
                        server.bind(str(path))
                        server.listen(1)
                        server.settimeout(5)
                        process = subprocess.Popen([str(binary), '--' + command, str(path)],
                                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                        try:
                            with server.accept()[0] as connection:
                                connection.settimeout(5)
                                assert connection.recv(32) == command.encode()
                                reply = Reply()
                                reply.magic, reply.abi, reply.size = 0x53434D43, 3, 296
                                reply.command, reply.backend, reply.pid, reply.instance_ns = command_id, 1, os.getpid(), 123
                                reply.worker_pid = -1
                                if case in ('magic', 'abi', 'size', 'command', 'code', 'last_code', 'backend', 'flags',
                                            'instance_ns', 'event', 'mode', 'fallbacks', 'reserved'):
                                    setattr(reply, case, {'abi': 4, 'size': 295, 'command': (1 if command_id != 1 else 3), 'flags': 16,
                                                         'instance_ns': 0, 'event': 4, 'mode': 4,
                                                         'fallbacks': 8, 'reserved': 1}.get(case, 99))
                                if case == 'writer-count': reply.writer_paths = 65
                                if case == 'reserved-tail': reply.reserved_tail = 1
                                if case == 'scan-reason': reply.last_scan_error = 99
                                if case == 'scan-errno': reply.last_scan_errno = -1
                                if case == 'error-accounting': reply.backend_error_requests = 1
                                if case == 'pid':
                                    reply.pid += 1
                                payload = bytes(reply)
                                if case == 'text-response':
                                    payload = b'ok'
                                if case == 'short':
                                    payload = payload[:-1]
                                if case == 'long':
                                    payload += b'x'
                                fds = [held] * (9 if case == 'extra-fds' else 1) if case in ('fds', 'extra-fds') else []
                                ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', fds))] if fds else []
                                connection.sendmsg([payload], ancillary)
                            output, error = process.communicate(timeout=5)
                            assert (process.returncode == 0) == (case == 'valid'), (case, output, error)
                            if case == 'valid':
                                assert json.loads(output)['pid'] == os.getpid()
                            else:
                                assert not output.strip(), (case, output)
                        finally:
                            if process.poll() is None:
                                process.kill()
                                process.wait(timeout=5)
                            path.unlink()
        finally:
            os.close(held)
    print('PASS management client rejects corrupt frames, identity mismatch and unexpected received FDs')


if __name__ == '__main__':
    main()
