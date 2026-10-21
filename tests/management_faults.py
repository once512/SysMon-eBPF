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
                ('scan_errors', ctypes.c_uint64 * 9), ('writer_paths', ctypes.c_uint32), ('fanotify_targets', ctypes.c_uint32),
                ('audit_written', ctypes.c_uint64), ('audit_dropped', ctypes.c_uint64), ('audit_invalid', ctypes.c_uint64),
                ('audit_queued', ctypes.c_uint32), ('audit_errno', ctypes.c_int32),
                ('diagnostic_written', ctypes.c_uint64), ('diagnostic_dropped', ctypes.c_uint64), ('diagnostic_invalid', ctypes.c_uint64),
                ('diagnostic_queued', ctypes.c_uint32), ('diagnostic_errno', ctypes.c_int32),
                *[(name, ctypes.c_uint32) for name in ('vault_paths', 'vault_sessions', 'vault_live_sessions',
                    'vault_session_history', 'vault_clock_valid', 'vault_reserved')],
                ('vault_next_deadline_boot_ns', ctypes.c_uint64)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', default='build')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('requires root to emulate a root control peer')
    assert ctypes.sizeof(Reply) == 392
    binary = Path(args.build_dir).resolve() / 'secmon'
    with tempfile.TemporaryDirectory(prefix='secmon-management-fault-') as temporary:
        path = Path(temporary) / 'fake.sock'
        cases = ['valid', 'magic', 'abi', 'size', 'command', 'code', 'last_code', 'backend', 'flags',
                 'pid', 'instance_ns', 'event', 'mode', 'fallbacks', 'reserved', 'scan-reason', 'scan-errno',
                 'writer-count', 'reserved-tail', 'audit-queue', 'audit-errno', 'audit-errno-range', 'diagnostic-queue', 'diagnostic-errno', 'diagnostic-errno-range', 'diagnostic-accounting', 'text-response', 'error-accounting', 'short', 'long', 'fds', 'extra-fds']
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
                                reply.magic, reply.abi, reply.size = 0x53434D43, 5, ctypes.sizeof(Reply)
                                reply.command, reply.backend, reply.pid, reply.instance_ns = command_id, 1, os.getpid(), 123
                                reply.worker_pid = -1
                                if case in ('magic', 'abi', 'size', 'command', 'code', 'last_code', 'backend', 'flags',
                                            'instance_ns', 'event', 'mode', 'fallbacks', 'reserved'):
                                    setattr(reply, case, {'abi': 3, 'size': ctypes.sizeof(Reply) - 1, 'command': (1 if command_id != 1 else 3), 'flags': 32,
                                                         'instance_ns': 0, 'event': 4, 'mode': 4,
                                                         'fallbacks': 8, 'reserved': 1}.get(case, 99))
                                if case == 'audit-queue': reply.audit_queued = 1025
                                if case == 'audit-errno': reply.audit_errno = -1
                                if case == 'audit-errno-range': reply.audit_errno = 4096
                                if case == 'diagnostic-queue': reply.diagnostic_queued = 257
                                if case == 'diagnostic-errno': reply.diagnostic_errno = -1
                                if case == 'diagnostic-errno-range': reply.diagnostic_errno = 4096
                                if case == 'diagnostic-accounting': reply.diagnostic_invalid = 1
                                if case == 'writer-count': reply.writer_paths = 65
                                if case == 'reserved-tail': reply.fanotify_targets = 65
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
