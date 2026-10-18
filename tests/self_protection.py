#!/usr/bin/env python3
# 验证信号、ptrace 类入口和 root 管理停止；这不等于抵御所有内核生成信号或拥有完整权限的管理员。
"""Root-only bounded test of self-protection and its management channel."""
import argparse
import ctypes
import errno
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', default='build')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('requires root')
    binary = Path(args.build_dir).resolve() / 'secmon'
    with tempfile.TemporaryDirectory(prefix='secmon-self-') as directory:
        control = Path(directory) / 'control.sock'
        output = Path(directory) / 'events.jsonl'
        errors = Path(directory) / 'stderr.log'
        with output.open('w') as stdout, errors.open('w') as stderr:
            monitor = subprocess.Popen([str(binary), '--self-protect', str(control),
                                        '--run-for', '20'], stdout=stdout, stderr=stderr)
            try:
                deadline = time.monotonic() + 10
                while 'Audit active;' not in errors.read_text():
                    if monitor.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError('monitor not ready\n' + errors.read_text())
                    time.sleep(0.05)
                os.kill(monitor.pid, 0)
                for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGSTOP,
                            signal.SIGKILL, signal.SIGUSR1):
                    try:
                        os.kill(monitor.pid, sig)
                    except PermissionError as error:
                        assert error.errno == errno.EPERM
                    else:
                        raise RuntimeError(f'signal {sig} unexpectedly allowed')
                    print(f'PASS deny signal {sig.name}')
                pidfd = os.pidfd_open(monitor.pid)
                try:
                    try:
                        signal.pidfd_send_signal(pidfd, signal.SIGTERM)
                    except PermissionError:
                        pass
                    else:
                        raise RuntimeError('pidfd signal unexpectedly allowed')
                finally:
                    os.close(pidfd)
                print('PASS deny pidfd signal')
                libc = ctypes.CDLL(None, use_errno=True)
                # Current development target is x86_64; tgkill syscall number 234.
                if libc.syscall(234, monitor.pid, monitor.pid, signal.SIGTERM) != -1 or \
                   ctypes.get_errno() != errno.EPERM:
                    raise RuntimeError('tgkill not denied with EPERM')
                print('PASS deny tgkill')
                libc.ptrace.argtypes = [ctypes.c_ulong, ctypes.c_ulong,
                                        ctypes.c_void_p, ctypes.c_void_p]
                libc.ptrace.restype = ctypes.c_long
                if libc.ptrace(0x4206, monitor.pid, None, None) != -1 or \
                   ctypes.get_errno() != errno.EPERM:  # PTRACE_SEIZE (does not stop target)
                    raise RuntimeError('ptrace not denied with EPERM')
                print('PASS deny ptrace seize')
                # process_vm_writev and /proc/PID/mem also use ptrace access checks.
                try:
                    fd = os.open(f'/proc/{monitor.pid}/mem', os.O_RDWR)
                except PermissionError:
                    pass
                else:
                    os.close(fd)
                    raise RuntimeError('/proc/PID/mem unexpectedly opened')
                print('PASS deny proc mem open')
                class Iovec(ctypes.Structure):
                    _fields_ = [('base', ctypes.c_void_p), ('length', ctypes.c_size_t)]
                byte = ctypes.create_string_buffer(b'x')
                local = Iovec(ctypes.cast(byte, ctypes.c_void_p), 1)
                # Invalid remote address ensures no memory is changed even on failure.
                remote = Iovec(1, 1)
                libc.process_vm_writev.argtypes = [ctypes.c_int, ctypes.POINTER(Iovec),
                                                   ctypes.c_ulong, ctypes.POINTER(Iovec),
                                                   ctypes.c_ulong, ctypes.c_ulong]
                libc.process_vm_writev.restype = ctypes.c_ssize_t
                if libc.process_vm_writev(monitor.pid, ctypes.byref(local), 1,
                                          ctypes.byref(remote), 1, 0) != -1 or \
                   ctypes.get_errno() != errno.EPERM:
                    raise RuntimeError('process_vm_writev not denied with EPERM')
                print('PASS deny process_vm_writev access')
                unprotected = subprocess.Popen(['/usr/bin/sleep', '10'])
                try:
                    unprotected.terminate()
                    assert unprotected.wait(timeout=3) == -signal.SIGTERM
                finally:
                    if unprotected.poll() is None:
                        unprotected.kill()
                        unprotected.wait()
                print('PASS unprotected process signal')
                # Invalid management commands must leave the service running.
                with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
                    client.settimeout(2)
                    client.connect(str(control))
                    client.sendall(b'bad-command')
                    assert client.recv(16) == b''
                assert monitor.poll() is None
                print('PASS reject invalid control command')
                nonroot_client = """import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
try:
    s.connect(sys.argv[1])
except PermissionError:
    sys.exit(0)
s.sendall(b'stop')
sys.exit(1)
"""
                rejected = subprocess.run(['/usr/bin/python3', '-c', nonroot_client, str(control)],
                                          user=65534, group=65534, extra_groups=[],
                                          capture_output=True, timeout=5)
                assert rejected.returncode == 0, rejected.stderr
                assert monitor.poll() is None
                print('PASS reject non-root stop')
                result = subprocess.run([str(binary), '--stop', str(control)],
                                        capture_output=True, text=True, timeout=5)
                if result.returncode:
                    raise RuntimeError(result.stderr)
                monitor.wait(timeout=5)
                assert monitor.returncode == 0
                assert not control.exists(), 'control socket not removed'
                print('PASS authorized root stop and socket cleanup')
            finally:
                if monitor.poll() is None:
                    subprocess.run([str(binary), '--stop', str(control)],
                                   capture_output=True, timeout=4)
                    # Internal deadline guarantees cleanup even if control fails.
                    monitor.wait(timeout=25)
        diagnostics = errors.read_text()
        events = [json.loads(line) for line in output.read_text().splitlines()]
        denials = [e for e in events if e['event'] == 'self_denied']
        assert denials, 'missing self denial events'
        assert all(e['pid'] == os.getpid() and e['tid'] == os.getpid() for e in denials)
        assert len({e['start_ns'] for e in denials}) == 1 and denials[0]['start_ns'] > 0
        assert all(e['target_pid'] == monitor.pid and e['errno'] == errno.EPERM for e in denials)
        assert any(e['operation'] == 9 for e in denials), 'missing signal denial event'
        assert any(e['operation'] == 10 for e in denials), 'missing ptrace denial event'
        assert 'ringbuf_dropped=0' in diagnostics, diagnostics
        assert 'baseline_update_failed=0' in diagnostics, diagnostics
        print('PASS self-protection audit identity and counters')
        bounded = subprocess.run([str(binary), '--self-protect', str(control),
                                  '--run-for', '1'], capture_output=True, text=True, timeout=5)
        assert bounded.returncode == 0, bounded.stderr
        assert 'Self protection active;' in bounded.stderr
        assert not control.exists()
        print('PASS internal deadline and socket cleanup')


if __name__ == '__main__':
    main()
