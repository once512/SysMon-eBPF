#!/usr/bin/env python3
# BPF 审计与文件只读端到端测试；使用独立进程触发实际 LSM 检查，验证拒绝、身份事件及卸载恢复。
"""Privileged integration test: temporary audit attach and exact-file read-only policy tests."""
import argparse
import ctypes
import errno
import mmap
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', default='build')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run with sudo to load the audit programs')
    build = Path(args.build_dir).resolve()
    with tempfile.TemporaryDirectory(prefix='secmon-test-') as directory:
        output = Path(directory) / 'events.jsonl'
        errors = Path(directory) / 'stderr.log'
        protected = Path(directory) / 'protected.txt'
        protected.write_bytes(b'original data\n')
        alias = Path(directory) / 'hardlink.txt'
        os.link(protected, alias)
        control = Path(directory) / 'control.txt'
        control.write_bytes(b'control\n')
        identity = protected.stat()
        # Open before policy activation to test use of an existing writable FD.
        writable = os.open(protected, os.O_RDWR)
        with output.open('w') as stdout, errors.open('w') as stderr:
            monitor = subprocess.Popen([str(build / 'secmon'), '--protect-file', str(protected)],
                                       stdout=stdout, stderr=stderr)
            try:
                deadline = time.monotonic() + 10
                while 'Audit active;' not in errors.read_text():
                    if monitor.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError('monitor did not become ready\n' + errors.read_text())
                    time.sleep(0.05)
                def denied(name, operation):
                    try:
                        operation()
                    except OSError as error:
                        if error.errno != errno.EACCES:
                            raise RuntimeError(f'{name}: unexpected errno {error.errno}') from error
                    else:
                        raise RuntimeError(f'{name}: operation unexpectedly allowed')
                    print(f'PASS deny {name}')

                def write_open(path):
                    fd = os.open(path, os.O_WRONLY)
                    os.close(fd)

                denied('write-open', lambda: write_open(protected))
                denied('hardlink-write', lambda: write_open(alias))
                denied('existing-fd-write', lambda: os.write(writable, b'changed'))
                denied('existing-fd-truncate', lambda: os.ftruncate(writable, 0))
                denied('path-truncate', lambda: os.truncate(protected, 0))
                denied('unlink', lambda: os.unlink(protected))
                denied('rename-source', lambda: os.rename(protected, Path(directory) / 'moved'))
                denied('rename-target', lambda: os.rename(control, protected))
                denied('new-hardlink', lambda: os.link(protected, Path(directory) / 'new-link'))
                denied('chmod', lambda: os.chmod(protected, 0o600))
                denied('utime', lambda: os.utime(protected, None))

                def shared_mapping():
                    with mmap.mmap(writable, 0, flags=mmap.MAP_SHARED,
                                   prot=mmap.PROT_READ | mmap.PROT_WRITE):
                        pass
                denied('shared-writable-mmap', shared_mapping)
                # A private writable mapping cannot modify the backing file.
                with mmap.mmap(writable, 0, flags=mmap.MAP_PRIVATE,
                               prot=mmap.PROT_READ | mmap.PROT_WRITE) as private:
                    private[0] = ord('X')
                libc = ctypes.CDLL(None, use_errno=True)
                libc.mmap.restype = ctypes.c_void_p
                libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                                      ctypes.c_int, ctypes.c_int, ctypes.c_long]
                libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
                libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                address = libc.mmap(None, 4096, mmap.PROT_READ, mmap.MAP_SHARED, writable, 0)
                if address == ctypes.c_void_p(-1).value:
                    raise OSError(ctypes.get_errno(), 'read-only mmap failed')
                try:
                    result = libc.mprotect(address, 4096, mmap.PROT_READ | mmap.PROT_WRITE)
                    if result != -1 or ctypes.get_errno() != errno.EACCES:
                        raise RuntimeError('mprotect unexpectedly allowed or wrong error')
                    print('PASS deny shared-mprotect')
                finally:
                    libc.munmap(address, 4096)
                if protected.read_bytes() != b'original data\n':
                    raise RuntimeError('protected contents changed')
                control.write_bytes(b'allowed\n')
                print('PASS read/private-mmap and unprotected write')
                cases = {}
                for mode in ('exec', 'threads', 'thread-exec', 'drop-exec'):
                    child = subprocess.Popen([str(build / 'secmon-scenarios'), mode])
                    cases[mode] = child.pid
                    result = child.wait(timeout=10)
                    if result != 0:
                        raise RuntimeError(f'{mode}: helper exit {result}')
                time.sleep(0.5)
            finally:
                os.close(writable)
                if monitor.poll() is None:
                    monitor.send_signal(signal.SIGTERM)
                try:
                    monitor.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    monitor.kill()
                    monitor.wait()
                    raise RuntimeError('monitor failed to stop')
        diagnostics = errors.read_text()
        if monitor.returncode != 0:
            raise RuntimeError(diagnostics)
        events = [json.loads(line) for line in output.read_text().splitlines()]
        denials = [e for e in events if e['event'] == 'file_denied']
        assert denials, 'no denial audit events'
        assert all(e['ino'] == identity.st_ino and
                   e['dev_major'] == os.major(identity.st_dev) and
                   e['dev_minor'] == os.minor(identity.st_dev) for e in denials)
        assert all(e['errno'] == errno.EACCES for e in denials)
        # A stopped monitor must release policy; no persistent links are pinned.
        protected.write_bytes(b'after stop\n')
        print('PASS denial identity/audit and policy removal')
        for mode, pid in cases.items():
            matching = [e for e in events if e['pid'] == pid]
            checks = [e for e in matching if e['event'] == 'exec_check'
                      and e['filename'] == '/usr/bin/true']
            success = [e for e in matching if e['event'] == 'exec_success'
                       and e['filename'] == '/usr/bin/true']
            assert checks and success, f'{mode}: missing check or completion'
            assert all(e['flags'] == 0 for e in matching), f'{mode}: credential mismatch'
            if mode == 'thread-exec':
                assert any(e['old_tid'] != e['tid'] for e in success), 'TID change not observed'
                assert any(c['tid'] == s['old_tid'] for c in checks for s in success), \
                    'pre-exec thread not linked to completion'
            if mode == 'drop-exec':
                assert all(e['uid'] == 65534 and e['euid'] == 65534 for e in checks + success)
            print(f'PASS {mode} pid={pid}')
        assert 'ringbuf_dropped=0' in diagnostics, diagnostics
        assert 'baseline_update_failed=0' in diagnostics, diagnostics
        print('PASS audit pipeline and clean shutdown (not an attack-detection test)')


if __name__ == '__main__':
    main()
