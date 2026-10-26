#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Root helper protection follows task ancestry, including a replacement reader."""
import argparse
from contextlib import ExitStack
import ctypes
import errno
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from permission_audit import AuditedService, contents, request
from management_harness import call


def denied_signal(pid, sig):
    try:
        os.kill(pid, sig)
    except PermissionError as error:
        assert error.errno == errno.EPERM
    else:
        # Avoid leaving a stopped helper if a regression makes the assertion fail.
        if sig == signal.SIGSTOP: os.kill(pid, signal.SIGCONT)
        raise AssertionError(f'helper signal {sig} was allowed')


def inspect_reader(pid):
    os.kill(pid, 0)
    for sig in (signal.SIGTERM, signal.SIGSTOP, signal.SIGKILL):
        denied_signal(pid, sig)
    with os.fdopen(os.pidfd_open(pid), 'rb', closefd=True) as ref:
        try:
            signal.pidfd_send_signal(ref.fileno(), signal.SIGTERM)
        except PermissionError as error:
            assert error.errno == errno.EPERM
        else:
            raise AssertionError('helper pidfd signal was allowed')
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p]
    libc.ptrace.restype = ctypes.c_long
    assert libc.ptrace(0x4206, pid, None, None) == -1 and ctypes.get_errno() == errno.EPERM
    try:
        ref = os.open(f'/proc/{pid}/mem', os.O_RDWR)
    except PermissionError:
        pass
    else:
        os.close(ref); raise AssertionError('helper memory was exposed')


def experiment(build, analysis, namespaced=False):
    with tempfile.TemporaryDirectory(prefix='secmon-helper-guard-') as tmp, ExitStack() as stack:
        root = Path(tmp); target = root / 'first'; target.write_bytes(b'clean')
        second = root / 'second'; second.write_bytes(b'other clean')
        fields = (f'fanotify-analyzer "{build / "secmon-analyzer"}"\nfanotify-marker "BLOCK"\n' if analysis
                  else 'fanotify-decision allow\n')
        service = AuditedService(build, root, target, fields, combined=True)
        stack.callback(service.close)
        state = service.status(); assert state['self_protected']
        first = state['reader_pid']; inspect_reader(first)
        assert request(target)['errno'] == 0
        protected = [first]
        if analysis:
            # A dropped-UID scanner is not treated as a privileged helper. Its
            # existing failure-injection and offline-fallback contract survives.
            worker = state['analyzer_pid']
            assert 'Uid:\t65534\t65534\t65534\t65534' in Path(f'/proc/{worker}/status').read_text()
            os.kill(worker, signal.SIGSTOP); os.kill(worker, signal.SIGCONT)
            assert request(target)['errno'] == 0
        else:
            # Replacement helper inherits protection by actual parent task,
            # without a registration window or a numerical PID allow-list.
            stage = root / 'staging'
            stage.write_text(f'revision 2\nfanotify-file "{second}"\nfanotify-decision allow\n')
            stage.chmod(0o600); stage.replace(service.policy)
            changed = call(build / 'secmon', 'reload', service.control)
            replacement = changed['reader_pid']
            assert replacement > 0 and replacement != first
            inspect_reader(replacement); protected.append(replacement)
            assert request(second)['errno'] == 0
            # Host-authorized handover must kill/reap its old helper normally.
            until = time.monotonic() + 2
            while Path(f'/proc/{first}').exists():
                assert time.monotonic() < until
                time.sleep(.01)
        unrelated = subprocess.Popen(['/usr/bin/sleep', '10'])
        try:
            unrelated.terminate(); assert unrelated.wait(timeout=2) == -signal.SIGTERM
        finally:
            if unrelated.poll() is None: unrelated.kill(); unrelated.wait(timeout=2)
        service.stop()
        for pid in protected:
            assert not Path(f'/proc/{pid}').exists(), pid
        events = [json.loads(line) for line in contents(service.output).splitlines()]
        rows = [e for e in events if e['event'] == 'self_denied' and (namespaced or e['target_pid'] in protected)]
        audited_targets = {e['target_pid'] for e in rows} if namespaced else protected
        assert len(audited_targets) == len(protected), rows
        for pid in audited_targets:
            assert {e['signal'] for e in rows if e['target_pid'] == pid} >= {int(signal.SIGTERM), int(signal.SIGSTOP), int(signal.SIGKILL)}, rows
        assert all(e['errno'] == errno.EPERM for e in rows)
        print(json.dumps({'analysis': analysis, 'pid_namespace': namespaced, 'protected_readers': len(protected), 'denials': len(rows),
                          'authorized_cleanup': True, 'dropped_scanner_unchanged': analysis}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, default=Path('build'))
    parser.add_argument('--inside-pid-namespace', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if os.geteuid() != 0 or not __debug__: parser.error('run as root without Python optimization')
    if args.inside_pid_namespace: assert os.getpid() == 1
    for analysis in (False, True): experiment(args.build_dir.resolve(), analysis, args.inside_pid_namespace)
    if not args.inside_pid_namespace:
        subprocess.run(['unshare', '--mount', '--pid', '--fork', '--mount-proc', sys.executable, '-B',
                        str(Path(__file__).resolve()), '--build-dir', str(args.build_dir.resolve()),
                        '--inside-pid-namespace'], check=True, timeout=20)
    print('PASS privileged reader ancestry protection, handover, ptrace rejection and authorized cleanup')


if __name__ == '__main__': main()
