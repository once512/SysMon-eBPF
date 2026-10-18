#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Kernel-delivered process references through cancellation, capacity, shutdown, and FD pressure."""
import argparse
from contextlib import ExitStack
import errno
import json
import os
from pathlib import Path
import re
import resource
import shutil
import selectors
import signal
import subprocess
import sys
import tempfile
import time
from permission_audit import AuditedService, contents

CODE = '''import json,os,sys
print('ready',flush=True)
assert sys.stdin.readline().strip() == 'go'
if sys.argv[2] == 'exec': os.execv(sys.argv[1], [sys.argv[1]])
try:
 fd=os.open(sys.argv[1],os.O_RDONLY)
 try:
  if sys.argv[2] == 'access': os.read(fd,1)
 finally: os.close(fd)
except OSError as error: result=error.errno
else: result=0
print(json.dumps({'pid':os.getpid(),'errno':result}),flush=True)
sys.stdin.readline()
'''


class Requester:
    def __init__(self, target, event):
        self.process = subprocess.Popen([sys.executable, '-B', '-c', CODE, str(target), event],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            assert self.read() == 'ready'
            self.reference = os.pidfd_open(self.process.pid)
            self.inode = os.fstat(self.reference).st_ino
        except BaseException:
            self.close()
            raise

    def read(self):
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            assert selector.select(5), 'requester deadline'
        line = self.process.stdout.readline()
        assert line, ('requester EOF', self.process.poll())
        return line.strip()

    def go(self):
        self.process.stdin.write('go\n')
        self.process.stdin.flush()

    def finish(self, expected=0):
        result = json.loads(self.read())
        assert result == {'pid': self.process.pid, 'errno': expected}, result

    def kill(self):
        signal.pidfd_send_signal(self.reference, signal.SIGKILL)
        self.process.wait(timeout=5)
        assert self.process.returncode == -signal.SIGKILL

    def close(self):
        if self.process.stdin.closed:
            return
        try:
            if self.process.poll() is None:
                try:
                    self.process.stdin.write('exit\n')
                    self.process.stdin.flush()
                    self.process.wait(timeout=5)
                except (BrokenPipeError, subprocess.TimeoutExpired):
                    self.process.kill()
                    self.process.wait(timeout=5)
            assert self.process.returncode in (0, -signal.SIGKILL), self.process.stderr.read()
        finally:
            if hasattr(self, 'reference'):
                os.close(self.reference)
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                stream.close()


def records(service):
    rows = [json.loads(line) for line in contents(service.output).splitlines()]
    return [row for row in rows if row['event'] == 'fanotify_decision']


def verify(service, expected):
    rows = records(service)
    assert len(rows) == len(expected), (rows, expected)
    assert sorted(row['request_id'] for row in rows) == list(range(1, len(rows) + 1))
    for row in rows:
        inode, reason, decision, state = expected[row['requester_pid']]
        assert row['requester_process_inode'] == inode
        assert row['reason'] == reason and row['decision'] == decision
        assert row['requester_reference'] == state and row['requester_identity_errno'] == 0
        assert row['requester_pid_kind'] == 'tgid'
    for field in ('audit_dropped', 'audit_invalid', 'audit_queued', 'audit_errno'):
        values = re.findall(r'\b' + field + r'=(\d+)', contents(service.errors))
        assert values and int(values[-1]) == 0, (field, values)


def scenario(build, event, kind):
    with tempfile.TemporaryDirectory(prefix='secmon-requester-pidfd-') as temporary, ExitStack() as stack:
        root = Path(temporary)
        target = root / 'target'
        target.write_bytes(b'clean')
        fields = f'fanotify-event {event}\nfanotify-decision allow\nfanotify-delay-ms 400\nfanotify-timeout-ms 2000\nfanotify-max-pending 1'
        if kind == 'timeout':
            fields = f'fanotify-event {event}\nfanotify-decision allow\nfanotify-delay-ms 1000\nfanotify-timeout-ms 100'
        if kind in ('analysis', 'analysis-error'):
            fields = f'fanotify-event {event}\nfanotify-analyzer "{build / "secmon-analyzer"}"\nfanotify-marker "BLOCK"'
        if kind == 'analysis-error':
            fields = f'fanotify-event {event}\nfanotify-analyzer "{build / "secmon-analysis-fault-worker"}"\nfanotify-marker "wrong-id"'
        if kind == 'exec':
            shutil.copy2('/usr/bin/true', target)
        if kind == 'fd-pressure':
            fields = f'fanotify-event {event}\nfanotify-decision allow'
        service = AuditedService(build, root, target, fields, requester_pidfd=True)
        stack.callback(service.close)
        baseline = set(int(path.name) for path in Path(f'/proc/{service.process.pid}/fd').iterdir())
        expected = {}
        child = Requester(target, event)
        stack.callback(child.close)
        if kind == 'fd-pressure':
            old = resource.prlimit(service.process.pid, resource.RLIMIT_NOFILE)
            free = next(value for value in range(max(baseline) + 2) if value not in baseline)
            # Only one free slot below the soft limit: event file succeeds, PIDFD allocation fails.
            resource.prlimit(service.process.pid, resource.RLIMIT_NOFILE, (free + 1, old[1]))
            try:
                child.go()
                child.finish()
            finally:
                resource.prlimit(service.process.pid, resource.RLIMIT_NOFILE, old)
            expected[child.process.pid] = (0, 'policy', 'allow', 'error')
        else:
            child.go()
            if kind in ('cancel', 'capacity', 'shutdown'):
                service.wait_pending(1)
            if kind == 'cancel':
                child.kill()
                service.wait_pending(0)
                expected[child.process.pid] = (child.inode, 'policy', 'allow', 'present')
            elif kind == 'capacity':
                second = Requester(target, event)
                stack.callback(second.close)
                second.go()
                second.finish(errno.EPERM)
                child.finish()
                expected[child.process.pid] = (child.inode, 'policy', 'allow', 'present')
                expected[second.process.pid] = (second.inode, 'capacity', 'deny', 'present')
            elif kind == 'shutdown':
                service.stop()
                child.finish(errno.EPERM)
                expected[child.process.pid] = (child.inode, 'shutdown', 'deny', 'present')
            elif kind == 'exec':
                child.process.wait(timeout=5)
                assert child.process.returncode == 0
                expected[child.process.pid] = (child.inode, 'policy', 'allow', 'present')
            else:
                denied = kind in ('timeout', 'analysis-error')
                child.finish(errno.EPERM if denied else 0)
                reason = {'timeout': 'timeout', 'analysis-error': 'analyzer_error'}.get(kind, 'analysis')
                expected[child.process.pid] = (child.inode, reason, 'deny' if denied else 'allow', 'present')
        if kind != 'shutdown':
            service.wait_pending(0)
            deadline = time.monotonic() + 3
            def recovered():
                current = set(int(path.name) for path in Path(f'/proc/{service.process.pid}/fd').iterdir())
                return len(current) == len(baseline) - 1 if kind == 'analysis-error' else current == baseline
            while not recovered():
                assert time.monotonic() < deadline, 'request handles not released back to baseline'
                time.sleep(0.01)
        service.stop()
        verify(service, expected)
    print(json.dumps(dict(experiment='requester-pidfd', event=event, scenario=kind, passed=True)), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', default='build')
    args = parser.parse_args()
    if os.geteuid() != 0 or sys.flags.optimize:
        parser.error('run as root without Python optimization')
    for event in ('open', 'access'):
        for kind in ('cancel', 'capacity', 'shutdown', 'timeout', 'analysis', 'analysis-error', 'fd-pressure'):
            scenario(Path(args.build_dir).resolve(), event, kind)
    scenario(Path(args.build_dir).resolve(), 'exec', 'exec')


if __name__ == '__main__':
    main()
