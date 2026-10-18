#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prove process pidfs identity through exec, non-leader exec, and leader-thread exit."""
import argparse
from contextlib import ExitStack
import errno
import json
import os
import re
from pathlib import Path
import select
import selectors
import signal
import subprocess
import sys
import tempfile
import time
from permission_audit import AuditedService, contents


class Subject:
    def __init__(self, build, target, held, nested):
        command = [str(build / 'secmon-requester-lifecycle'), str(target), str(held)]
        if nested:
            command = ['unshare', '--mount', '--pid', '--fork', '--mount-proc',
                       '--propagation', 'private', '--kill-child=KILL', '--', *command]
        self.process = subprocess.Popen(command, pass_fds=(held,), stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.ready = self.read()
            self.host_pid = self.process.pid
            if nested:
                children = Path(f'/proc/{self.process.pid}/task/{self.process.pid}/children').read_text().split()
                assert len(children) == 1
                self.host_pid = int(children[0])
                assert self.ready['pid'] == 1
            else:
                assert self.ready['pid'] == self.host_pid
            self.reference = os.pidfd_open(self.host_pid)
            self.inode = os.fstat(self.reference).st_ino
            assert self.ready['process_inode'] == self.inode
        except BaseException:
            self.close()
            raise

    def read(self):
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            assert selector.select(5), 'native actor deadline'
        line = self.process.stdout.readline()
        assert line, ('native actor EOF', self.process.poll(), self.process.stderr.read())
        return json.loads(line)

    def request(self, command):
        self.process.stdin.write(command + '\n')
        self.process.stdin.flush()
        return self.read()

    def stop(self):
        if self.process.poll() is None:
            self.process.stdin.write('exit\n')
            self.process.stdin.flush()
            self.process.wait(timeout=5)
        assert self.process.returncode == 0, self.process.stderr.read()

    def close(self):
        if self.process.stdin.closed:
            return
        try:
            try:
                self.stop()
            except (BrokenPipeError, subprocess.TimeoutExpired):
                self.process.kill()
                self.process.wait(timeout=5)
                raise
        finally:
            if hasattr(self, 'reference'):
                os.close(self.reference)
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                stream.close()


def experiment(build, event, nested):
    with tempfile.TemporaryDirectory(prefix='secmon-requester-lifecycle-') as temporary, ExitStack() as stack:
        root = Path(temporary)
        target = root / 'target'
        target.write_bytes(b'synthetic lifecycle fixture\n')
        held = os.open(target, os.O_RDWR | os.O_CLOEXEC)
        stack.callback(os.close, held)
        service = AuditedService(build, root, target, f'protect "{target}"\nfanotify-event {event}\nfanotify-decision allow',
                                 combined=True, requester_pidfd=True)
        stack.callback(service.close)
        subjects, samples = [], []
        for scenario in ('exec', 'leader-exit'):
            subject = Subject(build, target, held, nested)
            stack.callback(subject.close)
            subjects.append(subject)
            commands = ['probe', 'thread-probe', 'exec-leader', 'probe', 'exec-worker', 'probe'] if scenario == 'exec' else ['probe', 'leader-exit', 'probe']
            for command in commands:
                begin = time.monotonic_ns()
                row = subject.request(command)
                end = time.monotonic_ns()
                assert row['pid'] == subject.ready['pid'] and row['process_inode'] == subject.inode
                assert not select.select([subject.reference], [], [], 0)[0], 'process pidfd became readable while group still alive'
                if command == 'leader-exit':
                    deadline = time.monotonic() + 3
                    leader = Path(f'/proc/{subject.host_pid}/task/{subject.host_pid}/stat')
                    while leader.read_text().rsplit(')', 1)[1].split()[0] != 'Z':
                        assert time.monotonic() < deadline, 'leader did not exit'
                        time.sleep(0.005)
                    assert row['tid'] != row['pid']
                if row['phase'] == 'probe':
                    assert row['errno'] == errno.EACCES
                    samples.append(dict(scenario=scenario, command=command, host_pid=subject.host_pid,
                                        inode=subject.inode, begin_ns=begin, end_ns=end, actor=row))
            subject.stop()
            assert select.select([subject.reference], [], [], 0)[0]
            try:
                signal.pidfd_send_signal(subject.reference, 0)
            except ProcessLookupError:
                pass
            else:
                raise AssertionError('exited process reference accepted a signal')
            assert os.fstat(subject.reference).st_ino == subject.inode
        service.stop()
        records = [json.loads(line) for line in contents(service.output).splitlines()]
        permissions = [row for row in records if row['event'] == 'fanotify_decision']
        denials = [row for row in records if row['event'] == 'file_denied']
        assert len(permissions) == len(denials) == len(samples) == 6
        for sample in samples:
            permission = [row for row in permissions if row['requester_pid'] == sample['host_pid'] and
                          sample['begin_ns'] <= row['received_ns'] <= sample['end_ns']]
            denial = [row for row in denials if row['pid'] == sample['host_pid'] and
                      sample['begin_ns'] <= row['timestamp_ns'] <= sample['end_ns']]
            assert len(permission) == len(denial) == 1
            assert permission[0]['requester_reference'] == 'present'
            assert permission[0]['requester_process_inode'] == denial[0]['process_inode'] == sample['inode']
            assert permission[0]['requester_identity_errno'] == 0
            assert denial[0]['operation'] == 2
            sample['permission'], sample['denial'] = permission[0], denial[0]
        for subject in subjects:
            executions = [row for row in records if row['event'] == 'exec_success' and row['pid'] == subject.host_pid]
            assert len(executions) == (3 if subject == subjects[0] else 1), executions
            assert all(row['process_inode'] == subject.inode for row in executions)
            if subject == subjects[0]:
                assert any(row['old_tid'] != row['pid'] for row in executions), 'missing non-leader exec'
        assert target.read_bytes() == b'synthetic lifecycle fixture\n'
        for field in ('audit_dropped', 'audit_invalid', 'audit_queued', 'audit_errno', 'ringbuf_dropped', 'baseline_update_failed'):
            values = re.findall(r'\b' + field + r'=(\d+)', contents(service.errors))
            assert values and int(values[-1]) == 0, (field, values)
        return dict(event=event, nested=nested, samples=samples, passed=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', default='build')
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0 or sys.flags.optimize:
        parser.error('run as root without Python optimization')
    reports = []
    for nested in (False, True):
        for event in ('open', 'access'):
            reports.append(experiment(Path(args.build_dir).resolve(), event, nested))
            print(json.dumps(dict(experiment='requester-lifecycle', event=event, nested=nested, probes=6, passed=True)), flush=True)
    if args.report:
        args.report.write_text(json.dumps(reports, indent=2) + '\n')


if __name__ == '__main__':
    main()
