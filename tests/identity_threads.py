#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Observe process-level fanotify IDs and task-level BPF identities under concurrency."""
import argparse
from collections import Counter
from contextlib import ExitStack
import errno
import json
import os
import re
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import threading
import time
from credential_map import CredentialMap
from permission_audit import AuditedService, contents
from monitor_harness import MonitorRun


def actor(path, held):
    """Live, cooperative actors only: their reports are fixtures, not trusted identity evidence."""
    class Pool:
        def __init__(self):
            self.begin = threading.Barrier(5)
            self.end = threading.Barrier(5)
            self.stop = False
            self.iterations = 0
            self.tids = [0] * 4
            self.rows = [[] for _ in range(4)]
            self.ready = threading.Barrier(5)
            self.threads = [threading.Thread(target=self.work, args=(i,)) for i in range(4)]
            for thread in self.threads:
                thread.start()
            self.ready.wait()

        def work(self, index):
            self.tids[index] = threading.get_native_id()
            self.ready.wait()
            while True:
                self.begin.wait()
                if self.stop:
                    return
                self.rows[index] = [operation() for _ in range(self.iterations)]
                self.end.wait()

        def run(self, iterations):
            self.iterations = iterations
            self.begin.wait()
            self.end.wait()
            return [row for rows in self.rows for row in rows]

        def close(self):
            self.stop = True
            self.begin.wait()
            for thread in self.threads:
                thread.join()

    def operation():
        begin = time.monotonic_ns()
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
        try:
            assert os.read(fd, 1) == b's'
        finally:
            os.close(fd)
        read_end = time.monotonic_ns()
        try:
            os.pwrite(held, b'X', 0)
        except OSError as error:
            result = error.errno
        else:
            result = 0
        return dict(tid=threading.get_native_id(), begin_ns=begin, read_end_ns=read_end,
                    end_ns=time.monotonic_ns(), errno=result)

    pool = Pool()
    try:
        print(json.dumps(dict(pid=os.getpid(), tids=pool.tids)), flush=True)
        for line in sys.stdin:
            command = json.loads(line)
            if command['operation'] == 'quit':
                return
            if command['operation'] == 'replace':
                pool.close()
                pool = Pool()
                result = dict(pid=os.getpid(), tids=pool.tids)
            else:
                result = dict(rows=pool.run(command['iterations']), leader=operation())
            print(json.dumps(result), flush=True)
    finally:
        pool.close()
        os.close(held)


class Actor:
    def __init__(self, path, held, nested):
        command = [sys.executable, '-B', __file__, '--actor', str(path), str(held)]
        if nested:
            command = ['unshare', '--mount', '--pid', '--fork', '--mount-proc',
                       '--propagation', 'private', '--kill-child=KILL', '--', *command]
        self.process = subprocess.Popen(command, pass_fds=(held,), stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.local = self.read()
            self.host_pid = self.process.pid
            if nested:
                children = Path(f'/proc/{self.process.pid}/task/{self.process.pid}/children').read_text().split()
                assert len(children) == 1, children
                self.host_pid = int(children[0])
                assert self.local['pid'] == 1
            else:
                assert self.local['pid'] == self.host_pid
        except BaseException:
            self.close()
            raise

    def read(self):
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            assert selector.select(10), 'actor response deadline'
        line = self.process.stdout.readline()
        assert line, ('actor EOF', self.process.poll())
        return json.loads(line)

    def request(self, operation, iterations=12):
        self.process.stdin.write(json.dumps(dict(operation=operation, iterations=iterations)) + '\n')
        self.process.stdin.flush()
        return self.read()

    def task_mapping(self):
        # Python join/ready messages do not make a /proc task-directory walk an
        # atomic snapshot of kernel teardown. Wait for the exact expected set;
        # never silently discard an unexpected or permanently surviving task.
        expected = {self.local['pid'], *self.local['tids']}
        deadline = time.monotonic() + 3
        mapped = {}
        while time.monotonic() < deadline:
            mapped = {}
            try:
                for task in Path(f'/proc/{self.host_pid}/task').iterdir():
                    status = task.joinpath('status').read_text().splitlines()
                    ids = next(line.split()[1:] for line in status if line.startswith('NSpid:'))
                    assert int(ids[0]) == int(task.name)
                    mapped[int(ids[-1])] = int(task.name)
            except (FileNotFoundError, ProcessLookupError):
                # A task may disappear between readdir and opening its status.
                pass
            else:
                if set(mapped) == expected:
                    return mapped
            time.sleep(0.005)
        raise AssertionError(dict(expected=sorted(expected), observed=mapped))

    def close(self):
        if self.process.stdin.closed:
            return
        try:
            if self.process.poll() is None:
                try:
                    self.process.stdin.write('{"operation":"quit"}\n')
                    self.process.stdin.flush()
                    self.process.wait(timeout=5)
                except (BrokenPipeError, subprocess.TimeoutExpired):
                    self.process.kill()
                    self.process.wait(timeout=5)
            assert self.process.returncode == 0, self.process.stderr.read()
        finally:
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                stream.close()


def experiment(build, event, nested, requester_pidfd=False):
    with tempfile.TemporaryDirectory(prefix='secmon-thread-identity-') as temporary, ExitStack() as stack:
        root = Path(temporary)
        target = root / 'target'
        target.write_bytes(b'synthetic identity fixture\n')
        identity = target.stat()
        held = os.open(target, os.O_RDWR | os.O_CLOEXEC)
        stack.callback(os.close, held)
        service = AuditedService(build, root, target, f'protect "{target}"\nfanotify-event {event}\nfanotify-decision allow', combined=True, requester_pidfd=requester_pidfd)
        stack.callback(service.close)
        # The protected service deliberately rejects external /proc/fdinfo inspection.
        # A separate unprotected, read-only BPF observer supplies task baseline keys.
        observer = stack.enter_context(MonitorRun(build / 'secmon'))
        mapping = stack.enter_context(CredentialMap(observer.process.pid))
        subject = Actor(target, held, nested)
        stack.callback(subject.close)
        reference = os.pidfd_open(subject.host_pid)
        stack.callback(os.close, reference)
        process_inode = os.fstat(reference).st_ino
        rounds = []
        exited_keys = set()
        leader_key = None
        for generation in range(3):
            if generation:
                old = mapping.keys_for_group(subject.host_pid)
                subject.local = subject.request('replace')
                exited_keys |= {key for key in old if key[0] != subject.host_pid}
            local_to_host = subject.task_mapping()
            keys = mapping.keys_for_group(subject.host_pid)
            assert {key[0] for key in keys} == set(local_to_host.values()), keys
            assert keys.isdisjoint(exited_keys), 'exited worker identity survived replacement'
            current_leader = next(key for key in keys if key[0] == subject.host_pid)
            if leader_key is None:
                leader_key = current_leader
            assert current_leader == leader_key
            result = subject.request('run')
            samples = result['rows'] + [result['leader']]
            assert len(samples) == 49 and all(row['errno'] == errno.EACCES for row in samples)
            for row in samples:
                row['host_tid'] = local_to_host[row['tid']]
                row['task_start_ns'] = next(key[1] for key in keys if key[0] == row['host_tid'])
            rounds.append(dict(generation=generation, local_to_host=local_to_host,
                               task_keys=sorted(keys), samples=samples))
        subject.close()
        deadline = time.monotonic() + 3
        while mapping.keys_for_group(subject.host_pid):
            assert time.monotonic() < deadline, 'actor task keys survived exit'
            time.sleep(0.01)
        service.stop()
        records = [json.loads(line) for line in contents(service.output).splitlines()]
        permissions = [row for row in records if row['event'] == 'fanotify_decision']
        denials = [row for row in records if row['event'] == 'file_denied']
        samples = [row for result in rounds for row in result['samples']]
        assert len(permissions) == len(denials) == len(samples) == 147
        assert sorted(row['request_id'] for row in permissions) == list(range(1, 148))
        for row in permissions:
            if requester_pidfd:
                assert row['requester_reference'] == 'present' and row['requester_identity_errno'] == 0
                assert row['requester_process_inode'] == process_inode
            assert row['requester_pid_kind'] == 'tgid'
            assert row['pid_namespace_inode'] == os.stat('/proc/self/ns/pid').st_ino
            assert row['requester_pid'] == subject.host_pid  # TGID, not the acting worker TID.
            assert row['listener_pid'] == service.process.pid and row['instance_ns'] == service.initial['instance_ns']
            assert row['revision'] == 1 and row['decision'] == 'allow' and row['reason'] == 'policy'
            assert row['permission_event'] == event
            assert (row['major'], row['minor'], row['inode']) == (os.major(identity.st_dev), os.minor(identity.st_dev), identity.st_ino)
            # Concurrent time windows may overlap: deliberately retain ambiguity.
            candidates = [sample for sample in samples if sample['begin_ns'] <= row['received_ns'] <= sample['read_end_ns']]
            assert candidates
            row['candidate_host_tids'] = sorted({sample['host_tid'] for sample in candidates})
        expected = Counter((row['host_tid'], row['task_start_ns']) for row in samples)
        observed = Counter()
        for row in denials:
            assert row['process_inode'] == process_inode
            assert row['pid'] == subject.host_pid and row['operation'] == 2 and row['errno'] == errno.EACCES
            assert (row['dev_major'], row['dev_minor'], row['ino']) == (os.major(identity.st_dev), os.minor(identity.st_dev), identity.st_ino)
            observed[(row['tid'], row['start_ns'])] += 1
            candidates = [sample for sample in samples if sample['host_tid'] == row['tid'] and
                          sample['read_end_ns'] <= row['timestamp_ns'] <= sample['end_ns']]
            assert len(candidates) == 1, (row, candidates)
        assert observed == expected, (observed, expected)
        diagnostics = contents(service.errors)
        for field in ('audit_dropped', 'audit_invalid', 'audit_queued', 'audit_errno', 'ringbuf_dropped', 'baseline_update_failed'):
            values = re.findall(r'\b' + field + r'=(\d+)', diagnostics)
            assert values and int(values[-1]) == 0, (field, values)
        assert target.read_bytes() == b'synthetic identity fixture\n'
        return dict(event=event, nested=nested, host_pid=subject.host_pid, process_inode=process_inode, leader_key=leader_key,
                    audit_jsonl=contents(service.output),
                    rounds=rounds, permissions=permissions, denials=denials, diagnostics=diagnostics,
                    ambiguous_permissions=sum(len(row['candidate_host_tids']) > 1 for row in permissions))


def main():
    if '--actor' in sys.argv:
        actor(sys.argv[-2], int(sys.argv[-1]))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', default='build')
    parser.add_argument('--report', type=Path)
    parser.add_argument('--requester-pidfd', action='store_true')
    parser.add_argument('--duration', type=int, default=0, help='repeat all four variants for 0..1200 seconds')
    args = parser.parse_args()
    if os.geteuid() != 0 or sys.flags.optimize:
        parser.error('run as root without Python optimization')
    assert os.readlink('/proc/self/ns/pid') == os.readlink('/proc/1/ns/pid')
    assert Path('/proc/1/status').read_text().split('NSpid:')[1].splitlines()[0].split() == ['1']
    if not 0 <= args.duration <= 1200:
        parser.error('duration must be 0..1200 seconds')
    deadline = time.monotonic() + args.duration
    reports = []
    cycle = 0
    baseline_fds = len(list(Path('/proc/self/fd').iterdir()))
    while True:
        cycle += 1
        reports = []
        for nested in (False, True):
            for event in ('open', 'access'):
                report = experiment(Path(args.build_dir).resolve(), event, nested, args.requester_pidfd)
                reports.append(report)
                print(json.dumps(dict(experiment='identity-threads', cycle=cycle, event=event, nested=nested, permission_records=147,
                                      denial_records=147, ambiguous_permissions=report['ambiguous_permissions'], passed=True)), flush=True)
        assert len(list(Path('/proc/self/fd').iterdir())) == baseline_fds, 'controller FD leak across cycles'
        if time.monotonic() >= deadline:
            break
    if args.report:
        args.report.write_text(json.dumps(dict(cycles=cycle, permission_records=588 * cycle, denial_records=588 * cycle,
                                              last_cycle=reports), indent=2) + '\n')


if __name__ == '__main__':
    main()
