#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Full-file indexing/copy workloads across decoy aliases and pathname replacement."""
import argparse
from contextlib import ExitStack
import hashlib
import errno
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import subprocess
import sys
import tempfile
import time
from permission_audit import AuditedService, contents
from writer_harness import WriterProcess

CHUNK = 4096


def worker():
    print('ready', flush=True)
    for line in sys.stdin:
        command = json.loads(line)
        if command['operation'] == 'quit':
            return
        result = []
        for name in command['paths']:
            digest, total = hashlib.sha256(), 0
            destination = None
            try:
                if command['operation'] == 'backup':
                    destination = open(Path(command['destination']) / Path(name).name, 'xb', buffering=0)
                with open(name, 'rb', buffering=0) as source:
                    while True:
                        chunk = source.read(CHUNK)
                        if not chunk:
                            break
                        digest.update(chunk)
                        total += len(chunk)
                        if destination:
                            remaining = memoryview(chunk)
                            while remaining:
                                written = destination.write(remaining)
                                if not written:
                                    raise OSError('backup write made no progress')
                                remaining = remaining[written:]
                result.append(dict(path=name, bytes=total, sha256=digest.hexdigest()))
            finally:
                if destination:
                    destination.close()
        print(json.dumps(result), flush=True)


class Worker:
    def __init__(self):
        self.process = subprocess.Popen([sys.executable, '-B', __file__, '--worker'],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True)
        try:
            assert self.read() == 'ready'
        except BaseException:
            self.close()
            raise

    def read(self):
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            assert selector.select(10), 'workload deadline'
        line = self.process.stdout.readline()
        assert line, self.process.poll()
        return line.strip()

    def request(self, command):
        self.process.stdin.write(json.dumps(command) + '\n')
        self.process.stdin.flush()
        return json.loads(self.read())

    def close(self):
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


def experiment(build, event):
    with tempfile.TemporaryDirectory(prefix='secmon-workloads-') as temporary, ExitStack() as stack:
        root = Path(temporary)
        target, hard, symbolic = (root / name for name in ('decoy', 'hard', 'symbolic'))
        data = bytes(range(251)) * 40  # 10040 bytes: three data reads and one EOF read.
        target.write_bytes(data)
        os.link(target, hard)
        symbolic.symlink_to(target)
        identity = target.stat()
        renamed = Path(str(target) + '.alias')
        program = root / 'editor'
        shutil.copy2(build / 'secmon-writer-scenario', program)
        editor = stack.enter_context(WriterProcess(program, target))
        outsider = stack.enter_context(WriterProcess(build / 'secmon-writer-scenario', target))
        actors = {}
        for role in ('index', 'backup'):
            actors[role] = Worker()
            stack.callback(actors[role].close)
        fields = (f'protect "{target}"\nfanotify-event {event}\nfanotify-decision allow\n'
                  f'allow-writer "{program}" 0 "{target}" rename')
        service = AuditedService(build, root, target, fields, combined=True)
        stack.callback(service.close)
        scenarios = []
        for phase in ('before', 'after'):
            if phase == 'after':
                assert editor.request('n') == 0
                assert renamed.stat().st_ino == identity.st_ino
                target.write_bytes(b'replacement outside original inode policy\n')
                assert target.stat().st_ino != identity.st_ino
            paths = [target, hard, symbolic] + ([renamed] if phase == 'after' else [])
            for role, actor in actors.items():
                destination = root / f'{phase}-{role}'
                destination.mkdir()
                begin = time.monotonic_ns()
                result = actor.request(dict(operation=role, paths=[str(path) for path in paths],
                                            destination=str(destination)))
                end = time.monotonic_ns()
                for item, path in zip(result, paths):
                    # Use fixture expectations; reading marked files here would add parent events.
                    expected = data if path == hard or phase == 'before' or path == renamed else b'replacement outside original inode policy\n'
                    assert item['bytes'] == len(expected)
                    assert item['sha256'] == hashlib.sha256(expected).hexdigest()
                    if role == 'backup':
                        assert (destination / path.name).read_bytes() == expected
                assert len(result) == len(paths)
                scenarios.append(dict(phase=phase, role=role, pid=actor.process.pid,
                                      begin_ns=begin, end_ns=end, files=result,
                                      expected_permissions=(3 if phase == 'before' else 2) * (1 if event == 'open' else 4)))
            assert outsider.request('w') == errno.EACCES
        service.stop()
        assert hard.read_bytes() == data and renamed.read_bytes() == data
        assert target.read_bytes() == b'replacement outside original inode policy\n'
        records = [json.loads(line) for line in contents(service.output).splitlines()]
        permissions = [row for row in records if row['event'] == 'fanotify_decision']
        assert len(permissions) == sum(row['expected_permissions'] for row in scenarios)
        assert sorted(row['request_id'] for row in permissions) == list(range(1, len(permissions) + 1))
        for scenario in scenarios:
            evidence = [row for row in permissions if row['requester_pid'] == scenario['pid'] and
                        scenario['begin_ns'] <= row['received_ns'] <= scenario['end_ns']]
            assert len(evidence) == scenario['expected_permissions'], (scenario, evidence)
            scenario['evidence'] = evidence
        for row in permissions:
            assert (row['major'], row['minor'], row['inode']) == (os.major(identity.st_dev), os.minor(identity.st_dev), identity.st_ino)
            assert row['decision'] == 'allow' and row['reason'] == 'policy' and row['revision'] == 1
            assert row['listener_pid'] == service.process.pid and row['instance_ns'] == service.initial['instance_ns']
            assert row['permission_event'] == event
        denials = [row for row in records if row['event'] == 'file_denied']
        assert len(denials) == 2
        assert denials[0]['start_ns'] == denials[1]['start_ns'] > 0
        for row in denials:
            assert row['pid'] == outsider.process.pid and row['operation'] == 2 and row['errno'] == errno.EACCES
            assert (row['dev_major'], row['dev_minor'], row['ino']) == (os.major(identity.st_dev), os.minor(identity.st_dev), identity.st_ino)
        diagnostics = contents(service.errors)
        for field in ('audit_dropped', 'audit_invalid', 'audit_queued', 'audit_errno', 'ringbuf_dropped', 'baseline_update_failed'):
            values = re.findall(r'\b' + field + r'=(\d+)', diagnostics)
            assert values and int(values[-1]) == 0, (field, values)
        assert all(actor.process.poll() is None for actor in (*actors.values(), editor, outsider))
        return dict(event=event, scenarios=scenarios, denials=denials, diagnostics=diagnostics,
                    classification='none; controlled workload labels only')


def main():
    if '--worker' in sys.argv:
        worker()
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', default='build')
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0 or sys.flags.optimize:
        parser.error('run as root without Python optimization')
    # Same host initial PID namespace prerequisite as decoy_evidence.py.
    assert os.readlink('/proc/self/ns/pid') == os.readlink('/proc/1/ns/pid')
    assert Path('/proc/1/status').read_text().split('NSpid:')[1].splitlines()[0].split() == ['1']
    reports = []
    for event in ('open', 'access'):
        reports.append(experiment(Path(args.build_dir).resolve(), event))
        print(json.dumps(dict(experiment='decoy-workloads', event=event, scenarios=4,
                              permission_records=sum(row['expected_permissions'] for row in reports[-1]['scenarios']), passed=True)), flush=True)
    if args.report:
        args.report.write_text(json.dumps(reports, indent=2) + '\n')


if __name__ == '__main__':
    main()
