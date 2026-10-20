#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real application counterexamples and bounded destructive-operation simulations.

All targets are disposable files. Scenario labels describe test intent, not a
classifier decision. Native protection must reject every attempted modification.
"""
import argparse
from contextlib import ExitStack, closing
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import sqlite3
import subprocess
import sys
import tempfile
import time

from behavior_workloads import evaluate, external, reference
from permission_audit import AuditedService, contents

SCENARIOS = (
    'benign-inplace-save', 'benign-sed-save', 'benign-sqlite-update',
    'benign-log-rotation', 'controlled-read-overwrite', 'controlled-truncate',
    'controlled-split-process', 'controlled-delayed-write',
)

# Existing write descriptors are opened before protection activates, matching the
# existing-FD threat model. Reads subsequently open the marked object normally.
MUTATE = '''import errno,json,os,sys,time
path,mode=sys.argv[1:]
fd=os.open(path,os.O_RDWR) if mode != 'truncate' else None
print('ready',flush=True)
assert sys.stdin.readline().strip() == 'go'
if mode == 'truncate':
    operation=lambda: os.truncate(path,0)
else:
    data=b''
    if mode != 'write-only':
        with open(path,'rb') as source: data=source.read()
    if mode == 'delayed': time.sleep(1.2)
    payload=bytes(value ^ 0x5a for value in data) if mode == 'xor' else b'new saved data'
    operation=lambda: os.pwrite(fd,payload,0)
try:
    operation()
except OSError as error:
    assert error.errno == errno.EACCES, error
    print(json.dumps(dict(errno=error.errno,mode=mode)))
else:
    raise AssertionError('protected mutation unexpectedly succeeded')
'''

SQLITE = '''import json,sqlite3,sys
connection=sqlite3.connect(sys.argv[1])
assert connection.execute('select value from sample').fetchall() == [('original',)]
try:
    connection.execute("update sample set value='updated'")
    connection.commit()
except sqlite3.DatabaseError as error:
    assert error.sqlite_errorcode & 255 == sqlite3.SQLITE_READONLY, (error,error.sqlite_errorcode)
    print(json.dumps(dict(sqlite_errorcode=error.sqlite_errorcode,sqlite_errorname=error.sqlite_errorname)))
else:
    raise AssertionError('protected database update unexpectedly succeeded')
finally:
    connection.close()
'''


def experiment(build, event, pidfd, scenario, artifact):
    with tempfile.TemporaryDirectory(prefix='secmon-applications-') as temporary, ExitStack() as stack:
        root = Path(temporary)
        target = root / 'target'
        if scenario == 'benign-sqlite-update':
            with closing(sqlite3.connect(target)) as database:
                with database:
                    database.execute('create table sample(value text)')
                    database.execute("insert into sample values('original')")
        else:
            target.write_bytes(b'original disposable test data\n' * 32)
        before = target.read_bytes()
        identity = target.stat()
        prepared = None
        if scenario not in ('benign-sed-save', 'benign-sqlite-update', 'benign-log-rotation'):
            mode = {'benign-inplace-save': 'save', 'controlled-read-overwrite': 'xor',
                    'controlled-truncate': 'truncate', 'controlled-split-process': 'write-only',
                    'controlled-delayed-write': 'delayed'}[scenario]
            argv = [sys.executable, '-B', '-c', MUTATE, str(target), mode]
            prepared = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            def cleanup():
                if prepared.poll() is None:
                    prepared.kill()
                    prepared.communicate(timeout=5)
                for stream in (prepared.stdin, prepared.stdout, prepared.stderr):
                    stream.close()

            stack.callback(cleanup)
            with selectors.DefaultSelector() as selector:
                selector.register(prepared.stdout, selectors.EVENT_READ)
                assert selector.select(5), 'prepared actor ready deadline'
            assert prepared.stdout.readline() == b'ready\n'
            prepared_cookie = reference(stack, prepared.pid)
        fields = f'protect "{target}"\nfanotify-event {event}\nfanotify-decision allow\n'
        service = AuditedService(build, root, target, fields, combined=True, requester_pidfd=pidfd)
        stack.callback(service.close)
        tools = []

        def run(role, argv, code=0, expected=None):
            cookie, output = external(stack, argv, code)
            if expected is not None:
                assert output == expected, (role, output)
            tools.append(dict(role=role, process_inode=cookie, argv=list(map(str, argv)),
                              exit_code=code, output=output.decode(),
                              output_sha256=hashlib.sha256(output).hexdigest()))

        if scenario == 'benign-sed-save':
            run(scenario, ['/usr/bin/sed', '-i', '1s/^/saved:/', target], 4, b'')
        elif scenario == 'benign-log-rotation':
            run(scenario, ['/usr/bin/mv', '--', target, root / 'rotated'], 1, b'')
            assert not (root / 'rotated').exists()
        elif scenario == 'benign-sqlite-update':
            run(scenario, [sys.executable, '-B', '-c', SQLITE, target])
        else:
            if scenario == 'controlled-split-process':
                run('controlled-separate-reader', ['/usr/bin/cat', target], expected=before)
            output, error = prepared.communicate(b'go\n', timeout=10)
            assert prepared.returncode == 0, (scenario, error)
            tools.append(dict(role=scenario, process_inode=prepared_cookie, argv=argv,
                              exit_code=0, output=output.decode(),
                              output_sha256=hashlib.sha256(output).hexdigest()))
        service.stop()
        assert target.read_bytes() == before and target.stat().st_ino == identity.st_ino
        if scenario == 'benign-sqlite-update':
            with closing(sqlite3.connect(target)) as database:
                assert database.execute('pragma integrity_check').fetchone() == ('ok',)
                assert database.execute('select value from sample').fetchall() == [('original',)]
        raw = contents(service.output).encode()
        diagnostics = contents(service.errors)
        for field in ('audit_dropped', 'audit_invalid', 'audit_queued', 'audit_errno',
                      'ringbuf_dropped', 'baseline_update_failed'):
            values = re.findall(r'\b' + field + r'=(\d+)', diagnostics)
            assert values and int(values[-1]) == 0, (field, values)
        machine = Path('/etc/machine-id').read_text().strip()
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        capture = f'applications-{scenario}-{event}-{int(pidfd)}-{service.initial["instance_ns"]}'
        result, evidence = evaluate(raw, machine, boot, capture, rule_history=128)
        summary = result[-1]
        records = [json.loads(line) for line in raw.splitlines()]
        permissions = [r for r in records if r['event'] == 'fanotify_decision']
        denials = [r for r in records if r['event'] == 'file_denied']
        actor = tools[-1]['process_inode']
        assert denials and all(r['process_inode'] == actor and r['errno'] == 13 and
                              r['ino'] == identity.st_ino and
                              (r['dev_major'], r['dev_minor']) ==
                              (os.major(identity.st_dev), os.minor(identity.st_dev)) for r in denials), denials
        assert all(r['decision'] == 'allow' and r['permission_event'] == event for r in permissions)
        assert sorted(r['request_id'] for r in permissions) == list(range(1, len(permissions) + 1))
        for row in permissions:
            assert row['instance_ns'] == service.initial['instance_ns']
            assert (row['major'], row['minor'], row['inode']) == (
                os.major(identity.st_dev), os.minor(identity.st_dev), identity.st_ino)
            if pidfd:
                assert row['requester_reference'] == 'present'
                assert row['requester_process_inode'] in {t['process_inode'] for t in tools}
        assert summary['rule_history_evictions'] == 0
        assert summary['grouped'] + summary['unattributed'] == len(permissions) + len(denials)
        assert summary['unattributed'] == (0 if pidfd else len(permissions))
        # Independent complete-input oracle; scenario expectation additionally
        # checks which semantic boundaries should prevent a pattern observation.
        oracle = sum(any(p.get('requester_process_inode') == d['process_inode'] and
                         0 < d['timestamp_ns'] - p['responded_ns'] <= 1_000_000_000
                         for p in permissions) for d in denials) if pidfd else 0
        assert summary['rule_matches'] == oracle
        expected_positive = pidfd and scenario in (
            'benign-inplace-save', 'benign-sed-save', 'controlled-read-overwrite')
        assert (oracle > 0) == expected_positive, (scenario, event, pidfd, oracle, permissions, denials)
        report = dict(source=summary['source'], capture=capture, scenario=scenario,
                      event=event, requester_pidfd=pidfd, tools=tools, summary=summary,
                      permissions=len(permissions), denials=len(denials),
                      oracle_matches=oracle, target_unchanged=True,
                      declared_intent='benign' if scenario.startswith('benign-') else 'controlled-destructive-simulation',
                      interpretation='scenario intent is operator-declared; observations are not attack classification',
                      diagnostics=diagnostics, sqlite_version=sqlite3.sqlite_version,
                      environment=dict(kernel=platform.release(), python=sys.version,
                                       architecture=platform.machine()),
                      audit_sha256=hashlib.sha256(raw).hexdigest(),
                      evidence_sha256=hashlib.sha256(evidence).hexdigest())
        report['implementation_sha256'] = {
            str(path): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (Path(__file__).resolve(), build / 'secmon', Path('/usr/bin/sed'), Path('/usr/bin/mv'),
                         Path(sys.executable), Path(__file__).with_name('behavior_workloads.py'),
                         Path(__file__).with_name('permission_audit.py'),
                         Path(__file__).resolve().parents[1] / 'tools' / 'evidence.py',
                         Path(__file__).resolve().parents[1] / 'tools' / 'behavior.py')}
        if artifact:
            artifact.mkdir(parents=True, exist_ok=False)
            (artifact / 'audit.jsonl').write_bytes(raw)
            (artifact / 'evidence.jsonl').write_bytes(evidence)
            (artifact / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, default=Path('build'))
    parser.add_argument('--artifact-dir', type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0 or sys.flags.optimize or os.environ.get('PYTHONOPTIMIZE'):
        parser.error('run as root without Python optimization')
    assert os.readlink('/proc/self/ns/pid') == os.readlink('/proc/1/ns/pid')
    start = time.monotonic()
    base_fds = len(os.listdir('/proc/self/fd'))
    variants = 0
    reports = []
    for pidfd in (False, True):
        for event in ('open', 'access'):
            for scenario in SCENARIOS:
                name = f'{scenario}-{event}-pidfd-{int(pidfd)}'
                artifact = args.artifact_dir / name if args.artifact_dir else None
                report = experiment(args.build_dir.resolve(), event, pidfd, scenario, artifact)
                assert len(os.listdir('/proc/self/fd')) == base_fds, 'controller FD leak'
                assert not Path('/proc/self/task', str(os.getpid()), 'children').read_text().strip(), 'unreaped child'
                variants += 1
                row = dict(scenario=scenario, event=event, requester_pidfd=pidfd,
                           declared_intent=report['declared_intent'],
                           permissions=report['permissions'], denials=report['denials'],
                           matches=report['oracle_matches'], target_unchanged=report['target_unchanged'])
                reports.append(row)
                print(json.dumps(dict(**row, passed=True)), flush=True)
    summary = dict(passed=True, variants=variants, seconds=round(time.monotonic()-start, 3),
                   controller_base_fds=base_fds, controller_final_fds=len(os.listdir('/proc/self/fd')),
                   interpretation='controlled scenario coverage, not production attack detection accuracy',
                   classification='undetermined', response='none', results=reports)
    if args.artifact_dir:
        (args.artifact_dir / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({k: v for k, v in summary.items() if k != 'results'}), flush=True)


if __name__ == '__main__':
    main()
