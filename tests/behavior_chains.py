#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Multiple protected objects, one audited object: explicit chain coverage limits."""
import argparse
from collections import Counter
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import tempfile
import time

from behavior_workloads import evaluate, reference
from permission_audit import AuditedService, contents

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from chain_capture import chain_capture

ROLES = {'benign-index': 'read', 'benign-batch-save': 'save',
         'controlled-batch-overwrite': 'xor', 'controlled-batch-truncate': 'truncate',
         'controlled-repeat-one': 'repeat', 'controlled-separate-reader': 'read',
         'controlled-separate-writer': 'write-only'}

ACTOR = '''import errno,hashlib,json,os,sys
mode=sys.argv[1]
paths=sys.argv[2:]
fds=[os.open(path,os.O_RDWR) for path in paths] if mode in ('save','xor','repeat','write-only') else []
print('ready',flush=True)
assert sys.stdin.readline().strip() == 'go'
rows=[]
for index in range(len(paths)):
    slot=0 if mode == 'repeat' else index
    path=paths[slot]
    data=b''
    if mode not in ('truncate','write-only'):
        with open(path,'rb') as source: data=source.read()
    row=dict(slot=slot,read_sha256=hashlib.sha256(data).hexdigest(),errno=0)
    if mode != 'read':
        try:
            if mode == 'truncate': os.truncate(path,0)
            else:
                payload=bytes(v ^ 0x5a for v in data) if mode == 'xor' else b'ordinary batch save'
                os.pwrite(fds[slot],payload,0)
        except OSError as error:
            assert error.errno == errno.EACCES,error
            row['errno']=error.errno
        else: raise AssertionError('protected modification succeeded')
    rows.append(row)
print(json.dumps(rows),flush=True)
'''


def experiment(build, event, pidfd, artifact, mark_all=False, object_count=8):
    with tempfile.TemporaryDirectory(prefix='secmon-chains-') as temporary, ExitStack() as stack:
        root = Path(temporary)
        targets = [root / f'object-{i}' for i in range(object_count)]
        originals = []
        for index, target in enumerate(targets):
            payload = (f'disposable object {index}\n'.encode()) * 64
            target.write_bytes(payload)
            originals.append(payload)
        identities = [t.stat() for t in targets]
        by_inode = {s.st_ino: i for i, s in enumerate(identities)}
        actors, tools = {}, []
        for role, mode in ROLES.items():
            argv = [sys.executable, '-B', '-c', ACTOR, mode, *map(str, targets)]
            process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            def cleanup(process=process):
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)
                for stream in (process.stdin, process.stdout, process.stderr):
                    stream.close()

            stack.callback(cleanup)
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                assert selector.select(5), role
            assert process.stdout.readline() == b'ready\n'
            cookie = reference(stack, process.pid)
            actors[role] = process
            tools.append(dict(role=role, process_inode=cookie, argv=argv))
        fields = ''.join(f'protect "{t}"\n' for t in targets)
        if mark_all:
            fields += ''.join(f'fanotify-file "{t}"\n' for t in targets[1:])
        fields += f'fanotify-event {event}\nfanotify-decision allow\n'
        service = AuditedService(build, root, targets[0], fields, combined=True, requester_pidfd=pidfd)
        stack.callback(service.close)
        for tool in tools:
            role = tool['role']
            output, error = actors[role].communicate(b'go\n', timeout=10)
            assert actors[role].returncode == 0, (role, error)
            rows = json.loads(output)
            assert len(rows) == len(targets)
            for i, row in enumerate(rows):
                slot = 0 if ROLES[role] == 'repeat' else i
                payload = b'' if ROLES[role] in ('truncate', 'write-only') else originals[slot]
                assert row == dict(slot=slot, read_sha256=hashlib.sha256(payload).hexdigest(),
                                   errno=0 if ROLES[role] == 'read' else 13)
            tool.update(exit_code=0, operation_results=rows)
        service.stop()
        for target, original, identity in zip(targets, originals, identities):
            assert target.read_bytes() == original and target.stat().st_ino == identity.st_ino
        raw = contents(service.output).encode()
        diagnostics = contents(service.errors)
        for field in ('audit_dropped', 'audit_invalid', 'audit_queued', 'audit_errno',
                      'ringbuf_dropped', 'baseline_update_failed'):
            values = re.findall(r'\b' + field + r'=(\d+)', diagnostics)
            assert values and int(values[-1]) == 0, (field, values)
        machine = Path('/etc/machine-id').read_text().strip()
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        capture = f'chains-{event}-{int(pidfd)}-{service.initial["instance_ns"]}'
        grouped, evidence = evaluate(raw, machine, boot, capture, rule_history=128)
        summary = grouped[-1]
        records = [json.loads(line) for line in raw.splitlines()]
        permissions = [r for r in records if r['event'] == 'fanotify_decision']
        denials = [r for r in records if r['event'] == 'file_denied']
        cookies = {t['role']: t['process_inode'] for t in tools}
        expected = Counter({cookies[role]: object_count for role, mode in ROLES.items() if mode != 'read'})
        assert Counter(r['process_inode'] for r in denials) == expected
        for row in denials:
            assert row['ino'] in by_inode and row['errno'] == 13
            identity = identities[by_inode[row['ino']]]
            assert (row['dev_major'], row['dev_minor']) == (os.major(identity.st_dev), os.minor(identity.st_dev))
            expected_operation = 3 if row['process_inode'] == cookies['controlled-batch-truncate'] else 2
            assert row['operation'] == expected_operation
        for row in permissions:
            assert row['inode'] in (by_inode if mark_all else {identities[0].st_ino}) and row['decision'] == 'allow'
            assert (row['major'], row['minor']) == (os.major(identities[0].st_dev), os.minor(identities[0].st_dev))
            assert row['instance_ns'] == service.initial['instance_ns'] and row['permission_event'] == event
            if pidfd:
                assert row['requester_reference'] == 'present' and row['requester_process_inode'] in cookies.values()
        assert sorted(r['request_id'] for r in permissions) == list(range(1, len(permissions)+1))
        assert service.initial['fanotify_targets'] == (object_count if mark_all else 1)
        assert summary['rule_matches'] == ((object_count * 3 if mark_all else object_count + 2) if pidfd else 0)
        assert summary['unattributed'] == (0 if pidfd else len(permissions))
        assert summary['rule_history_evictions'] == 0
        report = dict(source=summary['source'], capture=capture, summary=summary, tools=tools,
                      event=event, requester_pidfd=pidfd, protected_objects=object_count,
                      fanotify_marked_objects=object_count if mark_all else 1,
                      permissions=len(permissions), denials=len(denials), targets_unchanged=True,
                      diagnostics=diagnostics, interpretation='operator-declared scenarios, not attack ground truth',
                      audit_sha256=hashlib.sha256(raw).hexdigest(), evidence_sha256=hashlib.sha256(evidence).hexdigest())
        report['implementation_sha256'] = {
            str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in
            (Path(__file__).resolve(), build / 'secmon', Path(sys.executable),
             Path(__file__).resolve().parents[1] / 'tools' / 'chain_capture.py')}
        # Always exercise verified capture ingestion, including runs without an
        # external artifact directory; keep the manifest immutable thereafter.
        destination = artifact if artifact else root / 'capture'
        destination.mkdir(parents=True, exist_ok=False)
        (destination / 'audit.jsonl').write_bytes(raw)
        (destination / 'evidence.jsonl').write_bytes(evidence)
        (destination / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
        chains = chain_capture(destination)
        by_role = {r['role']: r for r in chains['processes']}
        for role, mode in ROLES.items():
            row = by_role.get(role)
            if mode == 'read' and not pidfd:
                assert row is None
                continue
            assert row['distinct_denied_objects'] == (0 if mode == 'read' else 1 if mode == 'repeat' else object_count)
            expected_accessed = (object_count if mark_all and mode != 'repeat' else 1) if mode not in ('truncate', 'write-only') else 0
            assert row['distinct_accessed_objects'] == expected_accessed * int(pidfd)
            assert row['paired_denials'] == (object_count if mode == 'repeat' or (mark_all and mode in ('save','xor')) else 1 if mode in ('save', 'xor') else 0) * int(pidfd)
            assert row['multi_object_access_then_denial_observed'] == (mark_all and pidfd and mode in ('save','xor'))
            assert row['multi_object_denials_observed'] == (mode not in ('read', 'repeat'))
        (destination / 'chains.json').write_text(json.dumps(chains, indent=2) + '\n')
        return dict(event=event, requester_pidfd=pidfd, permissions=len(permissions), denials=len(denials),
                    rule_matches=summary['rule_matches'], processes=len(chains['processes']), passed=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, default=Path('build'))
    parser.add_argument('--artifact-dir', type=Path)
    parser.add_argument('--mark-all', action='store_true')
    parser.add_argument('--objects', type=int, default=8)
    parser.add_argument('--duration', type=int, default=0)
    args = parser.parse_args()
    if os.geteuid() != 0 or sys.flags.optimize or os.environ.get('PYTHONOPTIMIZE'):
        parser.error('run as root without Python optimization')
    if not 3 <= args.objects <= 64 or not 0 <= args.duration <= 1200:
        parser.error('objects must be 3..64; duration must be 0..1200')
    assert os.readlink('/proc/self/ns/pid') == os.readlink('/proc/1/ns/pid')
    start = time.monotonic()
    base_fds = len(os.listdir('/proc/self/fd'))
    reports = []
    cycle = 0
    while True:
        cycle += 1
        for pidfd in (False, True):
            for event in ('open', 'access'):
                artifact = args.artifact_dir / f'cycle-{cycle}-{event}-pidfd-{int(pidfd)}' if args.artifact_dir else None
                reports.append(experiment(args.build_dir.resolve(), event, pidfd, artifact, args.mark_all, args.objects))
                assert len(os.listdir('/proc/self/fd')) == base_fds, 'controller FD leak'
                assert not Path('/proc/self/task', str(os.getpid()), 'children').read_text().strip(), 'unreaped child'
                print(json.dumps(reports[-1]), flush=True)
        if time.monotonic()-start >= args.duration:
            break
    report = dict(passed=True, variants=len(reports), cycles=cycle, results=reports, seconds=round(time.monotonic()-start, 3),
                  controller_base_fds=base_fds, controller_final_fds=len(os.listdir('/proc/self/fd')))
    if args.artifact_dir:
        (args.artifact_dir / 'summary.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report), flush=True)


if __name__ == '__main__':
    main()
