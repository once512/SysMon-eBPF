#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Controlled live actors: correlate temporary decoy evidence, without threat labels."""
import argparse
from contextlib import ExitStack
import errno
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import time
from management_harness import call
from permission_audit import AuditedService, contents
from writer_harness import WriterProcess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', default='build')
    parser.add_argument('--report', type=Path)
    parser.add_argument('--event', choices=('open', 'access'), default='open')
    args = parser.parse_args()
    assert os.geteuid() == 0
    if sys.flags.optimize:
        parser.error('run without Python optimization; assertions must remain enabled')
    # Raw fanotify PIDs and BPF global IDs are only joined in the initial PID namespace.
    assert os.readlink('/proc/self/ns/pid') == os.readlink('/proc/1/ns/pid')
    assert Path('/proc/1/status').read_text().split('NSpid:')[1].splitlines()[0].split() == ['1']
    build = Path(args.build_dir).resolve()
    rows = []
    with tempfile.TemporaryDirectory(prefix='secmon-decoy-') as temporary, ExitStack() as stack:
        root = Path(temporary)
        target = root / 'decoy'
        target.write_bytes(b'synthetic decoy contents\n')
        identity = target.stat()
        actors = {}
        for role in ('indexer', 'backup', 'editor', 'outsider'):
            program = root / role
            shutil.copy2(build / 'secmon-writer-scenario', program)
            actors[role] = stack.enter_context(WriterProcess(program, target))
        fields = (f'protect "{target}"\nfanotify-decision allow\nfanotify-event {args.event}\n'
                  f'allow-writer "{root / "editor"}" 0 "{target}" open-write,write')
        service = AuditedService(build, root, target, fields, combined=True)
        stack.callback(service.close)
        # All actors were started before attachment and stay alive through the final drain.
        cases = [('indexer', 'r', 0), ('backup', 'r', 0), ('editor', 'o', 0),
                 ('editor', 'w', 0), ('outsider', 'o', errno.EACCES),
                 ('outsider', 'w', errno.EACCES), ('outsider', 't', errno.EACCES),
                 ('outsider', 'u', errno.EACCES), ('outsider', 'n', errno.EACCES),
                 ('outsider', 'l', errno.EACCES)]
        for role, command, expected in cases:
            begin = time.monotonic_ns()
            result = actors[role].request(command)
            end = time.monotonic_ns()
            assert result == expected, (role, command, result)
            rows.append(dict(role=role, command=command, pid=actors[role].process.pid,
                             begin_ns=begin, end_ns=end, errno=result))
        service.publish(2, f'protect "{target}"\nfanotify-decision allow\nfanotify-event {args.event}')
        call(service.binary, 'reload', service.control)
        begin = time.monotonic_ns()
        assert actors['editor'].request('w') == errno.EACCES
        rows.append(dict(role='editor', command='revoked-held-write', pid=actors['editor'].process.pid,
                         begin_ns=begin, end_ns=time.monotonic_ns(), errno=errno.EACCES))
        assert service.status()['revision'] == 2
        service.stop()
        assert all(actor.process.poll() is None for actor in actors.values())
        events = [json.loads(line) for line in contents(service.output).splitlines()]
        file_identity = (os.major(identity.st_dev), os.minor(identity.st_dev), identity.st_ino)
        for row in rows:
            selected = []
            for event in events:
                if event['event'] == 'fanotify_decision':
                    pid, timestamp = event['requester_pid'], event['received_ns']
                    key = (event['major'], event['minor'], event['inode'])
                elif event['event'] == 'file_denied':
                    pid, timestamp = event['pid'], event['timestamp_ns']
                    key = (event['dev_major'], event['dev_minor'], event['ino'])
                else:
                    continue
                if pid == row['pid'] and row['begin_ns'] <= timestamp <= row['end_ns']:
                    assert key == file_identity
                    selected.append(event)
            row['evidence'] = selected
        expected_kinds = [['fanotify_decision'], ['fanotify_decision'], ['fanotify_decision'], [],
                          ['file_denied'], ['file_denied'], ['file_denied'], ['file_denied'],
                          ['file_denied'], ['file_denied'], ['file_denied']]
        if args.event == 'access':
            expected_kinds[2] = []
        for row, kinds in zip(rows, expected_kinds):
            assert [event['event'] for event in row['evidence']] == kinds, row
        relevant = [event for event in events if event['event'] in ('fanotify_decision', 'file_denied')]
        assert sum(len(row['evidence']) for row in rows) == len(relevant)
        for field in ('ringbuf_dropped', 'baseline_update_failed'):
            assert re.search(r'^' + field + r'=0$', contents(service.errors), re.MULTILINE)
        for row, operation in zip(rows[4:], (1, 2, 3, 4, 5, 6, 2)):
            assert row['evidence'][0]['operation'] == operation, row
        for row in rows[:(3 if args.event == 'open' else 2)]:
            event = row['evidence'][0]
            assert event['decision'] == 'allow' and event['reason'] == 'policy'
            assert event['revision'] == 1 and event['instance_ns'] == service.initial['instance_ns']
            assert event['listener_pid'] == service.process.pid
            assert event['permission_event'] == args.event
        assert target.exists() and not Path(str(target) + '.alias').exists()
        for field in ('audit_dropped', 'audit_invalid', 'audit_queued', 'audit_errno'):
            values = re.findall(r'\b' + field + r'=(\d+)', contents(service.errors))
            assert values and int(values[-1]) == 0, (field, values)
        report = dict(permission_event=args.event, scope='controlled actors in initial PID namespace; roles are test declarations',
                      classification='none', identity=file_identity, scenarios=rows,
                      diagnostics=contents(service.errors))
        if args.report:
            args.report.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(dict(experiment='decoy-evidence', scenarios=len(rows),
                              permission_records=3 if args.event == 'open' else 2, denial_records=7, passed=True)))


if __name__ == '__main__':
    main()
