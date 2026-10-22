#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Semantic checks for bounded, non-classifying offline evidence grouping."""
import io
import json
from pathlib import Path
import sys
import subprocess
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from evidence import Grouper, consume

BOOT='00000000-0000-0000-0000-000000000001'

def permission(cookie=77, inode=99, decision='allow', **changes):
    row=dict(event='fanotify_decision', requester_reference='present', requester_process_inode=cookie,
             requester_identity_errno=0, requester_pid_kind='tgid', requester_pid=100,
             listener_pid=200, request_id=1, instance_ns=300, pid_namespace_inode=400,
             received_ns=500, responded_ns=600, major=8, minor=1, inode=inode,
             permission_event='open', decision=decision, revision=1, reason='policy')
    row.update(changes)
    return row


def denial(cookie=77, inode=99, **changes):
    row=dict(event='file_denied', process_inode=cookie, pid=100, tid=101, start_ns=10,
             timestamp_ns=700, dev_major=8, dev_minor=1, ino=inode, errno=13, operation=2)
    row.update(changes)
    return row


def run(rows, **options):
    data=b''.join((json.dumps(row)+'\n').encode() if isinstance(row,dict) else row for row in rows)
    result=list(consume(io.BytesIO(data),Grouper('test-host',BOOT,'test-capture',**options)))
    summary=result[-1]
    assert summary['records']==summary['grouped']+summary['unattributed']+summary['invalid']+summary['ignored']
    assert all(row['classification']=='undetermined' for row in result)
    return result[:-1],summary


def main():
    groups,summary=run([permission(),denial(pid=999,tid=1000)])
    assert len(groups)==1 and groups[0]['allow_and_mutation_denial_observed']
    assert groups[0]['permission_allow']==groups[0]['mutation_denied']==1
    assert groups[0]['denial_operations']=={'write':1}
    assert summary['grouped']==2 and summary['deduplication']=='none'
    for operation, name in ((16, 'setxattr'), (17, 'removexattr'), (18, 'setacl'),
                            (19, 'removeacl'), (20, 'ioctl-write')):
        groups, summary = run([denial(operation=operation)])
        assert groups[0]['denial_operations'] == {name: 1} and not summary['invalid']
    groups, summary = run([denial(operation=21), denial(operation=11)])
    assert not groups and summary['ignored'] == 2 and not summary['invalid']
    # Identical numeric PIDs cannot merge different process lifetimes or different file objects.
    groups,_=run([permission(),denial(cookie=78),denial(inode=100)])
    assert len(groups)==3 and not any(row['allow_and_mutation_denial_observed'] for row in groups)
    groups,_=run([permission(),permission(decision='deny'),permission(cookie=78)])
    assert all(row['mutation_denied']==0 for row in groups)
    # No source-lifetime claims for zero, missing, unavailable or failed identity.
    legacy=permission();del legacy['requester_reference'];del legacy['requester_process_inode']
    groups,summary=run([legacy,denial(cookie=0),permission(cookie=0,requester_reference='unavailable'),
                        permission(cookie=0,requester_identity_errno=95)])
    assert not groups and summary['unattributed']==4
    # Eviction emits independent segments: do not invent an unbounded process history.
    groups,summary=run([permission(),denial(cookie=78),denial()],max_groups=1,samples=1)
    assert len(groups)==3 and summary['capacity_evictions']==2
    assert [row['segment_end'] for row in groups]==['capacity','capacity','eof']
    assert not any(row['allow_and_mutation_denial_observed'] for row in groups)
    assert all(not row['observations_complete_for_process'] for row in groups)
    groups,summary=run([denial() for _ in range(20)],samples=2)
    assert groups[0]['mutation_denied']==20 and len(groups[0]['evidence_samples'])==2
    assert [row['line'] for row in groups[0]['evidence_samples']]==[19,20]
    assert summary['segments']==1
    # Invalid records are bounded and accounted for; their contents never create facts.
    invalid=[permission(cookie=True),denial(cookie=-1),permission(requester_pid_kind='tid'),
             permission(cookie=0),permission(requester_identity_errno=5),
             denial(operation=99),denial(errno=1),permission(responded_ns=499),
             b'{"event":"file_denied","event":"fanotify_decision"}\n',b'NaN\n',b'[]\n',b'\xff\n',
             b'{"event":"file_denied","extra":NaN}\n',b'x'*10000+b'\n']
    invalid.extend([b'{"event":"exec_success","extra":1e999}\n',
                    permission(revision=0), permission(reason='unknown')])
    groups,summary=run([*invalid,denial(),dict(event='exec_success')])
    assert len(groups)==1 and summary['invalid']==len(invalid) and summary['ignored']==1
    assert summary['records']==len(invalid)+2
    groups,summary=run([permission(),permission(instance_ns=301),denial()])
    assert summary['mixed_listener_instances'] and summary['invalid']==2
    assert groups[0]['mutation_denied']==0
    # Repeated input is explicitly observation counting, not a globally deduplicated audit ledger.
    groups,summary=run([permission(),permission()])
    assert groups[0]['permission_allow']==2 and summary['deduplication']=='none'
    for args in [('',BOOT),('host','bad'),('host','00000000-0000-0000-0000-000000000000')]:
        try:Grouper(args[0],args[1],'test-capture')
        except ValueError:pass
        else:raise AssertionError('missing source context accepted')
    for options in ({'max_groups':0},{'max_groups':4097},{'samples':0},{'samples':33},
                    {'max_groups':1.5},{'max_groups':True},{'samples':1.5},{'samples':True},
                    {'rule_history':1.5},{'rule_history':True},{'rule_window_ms':1.5},{'rule_window_ms':True}):
        try:Grouper('host',BOOT,'capture',**options)
        except ValueError:pass
        else:raise AssertionError('unbounded state accepted')
    tool = Path(__file__).resolve().parents[1] / 'tools' / 'evidence.py'
    command=[sys.executable,'-B',str(tool),'--machine-id','test-host','--boot-id',BOOT,'--capture-id','test-capture']
    result=subprocess.run(command,input=json.dumps(denial())+'\n',capture_output=True,text=True,check=True)
    assert json.loads(result.stdout.splitlines()[-1])['grouped']==1
    result=subprocess.run(command,input='bad JSON\n',capture_output=True,text=True)
    assert result.returncode==1 and json.loads(result.stdout.splitlines()[-1])['invalid']==1
    result=subprocess.run([sys.executable,'-B',str(tool)],input='',capture_output=True,text=True)
    assert result.returncode==2
    print('PASS stable process/object grouping, missing identity, eviction, sampling and malformed input accounting')


if __name__=='__main__':main()
