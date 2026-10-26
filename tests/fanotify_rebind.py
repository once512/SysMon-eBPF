#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit same-path object re-pinning, monotonic epochs and rollback."""
import argparse
from contextlib import ExitStack
import errno
import json
import os
from pathlib import Path
import tempfile
from permission_audit import AuditedService, request, contents, begin_request, finish_request
from fanotify_handover import LiveService
from management_harness import call
from writer_harness import WriterProcess


def experiment(build, combined, pidfd):
    with tempfile.TemporaryDirectory(prefix='secmon-rebind-') as tmp, ExitStack() as stack:
        root=Path(tmp); target=root/'target'; target.write_bytes(b'old')
        alias=root/'old-alias'; os.link(target,alias); old_inode=target.stat().st_ino
        guard=root/'guard'; guard.write_bytes(b'guard')
        old_writer=stack.enter_context(WriterProcess(build/'secmon-writer-scenario',alias))
        guard_writer=stack.enter_context(WriterProcess(build/'secmon-writer-scenario',guard))
        event='access' if pidfd else 'open'
        def fields(decision='allow',epoch=0,bad=False):
            text=f'fanotify-file "{target}"\nfanotify-event {event}\nfanotify-decision {decision}\n'
            if epoch: text+=f'fanotify-rebind-epoch {epoch}\n'
            if combined:
                text+=f'protect "{guard}"\n'
                if bad: text+=f'vault "{target}"\n'
                elif epoch: text+=f'protect "{target}"\n'
            return text
        service=LiveService(build,root,target,fields(),combined=combined,requester_pidfd=pidfd)
        stack.callback(service.close)
        initial=service.status(); baseline=len(os.listdir(f'/proc/{service.process.pid}/fd'))
        expected=[]; revision=1
        def probe(path,denied=False,marked=True,generation=1):
            result=request(path,event)
            assert result['errno']==(errno.EPERM if denied else 0),(path,result)
            if marked: expected.append((result['pid'],path.stat().st_ino,revision,generation,'deny' if denied else 'allow'))
        def publish(next_revision,decision='allow',epoch=0,code='ok',bad=False):
            nonlocal revision
            service.publish(next_revision,fields(decision,epoch,bad))
            state=call(build/'secmon','reload',service.control,code)
            if code=='ok': revision=next_revision
            assert state['revision']==revision and state['instance_ns']==initial['instance_ns'],state
            if combined: assert guard_writer.request('w')==errno.EACCES
            return state
        probe(target)
        replacement=root/'replacement'; replacement.write_bytes(b'new'); replacement.replace(target)
        new_inode=target.stat().st_ino; assert new_inode!=old_inode
        new_writer=stack.enter_context(WriterProcess(build/'secmon-writer-scenario',target))
        publish(2,'deny')
        probe(alias,True); probe(target,marked=False)
        publish(3,'deny',1,'restart_required')
        probe(alias,True)
        publish(3)
        saved=root/'saved'; target.rename(saved); target.symlink_to(saved)
        publish(4,'allow',1,'prepare_failed')
        probe(alias)
        target.unlink(); saved.rename(target)
        publish(4,'allow',1)
        probe(target,generation=2); probe(alias,marked=False)
        if combined:
            assert new_writer.request('w')==errno.EACCES and old_writer.request('w')==0
        publish(5,'deny',1) # Same epoch must not create another group.
        probe(target,True,generation=2); probe(alias,marked=False)
        publish(6,'allow',0,'invalid_policy') # Omitting a published epoch cannot reset it.
        publish(6,'allow',1)
        if combined:
            publish(7,'deny',2,'prepare_failed',bad=True) # Candidate group exists; BPF rejects vault/listener read conflict.
            probe(target,generation=2)
        publish(7,'deny',2)
        probe(target,True,generation=3); probe(alias,marked=False)
        state=publish(8,'allow',2)
        assert state['allowed']+state['denied']==len(expected),state
        assert len(os.listdir(f'/proc/{service.process.pid}/fd'))==baseline+int(combined)
        service.stop()
        records=[json.loads(line) for line in contents(service.output).splitlines()]
        decisions=[e for e in records if e['event']=='fanotify_decision']
        actual=[(e['requester_pid'],e['inode'],e['revision'],e['subscription_generation'],e['decision']) for e in decisions]
        assert actual==expected,(actual,expected)
        assert [e['request_id'] for e in decisions]==list(range(1,len(expected)+1))
        handovers=[e for e in records if e['event']=='fanotify_target_handover']
        assert len(handovers)==2 and all(e['retained_targets']==0 for e in handovers),handovers
        assert [(e['from_rebind_epoch'],e['to_rebind_epoch']) for e in handovers]==[(0,1),(1,2)]
        assert [(e['from_generation'],e['to_generation']) for e in handovers]==[(1,2),(2,3)]
        print(json.dumps({'combined':combined,'pidfd':pidfd,'same_path_new_inode':True,'stable_epoch_retains_group':True,
                          'rollback':True,'decisions':len(decisions),'handovers':2,'fd_baseline':baseline}))


def restricted(build):
    with tempfile.TemporaryDirectory(prefix='secmon-rebind-restricted-') as tmp:
        root=Path(tmp); target=root/'target'; target.write_bytes(b'clean')
        for analysis in (False,True):
            fields=(f'fanotify-analyzer "{build/"secmon-analyzer"}"\nfanotify-marker "BLOCK"\n' if analysis else
                    'fanotify-decision allow\nfanotify-delay-ms 300\nfanotify-timeout-ms 1000\n')
            service=AuditedService(build,root,target,fields)
            try:
                pending=begin_request(target)
                if not analysis:
                    service.wait_pending(1)
                    service.publish(2,fields+'fanotify-rebind-epoch 1\n')
                    assert call(build/'secmon','reload',service.control,'busy')['revision']==1
                assert finish_request(pending)['errno']==0
                service.publish(2,fields+'fanotify-rebind-epoch 1\n')
                assert call(build/'secmon','reload',service.control,'restart_required')['revision']==1
                assert service.status()['pending']==0
                service.stop()
            finally: service.close()
    print('PASS busy, delayed and idle-analysis rebind rejection preserves active revision')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir',type=Path,default=Path('build'))
    args=parser.parse_args()
    if os.geteuid()!=0 or not __debug__:parser.error('run as root without Python optimization')
    build=args.build_dir.resolve()
    for combined in (False,True):
        for pidfd in (False,True):experiment(build,combined,pidfd)
    restricted(build)
    print('PASS explicit fanotify object rebinding and transactional restrictions')
if __name__=='__main__':main()
