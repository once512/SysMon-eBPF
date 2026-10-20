#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Restricted allow-mode target handover, retained inodes and rollback."""
import argparse
import ctypes
from collections import Counter
from contextlib import ExitStack
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import sys
import tempfile
import time

from behavior_workloads import evaluate, reference
from management_harness import call
from permission_audit import AuditedService, contents
from writer_harness import WriterProcess
from permission_audit import begin_request, finish_request, request
from management_faults import Reply
from concurrent.futures import ThreadPoolExecutor


class LiveService(AuditedService):
    def publish(self, revision, fields):
        stage=self.root/'staging'
        stage.write_text(f'revision {revision}\n'+fields+'\n')
        stage.chmod(0o600)
        stage.replace(self.policy)


def experiment(build, event, pidfd, rounds, artifact):
    with tempfile.TemporaryDirectory(prefix='secmon-handover-') as temporary, ExitStack() as stack:
        root=Path(temporary)
        targets=[root/name for name in ('a','b','c')]
        for path in targets:
            path.write_bytes(path.name.encode()+b' original content\n')
        alias=root/'original-c-alias'
        os.link(targets[2],alias)
        old_c=targets[2].stat()
        guard=root/'guard'
        guard.write_bytes(b'guarded')
        actors={str(path):stack.enter_context(WriterProcess(build/'secmon-writer-scenario',path))
                for path in [*targets,alias]}
        guard_writer=stack.enter_context(WriterProcess(build/'secmon-writer-scenario',guard))
        tools=[dict(role=f'reader-{index}',process_inode=reference(stack,actor.process.pid),
                    pid=actor.process.pid,path=path) for index,(path,actor) in enumerate(actors.items())]
        tools.append(dict(role='guard-writer',process_inode=reference(stack,guard_writer.process.pid),
                          pid=guard_writer.process.pid,path=str(guard)))
        by_pid={tool['pid']:tool for tool in tools}

        def fields(paths,decision='allow',extra='',protect=True):
            return (f'protect "{guard}"\n' if protect else '')+''.join(f'fanotify-file "{p}"\n' for p in paths)+f'fanotify-event {event}\nfanotify-decision {decision}\n'+extra

        current={str(targets[0]):targets[0].stat().st_ino}
        revision,decision,updates=1,'allow',0
        service=LiveService(build,root,targets[0],fields([targets[0]]),combined=True,requester_pidfd=pidfd)
        stack.callback(service.close)
        base=len(list(Path(f'/proc/{service.process.pid}/fd').iterdir()))
        initial_pid=service.process.pid
        expected=[]
        expected_guard_denials=0

        def stable():
            nonlocal expected_guard_denials
            status=service.status()
            assert status['pid']==initial_pid and status['instance_ns']==service.initial['instance_ns']
            assert status['revision']==revision and status['fanotify_targets']==len(current)
            assert status['pending']==0
            assert len(list(Path(f'/proc/{initial_pid}/fd').iterdir()))==base+len(current)-1
            assert guard_writer.request('w')==errno.EACCES
            expected_guard_denials+=1

        def probe():
            for path,actor in actors.items():
                inode=Path(path).stat().st_ino
                marked=inode in current.values()
                expected_errno=errno.EPERM if marked and decision=='deny' else 0
                assert actor.request('r')==expected_errno,(path,revision,decision,marked)
                if marked:
                    expected.append((actor.process.pid,inode,revision,decision))
            stable()

        def change(paths,next_decision='allow',extra='',code='ok',protect=True):
            nonlocal current,revision,decision,updates
            before=service.status()
            source=fields(paths,next_decision,extra,protect)
            service.publish(revision+1,source)
            result=call(service.binary,'reload',service.control,code)
            if code=='ok':
                changed=[str(p) for p in paths]!=list(current)
                current={str(path):current.get(str(path),path.stat().st_ino) for path in paths}
                revision+=1
                decision=next_decision
                updates+=int(changed)
                assert result['source_sha256']==hashlib.sha256((service.policy).read_bytes()).hexdigest()
            else:
                assert result['source_sha256']==before['source_sha256']
            stable()

        probe()
        for selected in (targets[:2],targets[1:],[targets[2]]):
            change(selected)
            probe()
        change([targets[2],root/'missing'],code='prepare_failed')
        probe()
        change([targets[2],alias],code='prepare_failed')
        probe()
        change([targets[2],Path('/proc/self/status')],code='prepare_failed')
        probe()
        change(targets[:2],extra=f'protect "{root/"missing"}"\n',code='prepare_failed')
        probe()
        change([service.policy],code='prepare_failed')
        probe()
        # Retain the original c object despite replacement of the pathname.
        targets[2].rename(root/'renamed-c')
        targets[2].write_bytes(b'new c replacement\n')
        assert targets[2].stat().st_ino!=old_c.st_ino
        change([targets[2],targets[1]])
        assert current[str(targets[2])]==old_c.st_ino
        probe()  # alias is marked; replacement pathname is not.
        change(targets[:2])
        probe()
        # stable() checks descriptor-count recovery. Following /proc/PID/fd
        # references would violate the combined service's process protection.
        change([targets[2]])
        assert current[str(targets[2])]==targets[2].stat().st_ino
        probe()  # Re-added c resolves the new object; old alias is not marked.
        change(targets,next_decision='deny')
        probe()
        change(targets[:1],code='restart_required')
        probe()
        change(targets)  # Rule-only restoration of immediate allow.
        probe()
        change(targets,extra='fanotify-delay-ms 600\nfanotify-timeout-ms 2000\n')
        change(targets[:1],code='restart_required')  # Idle delayed-allow is also excluded.
        change(targets)
        selections=(targets[:1],targets[:2],targets[1:],[targets[2]])
        for index in range(rounds):
            change(selections[index%len(selections)])
            probe()
        service.stop()
        raw=contents(service.output).encode()
        diagnostics=contents(service.errors)
        records=[json.loads(line) for line in raw.splitlines()]
        permissions=[row for row in records if row['event']=='fanotify_decision']
        handovers=[row for row in records if row['event']=='fanotify_target_handover']
        assert len(handovers)==updates
        next_id=1
        for row in records:
            if row['event']=='fanotify_decision':
                assert row['request_id']==next_id
                next_id+=1
            elif row['event']=='fanotify_target_handover':
                assert row['next_request_id']==next_id
                assert row['listener_pid']==initial_pid and row['instance_ns']==service.initial['instance_ns']
                assert row['from_revision']<row['to_revision']<=revision
                assert 1<=row['old_targets']<=64 and 1<=row['new_targets']<=64
                assert 0<=row['retained_targets']<=min(row['old_targets'],row['new_targets'])
                assert row['kernel_unread']=='released_under_prior_allow' and row['individual_audit_complete'] is False
        actual=Counter((row['requester_pid'],row['inode'],row['revision'],row['decision']) for row in permissions)
        assert actual==Counter(expected),(actual,Counter(expected))
        assert sorted(row['request_id'] for row in permissions)==list(range(1,len(permissions)+1))
        for row in permissions:
            assert row['instance_ns']==service.initial['instance_ns'] and row['listener_pid']==initial_pid
            assert row['permission_event']==event and row['reason']=='policy'
            assert (row['major'],row['minor'])==(os.major(old_c.st_dev),os.minor(old_c.st_dev))
            if pidfd:
                assert row['requester_reference']=='present'
                assert row['requester_process_inode']==by_pid[row['requester_pid']]['process_inode']
        denials=[row for row in records if row['event']=='file_denied']
        assert len(denials)==expected_guard_denials and all(row['ino']==guard.stat().st_ino for row in denials)
        stats=next(json.loads(line) for line in diagnostics.splitlines() if line.startswith('{') and 'target_updates' in line)
        assert stats['target_updates']==updates
        assert stats['allowed']==sum(row['decision']=='allow' for row in permissions)
        assert stats['denied']==sum(row['decision']=='deny' for row in permissions)
        status=service.initial
        for field in ('audit_dropped','audit_invalid','audit_queued','audit_errno','ringbuf_dropped','baseline_update_failed'):
            values=re.findall(r'\b'+field+r'=(\d+)',diagnostics)
            assert values and int(values[-1])==0,(field,values)
        assert guard.read_bytes()==b'guarded' and alias.read_bytes()==b'c original content\n'
        machine=Path('/etc/machine-id').read_text().strip()
        boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        capture=f'handover-{event}-{int(pidfd)}-{status["instance_ns"]}'
        grouped,evidence=evaluate(raw,machine,boot,capture,rule_history=128)
        summary=grouped[-1]
        assert summary['rule_matches']==0 and summary['unattributed']==(0 if pidfd else len(permissions))
        report=dict(source=summary['source'],capture=capture,summary=summary,tools=tools,
                    event=event,requester_pidfd=pidfd,rounds=rounds,target_updates=updates,
                    permissions=len(permissions),guard_denials=len(denials),final_revision=revision,
                    audit_sha256=hashlib.sha256(raw).hexdigest(),evidence_sha256=hashlib.sha256(evidence).hexdigest(),
                    diagnostics=diagnostics,interpretation='controlled handover verification; not attack classification',
                    implementation_sha256={str(path):hashlib.sha256(path.read_bytes()).hexdigest() for path in
                        (Path(__file__).resolve(),build/'secmon')})
        if artifact:
            artifact.mkdir(parents=True,exist_ok=False)
            (artifact/'audit.jsonl').write_bytes(raw)
            (artifact/'evidence.jsonl').write_bytes(evidence)
            (artifact/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
        return {key:report[key] for key in ('event','requester_pidfd','target_updates','permissions','guard_denials','final_revision')}


def backlog(build,event,mode):
    """Stop only a fanotify-only test instance, queue known old kernel waiters,
    then place a reload command on its socket before resuming its event loop."""
    with tempfile.TemporaryDirectory(prefix='secmon-handover-backlog-') as temporary, ExitStack() as stack:
        root=Path(temporary)
        a,b=root/'a',root/'b'
        a.write_bytes(b'a')
        b.write_bytes(b'b')
        old_decision='deny' if mode=='deny-refused' else 'allow'
        old=f'fanotify-file "{a}"\nfanotify-event {event}\nfanotify-decision {old_decision}\n'
        service=LiveService(build,root,a,old,requester_pidfd=True)
        stack.callback(service.close)
        processes=[]
        stopped=False
        try:
            os.kill(service.process.pid,signal.SIGSTOP)
            stopped=True
            processes=[begin_request(a,event) for _ in range(8)]
            deadline=time.monotonic()+5
            while True:
                waiting=[Path('/proc',str(p.pid),'wchan').read_text().strip() for p in processes]
                if all('fanotify' in state for state in waiting):
                    break
                assert time.monotonic()<deadline,waiting
                time.sleep(0.005)
            next_fields=f'fanotify-file "{b}"\nfanotify-event {event}\nfanotify-decision deny\n'
            if mode=='prepare-rollback':
                next_fields+='fanotify-file "/proc/self/status"\n'
            service.publish(2,next_fields)
            with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as client:
                client.settimeout(5)
                client.connect(str(service.control))
                client.sendall(b'reload')
                os.kill(service.process.pid,signal.SIGCONT)
                stopped=False
                payload=client.recv(4096)
                assert len(payload)==ctypes.sizeof(Reply)
                reply=Reply.from_buffer_copy(payload)
                expected_code=6 if mode=='deny-refused' else 4 if mode=='prepare-rollback' else 0
                assert reply.magic==0x53434D43 and reply.abi==4 and reply.command==2
                assert reply.code==expected_code and reply.revision==(2 if expected_code==0 else 1)
            results=[finish_request(p)['errno'] for p in processes]
            assert results==([errno.EPERM]*8 if mode=='deny-refused' else [0]*8),results
            assert request(a,event)['errno']==(errno.EPERM if mode=='deny-refused' else 0)
            assert request(b,event)['errno']==(errno.EPERM if mode=='allow-handover' else 0)
            service.stop()
        finally:
            if stopped:
                os.kill(service.process.pid,signal.SIGCONT)
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)
        records=[json.loads(line) for line in contents(service.output).splitlines()]
        permissions=[r for r in records if r['event']=='fanotify_decision']
        assert sum(r['event']=='fanotify_target_handover' for r in records)==int(mode=='allow-handover')
        assert sorted(r['request_id'] for r in permissions)==list(range(1,len(permissions)+1))
        if mode=='deny-refused':
            assert len(permissions)==9 and all(r['revision']==1 and r['decision']=='deny' for r in permissions)
        elif mode=='prepare-rollback':
            assert len(permissions)==9 and all(r['revision']==1 and r['decision']=='allow' for r in permissions)
        else:
            # Old kernel-unread requests are allowed on close, not invented as
            # individually audited replies. One stable new b request is denied.
            assert 1<=len(permissions)<=9
            assert sum(r['revision']==2 and r['inode']==b.stat().st_ino and r['decision']=='deny' for r in permissions)==1
        stats=next(json.loads(line) for line in contents(service.errors).splitlines()
                   if line.startswith('{') and 'target_updates' in line)
        assert stats['allowed']==sum(r['decision']=='allow' for r in permissions)
        assert stats['denied']==sum(r['decision']=='deny' for r in permissions)
        print(json.dumps(dict(test='handover-backlog',event=event,mode=mode,
                              audited_permissions=len(permissions),passed=True)),flush=True)


def capacity(build,event):
    with tempfile.TemporaryDirectory(prefix='secmon-handover-capacity-') as temporary, ExitStack() as stack:
        root=Path(temporary)
        targets=[root/f'target-{i}' for i in range(65)]
        for target in targets:
            target.write_bytes(b'data')
        guard=root/'guard'
        guard.write_bytes(b'guarded')
        writer=stack.enter_context(WriterProcess(build/'secmon-writer-scenario',guard))
        def fields(paths):
            return f'protect "{guard}"\n'+''.join(f'fanotify-file "{p}"\n' for p in paths)+f'fanotify-event {event}\nfanotify-decision allow\n'
        selected=targets[:64]
        revision=1
        service=LiveService(build,root,targets[0],fields(selected),combined=True,requester_pidfd=True)
        stack.callback(service.close)
        base=len(list(Path(f'/proc/{service.process.pid}/fd').iterdir()))
        expected=Counter()
        updates=0
        def probe():
            with ThreadPoolExecutor(max_workers=8) as pool:
                results=list(pool.map(lambda path:request(path,event),targets))
            assert all(r['errno']==0 for r in results)
            expected.update((revision,path.stat().st_ino) for path in selected)
            assert writer.request('w')==errno.EACCES
            snapshot=service.status()
            assert snapshot['fanotify_targets']==len(selected) and snapshot['revision']==revision
            assert len(list(Path(f'/proc/{service.process.pid}/fd').iterdir()))==base+len(selected)-64
        probe()
        for paths,code,extra in ((targets,'invalid_policy',''),
                                 ([*targets[:63],targets[0]],'invalid_policy',''),
                                 ([*targets[:63],Path('/proc/self/status')],'prepare_failed',''),
                                 (targets[1:],'prepare_failed',f'protect "{root/"missing"}"\n')):
            service.publish(2,fields(paths)+extra)
            result=call(service.binary,'reload',service.control,code)
            assert result['revision']==1
            probe()
        for paths in (targets[:63],targets[1:],targets[:64]):
            service.publish(revision+1,fields(paths))
            revision+=1
            assert call(service.binary,'reload',service.control)['revision']==revision
            selected=paths
            updates+=1
            probe()
        service.stop()
        permissions=[json.loads(line) for line in contents(service.output).splitlines()
                     if json.loads(line)['event']=='fanotify_decision']
        assert Counter((r['revision'],r['inode']) for r in permissions)==expected
        assert sorted(r['request_id'] for r in permissions)==list(range(1,len(permissions)+1))
        stats=next(json.loads(line) for line in contents(service.errors).splitlines()
                   if line.startswith('{') and 'target_updates' in line)
        assert stats['target_updates']==updates and stats['allowed']==len(permissions) and stats['denied']==0
        print(json.dumps(dict(test='handover-capacity',event=event,permissions=len(permissions),passed=True)),flush=True)


def exclusions(build,event):
    with tempfile.TemporaryDirectory(prefix='secmon-handover-exclusions-') as temporary, ExitStack() as stack:
        root=Path(temporary)
        a,b=root/'a',root/'b'
        a.write_bytes(b'a')
        b.write_bytes(b'b')
        def fields(path,extra):
            return f'fanotify-file "{path}"\nfanotify-event {event}\n'+extra
        delayed='fanotify-decision allow\nfanotify-delay-ms 600\nfanotify-timeout-ms 2000\n'
        service=LiveService(build,root,a,fields(a,delayed),requester_pidfd=True)
        stack.callback(service.close)
        process=begin_request(a,event)
        try:
            service.wait_pending(1)
            service.publish(2,fields(b,'fanotify-decision allow\n'))
            assert call(service.binary,'reload',service.control,'busy')['revision']==1
            assert finish_request(process)['errno']==0
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)
        assert call(service.binary,'reload',service.control,'restart_required')['revision']==1
        service.stop()
    with tempfile.TemporaryDirectory(prefix='secmon-handover-analysis-') as temporary, ExitStack() as stack:
        root=Path(temporary)
        a,b=root/'a',root/'b'
        a.write_bytes(b'clean')
        b.write_bytes(b'clean')
        analyzer=f'fanotify-analyzer "{build/"secmon-analyzer"}"\nfanotify-marker "BLOCK"\n'
        service=LiveService(build,root,a,f'fanotify-file "{a}"\nfanotify-event {event}\n'+analyzer,requester_pidfd=True)
        stack.callback(service.close)
        service.publish(2,f'fanotify-file "{b}"\nfanotify-event {event}\n'+analyzer)
        reply=call(service.binary,'reload',service.control,'restart_required')
        assert reply['revision']==1 and reply['analyzer_pid']==service.initial['analyzer_pid']
        assert request(a,event)['errno']==0 and request(b,event)['errno']==0
        service.stop()
    print(json.dumps(dict(test='handover-exclusions',event=event,passed=True)),flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir',type=Path,default=Path('build'))
    parser.add_argument('--artifact-dir',type=Path)
    parser.add_argument('--rounds',type=int,default=16)
    parser.add_argument('--duration',type=int,default=0)
    args=parser.parse_args()
    if os.geteuid()!=0 or not __debug__ or os.environ.get('PYTHONOPTIMIZE'):
        parser.error('run as root without Python optimization')
    if not 1<=args.rounds<=512 or not 0<=args.duration<=2400:
        parser.error('rounds must be 1..512; duration must be 0..2400')
    assert os.readlink('/proc/self/ns/pid')==os.readlink('/proc/1/ns/pid')
    start=time.monotonic()
    base=len(os.listdir('/proc/self/fd'))
    reports=[]
    cycle=0
    for event in ('open','access'):
        for mode in ('allow-handover','deny-refused','prepare-rollback'):
            backlog(args.build_dir.resolve(),event,mode)
            assert len(os.listdir('/proc/self/fd'))==base
        capacity(args.build_dir.resolve(),event)
        exclusions(args.build_dir.resolve(),event)
        assert len(os.listdir('/proc/self/fd'))==base
    while True:
        cycle+=1
        for pidfd in (False,True):
            for event in ('open','access'):
                artifact=args.artifact_dir/f'cycle-{cycle}-{event}-pidfd-{int(pidfd)}' if args.artifact_dir else None
                row=experiment(args.build_dir.resolve(),event,pidfd,args.rounds,artifact)
                assert len(os.listdir('/proc/self/fd'))==base
                assert not Path('/proc/self/task',str(os.getpid()),'children').read_text().strip()
                reports.append(dict(cycle=cycle,**row))
                print(json.dumps(dict(passed=True,**reports[-1])),flush=True)
        if time.monotonic()-start>=args.duration:
            break
    result=dict(passed=True,cycles=cycle,variants=len(reports),results=reports,
                seconds=round(time.monotonic()-start,3),controller_base_fds=base,
                controller_final_fds=len(os.listdir('/proc/self/fd')))
    if args.artifact_dir:
        (args.artifact_dir/'summary.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({key:value for key,value in result.items() if key!='results'}),flush=True)


if __name__=='__main__':
    main()
