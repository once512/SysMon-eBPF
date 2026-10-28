#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reader quarantine retains group/BPF and uses only prior-allow recovery."""
import argparse
from contextlib import ExitStack
import errno
import json
import os
from pathlib import Path
import resource
import signal
import shutil
import subprocess
import tempfile
import time
from management_harness import call
from permission_audit import AuditedService,begin_request,finish_request,request,contents
from writer_harness import WriterProcess


def offline(service):
    until=time.monotonic()+3
    while True:
        state=service.status()
        if state['reader_state']=='offline':
            assert state['reader_pid']==-1 and state['reader_failure']!='none' and state['reader_failures']==1,state
            return state
        assert service.process.poll() is None and time.monotonic()<until,state
        time.sleep(.01)


def check(service,code):
    result=subprocess.run([str(service.build/'secmon-policyctl'),'--socket',str(service.control),'--require-ready'],capture_output=True,text=True,timeout=3)
    assert result.returncode==(0 if code=='ok' else 1) and json.loads(result.stdout)['code']==code,result


def clean_request(process):
    if process.poll() is None:process.kill();process.wait(timeout=3)


def scenario(build,mode,pidfd):
    with tempfile.TemporaryDirectory(prefix='secmon-reader-recovery-') as tmp,ExitStack() as stack:
        root=Path(tmp);target=root/'target';target.write_bytes(b'clean')
        fields='fanotify-timeout-ms 10000\n'
        if mode=='analysis':fields+=f'fanotify-analyzer "{build/"secmon-analyzer"}"\nfanotify-marker "BLOCK"\n'
        else:fields+=f'fanotify-decision {"deny" if mode=="deny" else "allow"}\n'
        if mode=='delayed':fields+='fanotify-delay-ms 5000\n'
        service=AuditedService(build,root,target,fields,requester_pidfd=pidfd);stack.callback(service.close)
        reader=service.status()['reader_pid']
        waiting=None;worker=None
        if mode in ('delayed','analysis'):
            if mode=='analysis':
                worker=service.status()['analyzer_pid'];os.kill(worker,signal.SIGSTOP)
            waiting=begin_request(target);stack.callback(clean_request,waiting);service.wait_pending(1)
        else:assert request(target)['errno']==(errno.EPERM if mode=='deny' else 0)
        os.kill(reader,signal.SIGKILL)
        state=offline(service);assert service.process.poll() is None
        check(service,'reader_offline')
        if waiting is not None:
            assert finish_request(waiting)['errno']==errno.EPERM
            assert state['reader_error_requests']==1 and state['reader_unconfirmed_requests']==0,state
        blocked=begin_request(target);stack.callback(clean_request,blocked)
        time.sleep(.08);assert blocked.poll() is None,'Offline group released an unpublished permission'
        service.publish(2,fields)
        unchanged=call(build/'secmon','reload',service.control)
        assert unchanged['reader_state']=='offline' and blocked.poll() is None
        if mode=='allow':
            service.publish(3,fields.replace('fanotify-decision allow','fanotify-decision deny')+'fanotify-rebind-epoch 1\n')
            recovered=call(build/'secmon','reload',service.control)
            assert recovered['reader_state']=='responsive' and recovered['reader_failures']==1 and recovered['reader_failure']=='none',recovered
            assert finish_request(blocked)['errno'] in (0,errno.EPERM), 'Unexpected old permission completion'
            # A syscall released by the old group may also encounter the new
            # group's deny mark; group release is not a final syscall-success promise.
            check(service,'ok');assert request(target)['errno']==errno.EPERM
        else:
            # A deny/delayed/analysis fault cannot be bypassed by first rewriting
            # the held gate to allow or by requesting a fresh subscription.
            changed=fields.replace('fanotify-decision deny','fanotify-decision allow').replace('fanotify-delay-ms 5000','fanotify-delay-ms 0')
            if mode=='analysis':changed=fields.replace('fanotify-timeout-ms 10000','fanotify-timeout-ms 9000')
            service.publish(3,changed)
            call(build/'secmon','reload',service.control,'restart_required')
            service.publish(3,fields+'fanotify-rebind-epoch 1\n')
            call(build/'secmon','reload',service.control,'restart_required')
            assert blocked.poll() is None and service.status()['reader_state']=='offline'
        service.stop()
        if blocked.poll() is None:finish_request(blocked) # Explicit stop retains documented group-release semantics.
        events=[json.loads(line) for line in contents(service.output).splitlines()]
        failures=[e for e in events if e.get('event')=='fanotify_reader_failure']
        decisions=[e for e in events if e.get('event')=='fanotify_decision']
        assert len(failures)==1 and failures[0]['group_held'] and not failures[0]['individual_audit_complete'],failures
        if waiting is not None:assert len(decisions)==1 and decisions[0]['reason']=='reader_error' and decisions[0]['decision']=='deny',decisions
        if mode=='allow':
            assert [e['request_id'] for e in decisions]==list(range(1,len(decisions)+1)),decisions
            assert decisions[0]['subscription_generation']==1 and all(e['subscription_generation']==2 for e in decisions[1:]),decisions
        print(json.dumps({'reader_quarantine':mode,'pidfd':pidfd,'known_denied':waiting is not None,'unknown_held':True,'recovered_under_prior_allow':mode=='allow'}))


def combined(build,pidfd):
    with tempfile.TemporaryDirectory(prefix='secmon-reader-bpf-retain-') as tmp,ExitStack() as stack:
        root=Path(tmp);target=root/'target';target.write_text('clean');guard=root/'guard';guard.write_text('guarded')
        writer=stack.enter_context(WriterProcess(build/'secmon-writer-scenario',guard))
        fields=f'fanotify-decision allow\nprotect "{guard}"\n'
        service=AuditedService(build,root,target,fields,combined=True,requester_pidfd=pidfd);stack.callback(service.close)
        reader=service.status()['reader_pid']
        # Resource limits are outside the current signal/ptrace self-guard. Force
        # a real child read failure without disabling that self-protection.
        resource.prlimit(reader,resource.RLIMIT_NOFILE,(0,0))
        trigger=begin_request(target);stack.callback(clean_request,trigger)
        state=offline(service)
        assert state['self_protected'] and writer.request('w')==errno.EACCES,state
        try:os.kill(service.process.pid,signal.SIGTERM)
        except PermissionError:pass
        else:raise AssertionError('Reader fault removed main task self-protection')
        blocked=begin_request(target);stack.callback(clean_request,blocked)
        time.sleep(.08);assert blocked.poll() is None
        service.publish(2,fields+'fanotify-rebind-epoch 1\n')
        state=call(build/'secmon','reload',service.control)
        assert state['reader_state']=='responsive' and state['reader_failures']==1 and writer.request('w')==errno.EACCES
        assert finish_request(blocked)['errno']==0
        finish_request(trigger) # The kernel may have rejected this event during FD allocation.
        assert request(target)['errno']==0
        service.stop()
        print(json.dumps({'combined':True,'pidfd':pidfd,'reader_resource_fault':True,'bpf_guard_retained':True,'self_guard_retained':True,'explicit_rebind_recovered':True}))


def vault_while_offline(build):
    with tempfile.TemporaryDirectory(prefix='secmon-reader-vault-lock-') as tmp,ExitStack() as stack:
        root=Path(tmp);target=root/'target';target.write_text('clean');secret=root/'secret';secret.write_text('vault content')
        client=root/'cat-client';shutil.copyfile(shutil.which('cat'),client);client.chmod(0o755)
        fields=f'fanotify-decision allow\nvault "{secret}"\n'
        service=AuditedService(build,root,target,fields,combined=True);stack.callback(service.close)
        def ctl(action,*extra):
            result=subprocess.run([str(build/'secmon-vaultctl'),action,'--policy',str(service.policy),'--socket',str(service.control),*map(str,extra)],capture_output=True,text=True,timeout=8)
            assert result.returncode==0,(result.returncode,result.stdout,result.stderr)
            return json.loads(result.stdout)
        ctl('open','--program',client,'--uid',0,'--target',secret,'--mode','read','--duration-ms',30000)
        assert subprocess.run([str(client),str(secret)],capture_output=True,timeout=3).stdout==b'vault content'
        resource.prlimit(service.status()['reader_pid'],resource.RLIMIT_NOFILE,(0,0))
        trigger=begin_request(target);stack.callback(clean_request,trigger);offline(service)
        closed=ctl('lock','--target',secret)
        assert closed['status']['reader_state']=='offline' and closed['removed_sessions']==1,closed
        denied=subprocess.run([str(client),str(secret)],capture_output=True,timeout=3)
        assert denied.returncode!=0 and not denied.stdout
        service.stop();finish_request(trigger)
    print('PASS vault can lock through unchanged offline fanotify subscription while BPF stays active')


def response_failure(build):
    with tempfile.TemporaryDirectory(prefix='secmon-reader-response-fault-') as tmp,ExitStack() as stack:
        root=Path(tmp);target=root/'target';target.write_text('clean');guard=root/'guard';guard.write_text('guarded')
        writer=stack.enter_context(WriterProcess(build/'secmon-writer-scenario',guard))
        fields=f'fanotify-decision allow\nfanotify-delay-ms 5000\nfanotify-timeout-ms 10000\nprotect "{guard}"\n'
        environment=os.environ.copy();environment['LD_PRELOAD']=str(build/'libsecmon-deny-write-fault.so')
        service=AuditedService(build,root,target,fields,combined=True,environment=environment);stack.callback(service.close)
        first=begin_request(target);stack.callback(clean_request,first);service.wait_pending(1)
        resource.prlimit(service.status()['reader_pid'],resource.RLIMIT_NOFILE,(0,0))
        trigger=begin_request(target);stack.callback(clean_request,trigger)
        state=offline(service)
        assert state['reader_unconfirmed_requests']==1 and state['reader_error_requests']==0 and state['pending']==0,state
        assert first.poll() is None and writer.request('w')==errno.EACCES
        service.stop();finish_request(first);finish_request(trigger)
        events=[json.loads(line) for line in contents(service.output).splitlines()]
        assert not any(e.get('event')=='fanotify_decision' for e in events),events
        failures=[e for e in events if e.get('event')=='fanotify_reader_failure']
        assert len(failures)==1 and failures[0]['unconfirmed_delivered']==1,failures
    print('PASS reader denial write EIO: unconfirmed count, no fabricated verdict, retained group/BPF and explicit-stop release')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--build-dir',type=Path,default=Path('build'));args=p.parse_args()
    if os.geteuid()!=0 or not __debug__:p.error('requires root without optimization')
    build=args.build_dir.resolve()
    for pidfd in (False,True):
        for mode in ('allow','deny','delayed','analysis'):scenario(build,mode,pidfd)
        combined(build,pidfd)
    response_failure(build)
    vault_while_offline(build)


if __name__=='__main__':main()
