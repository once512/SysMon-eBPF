#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit rebind follows a new FUSE mount at the same configured pathname."""
import argparse
from contextlib import ExitStack
import errno
import json
import os
import signal
from pathlib import Path
import subprocess
import tempfile
from decoy_harness import DecoyView, mounted
from virtual_decoy import DecoyActor
from fanotify_handover import LiveService
from permission_audit import contents
from management_harness import call


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir',type=Path,default=Path('build'))
    args=parser.parse_args()
    if os.geteuid()!=0 or not __debug__:parser.error('run as root without Python optimization')
    build=args.build_dir.resolve()
    with tempfile.TemporaryDirectory(prefix='secmon-virtual-rebind-') as tmp, ExitStack() as stack:
        root=Path(tmp); view=root/'view';view.mkdir()
        first=stack.enter_context(DecoyView(build/'secmon-decoyfs',view))
        trap=view/'accounts.csv'; victim=root/'victim';victim.write_bytes(b'original'+b'\0'*8192)
        old_key=(trap.stat().st_dev,trap.stat().st_ino)
        old=stack.enter_context(DecoyActor(build/'secmon-virtual-decoy-scenario',trap,victim))
        def fields(rebind=0,response=1):
            text=f'canary "{trap}"\ncanary-response {response} 30000\nfanotify-file "{trap}"\nfanotify-event access\nfanotify-decision allow\n'
            if rebind:text+=f'fanotify-rebind-epoch {rebind}\n'
            return text
        service=LiveService(build,root,trap,fields(),combined=True,requester_pidfd=True)
        stack.callback(service.close)
        paused=False
        def resume():
            nonlocal paused
            if paused and first.process.poll() is None:
                os.kill(first.process.pid,signal.SIGCONT);paused=False
        stack.callback(resume)
        assert old.request('r')==0
        assert old.request('c')==old.request('w')==errno.EACCES
        os.kill(first.process.pid,signal.SIGSTOP);paused=True
        service.publish(2,fields(1))
        rejected=call(build/'secmon','reload',service.control,'prepare_failed')
        assert rejected['revision']==1 and rejected['response_epoch']==1
        resume()
        assert old.request('r')==0 and old.request('w')==errno.EACCES
        subprocess.run(['fusermount3','-uz',str(view)],check=True,capture_output=True,timeout=4)
        first.process.kill();first.process.wait(timeout=4)
        second=stack.enter_context(DecoyView(build/'secmon-decoyfs',view))
        new_key=(trap.stat().st_dev,trap.stat().st_ino);assert old_key!=new_key
        new=stack.enter_context(DecoyActor(build/'secmon-virtual-decoy-scenario',trap,victim))
        assert new.request('r')==0 and new.request('w')==0
        # An ordinary reload can refresh BPF paths but retains the original
        # fanotify inode. The explicit rebind request closes that mismatch.
        service.publish(2,fields());call(build/'secmon','reload',service.control)
        assert new.request('r')==0 and old.request('w')==errno.EACCES
        assert service.status()['allowed']==2
        service.publish(3,fields(1,2));state=call(build/'secmon','reload',service.control)
        assert state['revision']==3 and state['response_epoch']==2
        assert new.request('r')==0
        assert old.request('w')==0
        assert new.request('c')==new.request('w')==errno.EACCES
        assert service.status()['allowed']==3 and service.status()['response_started']==2
        service.stop()
        records=[json.loads(line) for line in contents(service.output).splitlines()]
        decisions=[e for e in records if e['event']=='fanotify_decision']
        assert len(decisions)==3 and [e['subscription_generation'] for e in decisions]==[1,1,2]
        assert [(os.makedev(e['major'],e['minor']),e['inode']) for e in decisions]==[old_key,old_key,new_key]
        assert [e['requester_pid'] for e in decisions]==[old.process.pid,old.process.pid,new.process.pid]
        switches=[e for e in records if e['event']=='fanotify_target_handover']
        assert len(switches)==1 and switches[0]['retained_targets']==0 and switches[0]['to_rebind_epoch']==1
        print(json.dumps({'passed':True,'old_key':old_key,'new_key':new_key,'same_path_rebound':True,
                          'canary_and_fanotify_agree':True,'ordinary_reload_retains_subscription':True,
                          'response_release_explicit':True,'audited_permissions':3,'paused_preparation_rollback':True}))
if __name__=='__main__':main()
