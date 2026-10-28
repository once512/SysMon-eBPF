#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real monitor readiness/stop datagrams without installing or starting a unit."""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
from decoy_harness import mounted
from managed_decoy import ManagedRun
from management_harness import call


def receive(manager,pid,key):
    payload,ancillary,flags,_=manager.recvmsg(256,socket.CMSG_SPACE(struct.calcsize('3i')))
    assert not flags and payload.startswith(key+b'\n'),payload
    credentials=[struct.unpack('3i',data) for level,kind,data in ancillary if level==socket.SOL_SOCKET and kind==socket.SCM_CREDENTIALS]
    assert credentials==[(pid,0,0)],credentials
    return payload


def managed(build,analysis=False,abstract=False,manager_gone=False):
    with tempfile.TemporaryDirectory(prefix='secmon-notify-live-') as tmp,ExitStack() as stack:
        root=Path(tmp);manager=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)
        stack.callback(manager.close);manager.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1);manager.settimeout(4)
        name=('\0secmon-notify-'+str(os.getpid())) if abstract else str(root/'notify')
        manager.bind(name)
        previous=os.environ.get('NOTIFY_SOCKET')
        os.environ['NOTIFY_SOCKET']='@'+name[1:] if abstract else name
        try:service=ManagedRun(build,root,analysis=analysis)
        finally:
            if previous is None:os.environ.pop('NOTIFY_SOCKET',None)
            else:os.environ['NOTIFY_SOCKET']=previous
        stack.callback(service.close)
        receive(manager,service.process.pid,b'READY=1')
        state=service.ready();assert state['configured'] and state['self_protected']
        assert state['decoy_mount_state']=='attached' and state['reader_state']=='responsive',state
        if analysis:assert state['analyzer_online'],state
        # Protected helper environments are intentionally not readable by an
        # unrelated root observer. Environment removal is covered by the pure
        # notification test; these live messages must come only from main.
        service.check()
        service.policy.write_text(service.policy.read_text().replace('revision 1\n','revision 2\n'))
        assert call(build/'secmon','reload',service.control)['revision']==2
        if manager_gone:manager.close()
        service.stop()
        if not manager_gone:receive(manager,service.process.pid,b'STOPPING=1')
        assert not mounted(service.view)
        print(json.dumps({'notify_live':True,'analysis':analysis,'abstract':abstract,'manager_disappeared':manager_gone,'ready_after_resources':True,'main_credentials_verified':True}))


def failure(build,missing_endpoint):
    with tempfile.TemporaryDirectory(prefix='secmon-notify-failed-') as tmp:
        root=Path(tmp);(root/'management').mkdir(mode=0o700)
        target=root/'guard';target.write_text('original')
        policy=root/'policy';policy.write_text(f'revision 1\nprotect "{target}"\n'+('' if missing_endpoint else 'unknown-field value\n'));policy.chmod(0o600)
        control=root/'management'/'control'
        with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as manager:
            manager.bind(str(root/'notify'));manager.settimeout(.1)
            environment=os.environ.copy();environment['NOTIFY_SOCKET']=str(root/('missing' if missing_endpoint else 'notify'))
            result=subprocess.run([str(build/'secmon'),'--policy',str(policy),'--control',str(control)],env=environment,capture_output=True,text=True,timeout=8)
            assert result.returncode==1,(result.returncode,result.stdout,result.stderr)
            assert not control.exists() and target.read_text()=='original'
            try:unexpected=manager.recv(256)
            except socket.timeout:pass
            else:raise AssertionError(unexpected)
            if missing_endpoint:assert 'send service readiness' in result.stderr,result.stderr
        print('PASS failed startup emits no READY and rolls back resources:', 'missing endpoint' if missing_endpoint else 'invalid policy')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--build-dir',type=Path,default=Path('build'));args=p.parse_args()
    if os.geteuid()!=0 or not __debug__:p.error('requires root without optimization')
    build=args.build_dir.resolve()
    managed(build);managed(build,analysis=True,abstract=True);managed(build,manager_gone=True)
    failure(build,False);failure(build,True)


if __name__=='__main__':main()
