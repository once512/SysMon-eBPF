#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit installed-layout validation; never registers a systemd service."""
import argparse
import errno
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
from decoy_harness import mounted
from management_harness import call
from permission_audit import contents


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--prefix',type=Path,required=True);args=p.parse_args()
    if os.geteuid()!=0 or not __debug__:p.error('requires root without optimization')
    prefix=args.prefix.resolve();binary=prefix/'bin/secmon';helpers=prefix/'libexec/secmon'
    for program in (binary,prefix/'bin/secmon-policyctl',helpers/'secmon-decoyfs',helpers/'secmon-analyzer'):assert program.is_file(),program
    with tempfile.TemporaryDirectory(prefix='secmon-installed-layout-') as tmp:
        root=Path(tmp);root.chmod(0o755);view=root/'view';view.mkdir(mode=0o755)
        management=root/'management';management.mkdir(mode=0o700)
        control=management/'control';trap=view/'accounts.csv';guard=root/'guard';guard.write_text('guarded')
        policy=root/'policy';policy.write_text(f'revision 1\nprotect "{guard}"\ncanary "{trap}"\ncanary-response 1 30000\nfanotify-file "{trap}"\nfanotify-event access\nfanotify-analyzer "{helpers/"secmon-analyzer"}"\nfanotify-marker "BLOCK"\nfanotify-timeout-ms 1000\n');policy.chmod(0o600)
        output,errors=tempfile.TemporaryFile(),tempfile.TemporaryFile()
        with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as manager:
            manager.bind(str(root/'notify'));manager.settimeout(5)
            environment=os.environ.copy();environment['NOTIFY_SOCKET']=str(root/'notify')
            process=subprocess.Popen([str(binary),'--policy',str(policy),'--control',str(control),
                '--decoy-provider',str(helpers/'secmon-decoyfs'),'--decoy-mount',str(view),'--decoy-file','accounts.csv',
                '--decoy-allow-other','--audit-permissions','--requester-pidfd','--run-for','30'],env=environment,cwd='/',stdout=output,stderr=errors)
            try:
                assert manager.recv(256).startswith(b'READY=1\n')
                checked=subprocess.run([str(prefix/'bin/secmon-policyctl'),'--socket',str(control),'--expect-revision','1','--require-ready','--require-decoy'],cwd='/',capture_output=True,text=True,timeout=3)
                assert checked.returncode==0,checked.stderr
                state=json.loads(checked.stdout)['status'];assert state['analyzer_online'] and state['decoy_mount_state']=='attached'
                read=subprocess.run(['cat',str(trap)],cwd='/',capture_output=True,timeout=3)
                assert read.returncode==0 and len(read.stdout)==4096 and read.stdout.startswith(b'SecMon synthetic decoy: accounts.csv\n'),read
                actor='import os,sys\ntry: os.open(sys.argv[1],os.O_WRONLY)\nexcept OSError as e: print(e.errno)\nelse: raise SystemExit(4)'
                mutation=subprocess.run(['python3','-c',actor,str(trap)],cwd='/',capture_output=True,text=True,timeout=3)
                assert mutation.returncode==0 and mutation.stdout.strip()==str(errno.EACCES),mutation
                state=call(binary,'status',control);assert state['response_started']==1 and state['allowed']>=1,state
                try:guard.write_text('must fail')
                except OSError as error:assert error.errno==errno.EACCES
                else:raise AssertionError('installed BPF policy inactive')
                call(binary,'stop',control);process.wait(timeout=8)
                assert process.returncode==0,contents(errors)
                assert manager.recv(256).startswith(b'STOPPING=1\n')
                assert not mounted(view) and not control.exists() and guard.read_text()=='guarded'
            finally:
                if process.poll() is None:
                    if control.exists():call(binary,'stop',control)
                    else:process.terminate()
                    process.wait(timeout=8)
                if mounted(view):subprocess.run(['fusermount3','-uz',str(view)],check=True,capture_output=True,timeout=3)
                output.close();errors.close()
    print(json.dumps({'installed_prefix':str(prefix),'cwd':'/','managed_fuse':True,'dropped_analysis':True,'canary_response':True,'independent_guard':True,'notify_start_stop':True,'unmounted':True}))


if __name__=='__main__':main()
