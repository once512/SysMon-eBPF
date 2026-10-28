#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Root-only protocol injection: definitive rejection versus lost/ambiguous commit."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shlex
import socket
import subprocess
import tempfile
import threading
from management_faults import Reply


class Peer:
    def __init__(self,path,policy,mode):
        self.policy,self.mode=policy,mode
        self.text=policy.read_text();self.instance=123
        self.commands=[];self.errors=[];self.done=threading.Event()
        self.server=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        self.server.bind(str(path));self.server.listen(4);self.server.settimeout(.1)
        self.thread=threading.Thread(target=self.run);self.thread.start()

    def reply(self,command,code=0):
        reply=Reply();reply.magic=0x53434D43;reply.abi=10;reply.size=ctypes.sizeof(Reply)
        reply.command={'status':3,'reload':2}[command];reply.code=code
        reply.backend=1;reply.flags=1;reply.pid=os.getpid();reply.instance_ns=self.instance
        reply.worker_pid=reply.reader_pid=reply.decoy_provider_pid=-1
        sessions=[]
        for line in self.text.splitlines():
            words=shlex.split(line)
            if not words or words[0].startswith('#'):continue
            if words[0]=='revision':reply.revision=int(words[1])
            if words[0]=='vault':reply.vault_paths+=1;reply.protected_paths+=1
            if words[0]=='vault-session':sessions.append(words)
        reply.source_digest[:]=hashlib.sha256(self.text.encode()).digest()
        reply.vault_sessions=reply.vault_session_history=len(sessions);reply.vault_clock_valid=1
        if sessions:reply.vault_next_deadline_boot_ns=min(int(s[8])+int(s[6])*1000000 for s in sessions)
        return reply

    def run(self):
        try:
            while not self.done.is_set():
                try:connection,_=self.server.accept()
                except socket.timeout:continue
                with connection:
                    command=connection.recv(32).decode();self.commands.append(command)
                    assert command in ('status','reload'),command
                    if command=='status':connection.send(bytes(self.reply(command)));continue
                    if self.mode in ('applied','lost-after-commit','changed-instance'):
                        self.text=self.policy.read_text()
                    if self.mode in ('lost-after-commit','lost-before-commit'):continue
                    if self.mode=='changed-instance':self.instance+=1
                    if self.mode=='foreign-source':self.policy.write_text(self.text.replace('revision 1','revision 99'));self.policy.chmod(0o600)
                    connection.send(bytes(self.reply(command,4 if self.mode in ('rejected','foreign-source') else 0)))
        except BaseException as error:self.errors.append(error)

    def close(self):
        self.done.set();self.thread.join(timeout=2);self.server.close()
        assert not self.thread.is_alive() and not self.errors,self.errors


def invoke(binary,policy,control,*extras):
    return subprocess.run([str(binary),'open','--policy',str(policy),'--socket',str(control),
                          '--program','/usr/bin/cat','--uid','1000','--target','/test/secret',
                          '--mode','read','--duration-ms','30000',*extras],capture_output=True,text=True,timeout=8)


def protocol(build):
    for mode,exitcode,code in (('applied',0,'applied'),('rejected',1,'prepare_failed'),
            ('lost-after-commit',0,'applied'),('lost-before-commit',3,'activation_unknown'),
            ('changed-instance',3,'activation_unknown'),('foreign-source',3,'activation_unknown')):
        with tempfile.TemporaryDirectory(prefix='secmon-vaultctl-peer-') as tmp:
            root=Path(tmp);policy=root/'policy';control=root/'control'
            original='revision 1\nvault "/test/secret"\n'
            policy.write_text(original);policy.chmod(0o600)
            peer=Peer(control,policy,mode)
            try:
                result=invoke(build/'secmon-vaultctl',policy,control)
                assert result.returncode==exitcode,(mode,result.returncode,result.stdout,result.stderr)
                reply=json.loads(result.stdout);assert reply['code']==code,(mode,reply)
                assert peer.commands.count('reload')==1,peer.commands
                if mode=='rejected':assert reply['rolled_back'] and policy.read_text()==original
                elif mode=='foreign-source':assert 'revision 99\n' in policy.read_text() and not reply['rolled_back']
                else:assert 'vault-session ' in policy.read_text() and 'revision 2\n' in policy.read_text()
                if mode=='lost-after-commit':assert reply['response_recovered']
                if mode=='lost-before-commit':
                    assert peer.text==original and not reply['rolled_back']
                    pending=subprocess.run([str(build/'secmon-vaultctl'),'status','--policy',str(policy),'--socket',str(control)],capture_output=True,text=True,timeout=3)
                    review=json.loads(pending.stdout)
                    assert pending.returncode==1 and review['code']=='policy_mismatch' and not review['source_matches'],review
                    assert len(review['sessions'])==1 and not review['sessions'][0]['live'] and review['sessions'][0]['time_valid'],review
                assert not list(root.glob('.secmon-vault-*.tmp'))
            finally:peer.close()
        print('PASS vaultctl management outcome:',mode)


def sources(build):
    for mode in ('symlink','hardlink','world-readable','untrusted-parent','unsafe-parent','symlink-parent','missing'):
        with tempfile.TemporaryDirectory(prefix='secmon-vaultctl-source-') as tmp:
            root=Path(tmp);folder=root/'private';folder.mkdir()
            policy=folder/'policy';original='revision 1\nvault "/test/secret"\n'
            policy.write_text(original);policy.chmod(0o600)
            actual=policy
            if mode=='symlink':
                policy=folder/'alias';policy.symlink_to(actual)
            elif mode=='hardlink':os.link(policy,folder/'alias')
            elif mode=='world-readable':policy.chmod(0o644)
            elif mode=='untrusted-parent':os.chown(folder,65534,65534)
            elif mode=='unsafe-parent':folder.chmod(0o777)
            elif mode=='symlink-parent':
                alias=root/'alias';alias.symlink_to(folder);policy=alias/'policy'
            else:policy=folder/'missing'
            result=invoke(build/'secmon-vaultctl',policy,root/'absent-control')
            assert result.returncode==1 and json.loads(result.stdout)['code']=='failed',(mode,result)
            assert 'Cannot connect to root control service' not in result.stderr,(mode,result.stderr)
            assert actual.read_text()==original and not list(root.glob('**/.secmon-vault-*.tmp'))
        print('PASS vaultctl source refusal:',mode)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--build-dir',type=Path,default=Path('build'));args=p.parse_args()
    if os.geteuid()!=0 or not __debug__:p.error('requires root without optimization')
    protocol(args.build_dir.resolve());sources(args.build_dir.resolve())


if __name__=='__main__':main()
