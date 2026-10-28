#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Operator open/close/lock drives real applications through the existing policy."""
import argparse
import errno
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from management_harness import call
from monitor_harness import MonitorRun


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir',type=Path,default=Path('build'))
    args=parser.parse_args()
    if os.geteuid()!=0 or not __debug__: parser.error('requires root without optimization')
    build=args.build_dir.resolve()
    with tempfile.TemporaryDirectory(prefix='secmon-vaultctl-') as tmp:
        root=Path(tmp);root.chmod(0o755)
        private=root/'management';private.mkdir(mode=0o700)
        control=private/'control';policy=root/'policy';target=root/'保险箱 private document'
        guard=root/'guard';guard.write_text('guarded')
        alias=root/'private-alias';other=root/'other-document'
        other.write_bytes(b'other');other.chmod(0o666)
        target.write_bytes(bytes(range(256))*32);target.chmod(0o666);os.link(target,alias)
        reader=root/'cat-client';writer=root/'dd-client';outsider=root/'dd-outsider';bad=root/'unsafe-client'
        for program,source in ((reader,'cat'),(writer,'dd'),(outsider,'dd'),(bad,'cat')):
            shutil.copyfile(shutil.which(source),program);program.chmod(0o755)
        bad.chmod(0o777)
        original=f'# preserve this comment\nrevision 1\nvault "{target}"\nprotect "{guard}"\n# final comment\n'
        policy.write_text(original);policy.chmod(0o600)
        def drop():
            os.setgroups([]);os.setgid(65534);os.setuid(65534)
        def command(program,*args,data=None,uid=65534):
            return subprocess.run([str(program),*map(str,args)],input=data,capture_output=True,timeout=4,preexec_fn=drop if uid==65534 else None)
        def read(program=reader,uid=65534):return command(program,target,uid=uid)
        def write(program=writer):return command(program,f'of={target}','conv=notrunc','bs=1','count=4','status=none',data=b'EDIT')
        def ctl(action,*args,code='applied',exitcode=0):
            result=subprocess.run([str(build/'secmon-vaultctl'),action,'--policy',str(policy),'--socket',str(control),*map(str,args)],capture_output=True,text=True,timeout=8)
            assert result.returncode==exitcode,(result.returncode,result.stdout,result.stderr)
            reply=json.loads(result.stdout);assert reply['code']==code,reply
            return reply
        def open_session(program,mode='read',duration=30000,**kw):
            return ctl('open','--program',program,'--uid',65534,'--target',target,'--mode',mode,'--duration-ms',duration,**kw)
        with MonitorRun(build/'secmon',['--policy',str(policy),'--control',str(control)],seconds=90) as monitor:
            try:
                assert read().returncode!=0 and write().returncode!=0
                files_before=set(root.iterdir())
                assert ctl('status',code='ok')['sessions']==[]
                assert set(root.iterdir())==files_before,'status must not create a lock or staging file'
                opened=open_session(reader)
                assert opened['revision']==2 and opened['session_id']>0
                first_id=opened['session_id'];first_deadline=opened['deadline_boot_ns']
                assert read().stdout==bytes(range(256))*32 and read().returncode==0
                assert read(uid=0).returncode!=0 and write().returncode!=0
                opened_writer=open_session(writer,'read-write')
                assert opened_writer['revision']==3 and opened_writer['session_id']!=first_id
                status=ctl('status',code='ok')
                assert len(status['sessions'])==2 and all(s['live'] for s in status['sessions'])
                assert all(s['target']==str(target) for s in status['sessions']),status
                assert next(s for s in status['sessions'] if s['id']==first_id)['deadline_boot_ns']==first_deadline
                assert write().returncode==0 and write(outsider).returncode!=0
                assert read().stdout.startswith(b'EDIT')
                source=policy.read_text();assert '# preserve this comment\n' in source and '# final comment\n' in source
                # A server-side program ownership/mode rejection restores exact
                # source bytes and keeps old application access intact.
                failure=open_session(bad,code='prepare_failed',exitcode=1)
                assert failure['rolled_back'] and policy.read_text()==source
                assert read().returncode==0 and write().returncode==0
                stale=ctl('close','--id',first_id,'--expect-revision',1,code='failed',exitcode=1)
                assert policy.read_text()==source
                closed=ctl('close','--id',first_id)
                assert closed['removed_sessions']==1 and closed['revision']==4
                assert read().returncode!=0 and write().returncode==0
                locked=ctl('lock','--target',target)
                assert locked['removed_sessions']==1 and locked['revision']==5
                assert read().returncode!=0 and write().returncode!=0
                locked_source=policy.read_bytes()
                assert ctl('lock','--target',target,code='unchanged')['revision']==5
                assert policy.read_bytes()==locked_source
                # Advisory lock is checked before publication/reload.
                with open(root/'.policy.secmon-vault.lock','r+') as lock:
                    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    open_session(reader,code='failed',exitcode=1)
                assert policy.read_bytes()==locked_source
                # Expiry remains in kernel time and is visible per declaration.
                short=open_session(reader,duration=700)
                until=time.monotonic()+2
                while ctl('status',code='ok')['sessions'][0]['live']:
                    assert time.monotonic()<until
                    time.sleep(.05)
                assert read().returncode!=0
                ctl('lock','--target',target)
                assert stat_mode(policy)==0o600
                # A lock must revoke grants declared through a hard-link alias,
                # while preserving a separate vault's independent session.
                source=policy.read_text();revision=ctl('status',code='ok')['revision']
                policy.write_text(source.replace(f'revision {revision}\n',f'revision {revision+1}\n')+f'vault "{alias}"\nvault "{other}"\n')
                call(build/'secmon','reload',control)
                alias_open=ctl('open','--program',reader,'--uid',65534,'--target',alias,'--mode','read','--duration-ms',30000)
                other_open=ctl('open','--program',reader,'--uid',65534,'--target',other,'--mode','read','--duration-ms',30000)
                assert read().returncode==0 and command(reader,other).returncode==0
                alias_lock=ctl('lock','--target',target)
                assert alias_lock['removed_sessions']==1 and alias_lock['status']['vault_live_sessions']==1
                assert read().returncode!=0 and command(reader,alias).returncode!=0 and command(reader,other).stdout==b'other'
                ctl('close','--id',other_open['session_id'])
                # An unrelated guarded object never becomes writable.
                try: guard.write_text('must fail')
                except OSError as error: assert error.errno==errno.EACCES
                else: raise AssertionError('unrelated guard lost protection')
            finally:
                call(build/'secmon','stop',control);monitor.process.wait(timeout=5)
        assert target.read_bytes().startswith(b'EDIT') and guard.read_text()=='guarded'
        assert not list(root.glob('.secmon-vault-*.tmp'))
    print('PASS vaultctl actual cat/dd: open, scoped writes, unchanged deadlines, close, lock, expiry, rollback, version/lock conflicts and independent guard')


def stat_mode(path):return path.stat().st_mode&0o7777
if __name__=='__main__':main()
