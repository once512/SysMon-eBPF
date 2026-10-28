#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real Vim in-place profile, including locking an already running editor."""
import argparse
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
    parser.add_argument('--build-dir',type=Path,default=Path('build'));args=parser.parse_args()
    if os.geteuid()!=0 or not __debug__:parser.error('requires root without optimization')
    vim=shutil.which('vim')
    if not vim:parser.error('real Vim required for this topic')
    build=args.build_dir.resolve()
    with tempfile.TemporaryDirectory(prefix='secmon-vault-editor-') as tmp:
        root=Path(tmp);root.chmod(0o755)
        management=root/'management';management.mkdir(mode=0o700)
        work=root/'work';work.mkdir(mode=0o700);os.chown(work,65534,65534)
        target=root/'document.txt';target.write_text('original\nsecond line\n');target.chmod(0o666)
        original_inode=target.stat().st_ino
        editor=root/'vim-client';shutil.copyfile(vim,editor);editor.chmod(0o755)
        policy=root/'policy';policy.write_text(f'revision 1\nvault "{target}"\n');policy.chmod(0o600)
        control=management/'control'
        def drop():os.setgroups([]);os.setgid(65534);os.setuid(65534)
        def ctl(action,*extra):
            result=subprocess.run([str(build/'secmon-vaultctl'),action,'--policy',str(policy),'--socket',str(control),*map(str,extra)],capture_output=True,text=True,timeout=8)
            assert result.returncode==0,(result.returncode,result.stdout,result.stderr)
            return json.loads(result.stdout)
        def grant(mode):return ctl('open','--program',editor,'--uid',65534,'--target',target,'--mode',mode,'--duration-ms',30000)
        base=[str(editor),'-u','NONE','-i','NONE','-n','--noplugin','-es','--cmd',
              'set nomodeline noundofile noswapfile nobackup nowritebackup backupcopy=yes']
        with MonitorRun(build/'secmon',['--policy',str(policy),'--control',str(control)],seconds=90) as monitor:
            child=None
            try:
                grant('read')
                denied=subprocess.run([*base,'-c',"call setline(1, 'must not save')",'-c','write','-c','quit!',str(target)],capture_output=True,preexec_fn=drop,cwd=work,timeout=4)
                assert denied.returncode!=0,denied
                ctl('lock','--target',target)
                grant('read-write')
                saved=subprocess.run([*base,'-c',"if getline(1) !=# 'original' | cquit 31 | endif",'-c',"call setline(1, 'saved first')",'-c','write','-c','quit!',str(target)],capture_output=True,preexec_fn=drop,cwd=work,timeout=4)
                assert saved.returncode==0,(saved.returncode,saved.stdout,saved.stderr)
                assert target.stat().st_ino==original_inode
                # Keep the application alive across explicit revocation and a
                # fresh grant; the BPF program identity stays the same instance.
                child=subprocess.Popen([*base,str(target)],stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True,preexec_fn=drop,cwd=work)
                ready=work/'ready';denial=work/'denial';success=work/'success'
                def send(text):child.stdin.write(text+'\n');child.stdin.flush()
                def wait(path):
                    until=time.monotonic()+3
                    while not path.exists():
                        assert child.poll() is None and time.monotonic()<until,(child.poll(),path)
                        time.sleep(.01)
                send("if getline(1) !=# 'saved first' | cquit 32 | endif")
                send("call setline(1, 'pending unsaved')")
                send(f"call writefile(['ready'], '{ready}')");wait(ready)
                ctl('lock','--target',target)
                send("let v:errmsg = ''");send('silent! write')
                send(f"call writefile([v:errmsg], '{denial}')");wait(denial)
                assert denial.read_text().strip(), 'Closed session did not reject actual Vim write'
                grant('read-write')
                send("let v:errmsg = ''");send('write')
                send(f"call writefile([v:errmsg], '{success}')");wait(success)
                assert not success.read_text().strip(),success.read_text()
                send('quit!');child.stdin.close();child.wait(timeout=4)
                assert child.returncode==0,child.stderr.read()
                ctl('lock','--target',target)
                assert target.stat().st_ino==original_inode
                assert sorted(p.name for p in work.iterdir())==['denial','ready','success']
                assert not list(root.glob('*.swp')) and not list(root.glob('*~')) and not list(root.glob('*.un~'))
            finally:
                if child is not None and child.poll() is None:
                    child.kill();child.wait(timeout=3)
                call(build/'secmon','stop',control);monitor.process.wait(timeout=5)
        assert target.read_text()=='pending unsaved\nsecond line\n'
    print('PASS real Vim: read-only save denied, in-place save, running editor revoked/regranted, unchanged inode and no profile backup/swap artifacts')


if __name__=='__main__':main()
