#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Protect the trusted executable's ACL/capabilities through read-only held FDs."""
import argparse
from contextlib import ExitStack
import errno
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
from file_metadata import ACL
from management_harness import call
from monitor_harness import MonitorRun
from writer_harness import WriterProcess

ACTOR = r'''import array,fcntl,os,struct,sys
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_CLOEXEC)
acl=bytes.fromhex(sys.argv[2])
# VFS capabilities v2, effective CAP_NET_BIND_SERVICE.
cap=struct.pack('<IIIII',0x02000001,1<<10,0,0,0)
print('ready',flush=True)
for line in sys.stdin:
 c=line.strip()
 if c=='q':break
 try:
  if c=='x':os.setxattr(fd,'user.secmon',b'value')
  elif c=='d':os.removexattr(fd,'user.secmon')
  elif c=='a':os.setxattr(fd,'system.posix_acl_access',acl)
  elif c=='r':os.removexattr(fd,'system.posix_acl_access')
  elif c=='c':os.setxattr(fd,'security.capability',cap)
  elif c=='e':os.removexattr(fd,'security.capability')
  elif c=='i':
   flags=array.array('l',[0]);fcntl.ioctl(fd,0x80086601,flags,True)
   flags[0]^=0x40;fcntl.ioctl(fd,0x40086602,flags)
  else:raise OSError(22,'invalid command')
  print(0,flush=True)
 except OSError as error:print(error.errno,flush=True)
'''

class MetadataIdentityProcess(WriterProcess):
    def __init__(self, target, executable):
        self.lock = threading.Lock()
        self.process = subprocess.Popen([str(executable), '-u', '-c', ACTOR, str(target), ACL.hex()],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True, bufsize=1)
        try: assert self.read() == 'ready'
        except BaseException:
            self.close(); raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', default='build')
    args = parser.parse_args()
    assert os.geteuid() == 0
    build = Path(args.build_dir).resolve()
    with tempfile.TemporaryDirectory(prefix='secmon-metadata-identity-') as temporary, ExitStack() as stack:
        root = Path(temporary)
        program = root / 'trusted'
        shutil.copyfile(Path(sys.executable).resolve(), program); program.chmod(0o755)
        target = root / 'data'; target.write_bytes(b'data')
        alias = root / 'program-alias'; os.link(program, alias)
        actor = stack.enter_context(MetadataIdentityProcess(alias, program))
        # FD is read-only; actual success proves the kernel does not require
        # an ordinary content write check for these metadata mutations.
        for command in 'xdarcei': assert actor.request(command) == 0, command
        program.chmod(0o755)
        assert actor.request('x') == actor.request('a') == actor.request('c') == 0
        program.chmod(0o755)
        policy, control = root / 'policy', root / 'control'
        def publish(revision, extra=''):
            stage = root / 'stage'
            stage.write_text(f'revision {revision}\nprotect "{target}"\n'
                             f'allow-writer "{program}" 0 "{target}" all\n' + extra)
            stage.chmod(0o600); stage.replace(policy)
        publish(1)
        monitor = stack.enter_context(MonitorRun(build / 'secmon', ['--policy', str(policy), '--control', str(control)]))
        def stop():
            if monitor.process.poll() is None:
                call(build / 'secmon', 'stop', control); monitor.process.wait(timeout=5)
        stack.callback(stop)
        saved = {name: os.getxattr(program, name) for name in os.listxattr(program)}
        for command in 'xdarcei': assert actor.request(command) == errno.EACCES, command
        # An all grant on the executable itself cannot override identity safety.
        publish(2, f'protect "{alias}"\nallow-writer "{program}" 0 "{alias}" all\n')
        call(build / 'secmon', 'reload', control)
        for command in 'xdarcei': assert actor.request(command) == errno.EACCES, command
        assert saved == {name: os.getxattr(program, name) for name in os.listxattr(program)}
        stop(); monitor.stop()
        events = [e for e in monitor.events() if e.get('event') == 'file_denied']
        assert len(events) == 14 and {e['operation'] for e in events} == {16, 17, 18, 19, 20}, events
        assert all(not e['canary_hit'] and not e['response_started'] for e in events)
        print('PASS trusted executable metadata identity: read-only held FD, hardlink, ACL, capabilities and self grant', flush=True)

if __name__ == '__main__': main()
