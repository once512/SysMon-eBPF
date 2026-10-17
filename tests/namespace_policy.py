#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# 在私有 mount namespace 验证同一 inode 的绑定别名与新 tmpfs 对象；不更改宿主挂载表或全局 sysctl。
import argparse
from contextlib import contextmanager
import errno
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
from fanotify_harness import GateRun
from monitor_harness import MonitorRun

BIND_PROBE = r'''
import json,os,subprocess,sys
source,alias,read_error,write_error=sys.argv[1:]
subprocess.run(['mount','--bind',source,alias],check=True)
a=os.stat(source+'/target'); b=os.stat(alias+'/target')
assert (a.st_dev,a.st_ino)==(b.st_dev,b.st_ino)
def attempt(flags):
    try:
        fd=os.open(alias+'/target',flags|os.O_CLOEXEC)
    except OSError as error:
        return error.errno
    os.close(fd); return 0
assert attempt(os.O_RDONLY)==int(read_error)
assert attempt(os.O_WRONLY)==int(write_error)
# 邻近未标记对象不因目录别名而被扩大保护。
fd=os.open(alias+'/neighbor',os.O_WRONLY|os.O_CLOEXEC); os.close(fd)
print(json.dumps({'pid':os.getpid(),'dev':b.st_dev,'ino':b.st_ino}))
'''
TMPFS_HELPER = r'''
import json,os,subprocess,sys
root=sys.argv[1]
subprocess.run(['mount','-t','tmpfs','-o','size=1m,nodev,nosuid,noexec','secmon-test',root],check=True)
path=root+'/target'
with open(path,'wb') as out: out.write(b'private tmpfs object')
def attempt(flags):
    try: fd=os.open(path,flags|os.O_CLOEXEC)
    except OSError as error: return error.errno
    os.close(fd); return 0
st=os.stat(path)
print(json.dumps({'pid':os.getpid(),'dev':st.st_dev,'ino':st.st_ino}),flush=True)
for command in sys.stdin:
    if command.strip()=='exit': break
    assert command.strip()=='probe'
    print(json.dumps({'read':attempt(os.O_RDONLY),'write':attempt(os.O_WRONLY)}),flush=True)
'''


def read_json(process, errors):
    ready, _, _ = select.select([process.stdout], [], [], 5)
    if not ready:
        raise RuntimeError('namespace helper response deadline exceeded')
    line = process.stdout.readline()
    if not line:
        errors.seek(0)
        raise RuntimeError('namespace helper exited: ' + errors.read())
    return json.loads(line)


@contextmanager
def tmpfs_namespace(directory):
    with tempfile.TemporaryFile(mode='w+') as errors:
        process = subprocess.Popen(['unshare', '--mount', '--propagation', 'private', '--',
                                    sys.executable, '-u', '-c', TMPFS_HELPER, str(directory)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors, text=True)
        try:
            identity = read_json(process, errors)
            assert identity['pid'] == process.pid
            yield process, errors, identity
        finally:
            if process.poll() is None:
                try:
                    process.stdin.write('exit\n')
                    process.stdin.flush()
                    process.wait(timeout=5)
                except (BrokenPipeError, subprocess.TimeoutExpired):
                    process.kill()
                    process.wait(timeout=5)
            process.stdin.close()
            process.stdout.close()
            errors.seek(0)
            assert process.returncode == 0, errors.read()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', default='build')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('requires root/BPF/fanotify and mount-namespace permissions')
    build = Path(args.build_dir).resolve()
    with tempfile.TemporaryDirectory(prefix='secmon-namespaces-') as temporary:
        root = Path(temporary)
        source, alias, private = [root / name for name in ('source', 'alias', 'private')]
        for directory in (source, alias, private):
            directory.mkdir()
        target = source / 'target'
        target.write_bytes(b'original')
        (source / 'neighbor').write_bytes(b'other')
        identity = target.stat()

        def bind_probe(read_error, write_error):
            probe = subprocess.run(['unshare', '--mount', '--propagation', 'private', '--', sys.executable,
                                    '-c', BIND_PROBE, str(source), str(alias), str(read_error), str(write_error)],
                                   capture_output=True, text=True, timeout=10)
            assert probe.returncode == 0, probe.stderr
            observed = json.loads(probe.stdout)
            assert (observed['dev'], observed['ino']) == (identity.st_dev, identity.st_ino)
            assert not (alias / 'target').exists(), 'bind mount escaped its private mount namespace'

        with MonitorRun(build / 'secmon', ['--protect-file', str(target)]):
            gate = GateRun(build / 'secmon-fanotify', target, 'deny', [])
            try:
                bind_probe(errno.EPERM, errno.EACCES)
            finally:
                gate.finish()
            bind_probe(0, errno.EACCES)
        gate = GateRun(build / 'secmon-fanotify', target, 'deny', [])
        try:
            bind_probe(errno.EPERM, errno.EPERM)
        finally:
            gate.finish()
        bind_probe(0, 0)
        print('PASS private bind aliases preserve BPF/fanotify inode identity and independent layer cleanup')

        with tmpfs_namespace(private) as (process, errors, expected):
            pinned_path = Path(f'/proc/{process.pid}/root') / str(private / 'target').lstrip('/')
            assert not (private / 'target').exists(), 'private tmpfs leaked into the host mount table'
            actual = pinned_path.stat()
            assert (actual.st_dev, actual.st_ino) == (expected['dev'], expected['ino'])
            assert actual.st_dev != identity.st_dev, 'tmpfs must exercise a distinct device identity'

            def probe(read_error, write_error):
                process.stdin.write('probe\n')
                process.stdin.flush()
                assert read_json(process, errors) == {'read': read_error, 'write': write_error}

            probe(0, 0)
            with MonitorRun(build / 'secmon', ['--protect-file', str(pinned_path)]):
                gate = GateRun(build / 'secmon-fanotify', pinned_path, 'deny', [])
                try:
                    probe(errno.EPERM, errno.EACCES)
                finally:
                    gate.finish()
                probe(0, errno.EACCES)
            probe(0, 0)
        assert not (private / 'target').exists()
        print('PASS private tmpfs pinned through proc root; device/inode matching and mount namespace cleanup')


if __name__ == '__main__':
    main()
