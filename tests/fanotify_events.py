#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare open, read and direct-execution permission coverage on temporary files."""
import argparse
import errno
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from fanotify_harness import start, stop


def operation(path, action, inherited=-1):
    code = '''import mmap, os, sys
try:
    action = sys.argv[2]
    if action == 'inherited-read':
        os.read(int(sys.argv[3]), 4)
    elif action == 'open':
        fd = os.open(sys.argv[1], os.O_RDONLY)
        os.close(fd)
    else:
        fd = os.open(sys.argv[1], os.O_RDONLY)
        try:
            if action == 'read':
                os.read(fd, 4)
            elif action == 'mmap':
                with mmap.mmap(fd, 0, access=mmap.ACCESS_READ) as view:
                    assert view[0] >= 0
        finally:
            os.close(fd)
except OSError as error:
    print(error.errno)
else:
    print(0)
'''
    result = subprocess.run(['python3', '-c', code, str(path), action, str(inherited)],
                            pass_fds=(inherited,) if inherited >= 0 else (),
                            capture_output=True, text=True, check=True, timeout=5)
    return int(result.stdout)


def execute(argv):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=5)
    except OSError as error:
        return error.errno
    assert result.returncode == 0, result.stderr
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', default='build')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('requires root/CAP_SYS_ADMIN')
    binary = (Path(args.build_dir) / 'secmon-fanotify').resolve()
    with tempfile.TemporaryDirectory(prefix='secmon-event-kinds-') as temporary:
        directory = Path(temporary)
        target = directory / 'data'
        target.write_bytes(b'permission data')
        for decision in ('allow', 'deny'):
            expected = 0 if decision == 'allow' else errno.EPERM
            fd = os.open(target, os.O_RDWR | os.O_CLOEXEC)
            try:
                with tempfile.TemporaryFile(mode='w+') as output, tempfile.TemporaryFile(mode='w+') as errors:
                    listener = start(binary, target, decision, output, errors, extra=['--event', 'access'])
                    try:
                        assert operation(target, 'open') == 0
                        assert operation(target, 'inherited-read', fd) == expected
                        assert operation(target, 'read') == expected
                        # Read permission events do not cover memory-mapped access or writes.
                        assert operation(target, 'mmap') == 0
                        assert os.pwrite(fd, b'P', 0) == 1
                    finally:
                        stop(listener)
                    assert listener.returncode == 0
                    output.seek(0)
                    stats = json.load(output)
                    assert stats['permission_event'] == 'access'
                    assert stats['allowed' if decision == 'allow' else 'denied'] == 2
                    assert stats['overflow'] == 0
                    print(f'PASS access {decision}: new/inherited reads, open/write/mmap boundaries')
            finally:
                os.close(fd)
        executable = directory / 'true'
        shutil.copyfile('/usr/bin/true', executable)
        executable.chmod(0o755)
        script = directory / 'script.sh'
        script.write_text('#!/bin/sh\nexit 0\n')
        script.chmod(0o755)
        for target in (executable, script):
            for decision in ('allow', 'deny'):
                with tempfile.TemporaryFile(mode='w+') as output, tempfile.TemporaryFile(mode='w+') as errors:
                    listener = start(binary, target, decision, output, errors, extra=['--event', 'exec'])
                    try:
                        assert operation(target, 'open') == 0
                        assert operation(target, 'read') == 0
                        assert execute([str(target)]) == (0 if decision == 'allow' else errno.EPERM)
                        if target == script:
                            # Interpreter reading a script is not a direct exec of that file.
                            assert execute(['/bin/sh', str(script)]) == 0
                    finally:
                        stop(listener)
                    assert listener.returncode == 0
                    output.seek(0)
                    stats = json.load(output)
                    assert stats['permission_event'] == 'exec'
                    assert stats['allowed' if decision == 'allow' else 'denied'] >= 1
                    assert stats['denied' if decision == 'allow' else 'allowed'] == 0
                    assert stats['overflow'] == 0
                    print(f'PASS exec {decision}: {target.name}, ordinary read and interpreter boundaries')
        assert execute([str(executable)]) == execute([str(script)]) == 0
        print('PASS event-specific marks removed on exit')


if __name__ == '__main__':
    main()
