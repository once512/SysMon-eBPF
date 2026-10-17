# SPDX-License-Identifier: MIT
"""Temporary-process helpers shared by privileged fanotify experiments."""
import subprocess
import time

def start(binary, path, decision, output, errors, seconds=20, extra=()):
    process = subprocess.Popen([str(binary), '--file', str(path), '--decision', decision,
                                '--run-for', str(seconds), *extra], stdout=output, stderr=errors)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        errors.flush()
        errors.seek(0)
        if 'Fanotify active;' in errors.read():
            return process
        if process.poll() is not None:
            raise RuntimeError('fanotify startup failed; check kernel/filesystem permissions')
        time.sleep(0.02)
    process.kill()
    process.wait(timeout=5)
    raise RuntimeError('fanotify startup timed out')


def open_errno(path):
    # A separate process bounds blocking syscalls if the listener regresses.
    code = '''import os, sys
try:
    fd = os.open(sys.argv[1], os.O_RDONLY)
    os.close(fd)
except OSError as error:
    print(error.errno)
else:
    print(0)
'''
    result = subprocess.run(['python3', '-c', code, str(path)], capture_output=True,
                            text=True, timeout=5, check=True)
    return int(result.stdout)


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
            raise

