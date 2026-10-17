# SPDX-License-Identifier: MIT
"""Temporary-process helpers shared by privileged fanotify experiments."""
import subprocess
import tempfile
import json
import select
import time

def start(binary, path, decision, output, errors, seconds=20, extra=()):
    command = [str(binary), '--file', str(path), '--run-for', str(seconds), *extra]
    if decision is not None:
        command += ['--decision', decision]
    process = subprocess.Popen(command, stdout=output, stderr=errors)
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


class GateRun:
    def __init__(self, binary, path, decision, extra, seconds=20):
        self.output = tempfile.TemporaryFile(mode='w+')
        self.errors = tempfile.TemporaryFile(mode='w+')
        try:
            self.process = start(binary, path, decision, self.output, self.errors,
                                 seconds=seconds, extra=extra)
        except BaseException:
            self.output.close()
            self.errors.close()
            raise

    def finish(self):
        try:
            stop(self.process)
            self.errors.seek(0)
            assert self.process.returncode == 0, self.errors.read()
            self.output.seek(0)
            return json.load(self.output)
        finally:
            self.output.close()
            self.errors.close()


def begin_open(path):
    code = '''import errno, os, sys
print('ready', flush=True)
try:
    fd = os.open(sys.argv[1], os.O_RDONLY)
    os.close(fd)
except OSError as error:
    print(error.errno, flush=True)
else:
    print(0, flush=True)
'''
    process = subprocess.Popen(['python3', '-c', code, str(path)], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    readable, _, _ = select.select([process.stdout], [], [], 5)
    if not readable or process.stdout.readline().strip() != 'ready':
        process.kill()
        process.wait(timeout=5)
        raise RuntimeError('opener did not become ready')
    return process


def finish_open(process):
    output, error = process.communicate(timeout=5)
    assert process.returncode == 0, error
    return int(output)

