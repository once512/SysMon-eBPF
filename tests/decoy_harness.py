# SPDX-License-Identifier: MIT
"""Foreground virtual view with explicit mount ownership and cleanup."""
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time


def mounted(path):
    # mountinfo is readable without asking a potentially failed FUSE server.
    def unescape(value):
        for old, new in ((r'\040', ' '), (r'\011', '\t'), (r'\012', '\n'), (r'\134', '\\')):
            value = value.replace(old, new)
        return value
    return any(unescape(line.split()[4]) == str(path)
               for line in Path('/proc/self/mountinfo').read_text().splitlines())


class DecoyView:
    def __init__(self, binary, mountpoint, names=('accounts.csv', 'notes.txt'), allow_other=False):
        self.mountpoint = Path(mountpoint)
        self.names = names
        self.errors = tempfile.TemporaryFile(mode='w+')
        self.process = None
        args = [str(binary), '--mountpoint', str(mountpoint)]
        for name in names:
            args += ['--file', name]
        if allow_other:
            args += ['--allow-other']
        try:
            self.process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=self.errors)
            until = time.monotonic() + 5
            while not mounted(self.mountpoint):
                if self.process.poll() is not None or time.monotonic() >= until:
                    self.errors.seek(0)
                    raise RuntimeError('view mount failed: ' + self.errors.read())
                time.sleep(.01)
            # Complete INIT/lookup through a bounded process, rather than block
            # this controlling process if a filesystem regression hangs.
            subprocess.run(['stat', str(self.mountpoint / names[0])],
                           capture_output=True, check=True, timeout=5)
        except BaseException:
            self.close()
            raise

    def close(self):
        try:
            if self.process is not None and self.process.poll() is None:
                self.process.send_signal(signal.SIGCONT)
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=5)
                    raise
            if mounted(self.mountpoint):
                subprocess.run(['fusermount3', '-uz', str(self.mountpoint)], check=True,
                               capture_output=True, timeout=5)
            if self.process is not None:
                assert self.process.returncode in (0, -signal.SIGKILL), self.process.returncode
        finally:
            self.errors.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
