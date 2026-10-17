# SPDX-License-Identifier: MIT
# 受控生命周期场景的命令/回报同步，避免测试进程提前退出后误读已复用的数字任务身份。
"""Interactive task-lifetime fixture and a traversable temporary executable."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import tempfile
import time

class Scenario:
    def __init__(self, executable):
        self.process = subprocess.Popen([str(executable)], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.buffer = b''

    def phase(self, expected):
        deadline = time.monotonic() + 5
        while b'\n' not in self.buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.process.stdout], [], [], remaining)[0]:
                raise RuntimeError(f'lifecycle scenario stalled before {expected}')
            chunk = os.read(self.process.stdout.fileno(), 4096)
            if not chunk:
                self.process.wait(timeout=1)
                raise RuntimeError(f'lifecycle scenario exited before {expected}: ' +
                                   self.process.stderr.read().decode(errors='replace'))
            self.buffer += chunk
        line, self.buffer = self.buffer.split(b'\n', 1)
        data = json.loads(line)
        assert data['phase'] == expected, data
        assert data['pid'] == self.process.pid, data
        return data

    def command(self, text):
        self.process.stdin.write(text.encode() + b'\n')
        self.process.stdin.flush()

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.process.stdin.close()
        self.process.stdout.close()
        self.process.stderr.close()


def expect_keys(mapping, pid, tids):
    deadline = time.monotonic() + 3
    keys = set()
    while time.monotonic() < deadline:
        keys = mapping.keys_for_group(pid)
        if {tid for tid, _ in keys} == set(tids) and len(keys) == len(tids):
            return keys
        time.sleep(0.01)
    raise AssertionError(f'pid={pid}: expected tids={tids}, observed keys={keys}')



@contextmanager
def lifecycle_helper(build):
    # Never change the checkout/home directory permissions for a dropped UID.
    with tempfile.TemporaryDirectory(prefix='secmon-lifecycle-') as staging:
        Path(staging).chmod(0o755)
        helper = Path(staging) / 'scenario'
        shutil.copyfile(build / 'secmon-lifecycle-scenario', helper)
        helper.chmod(0o755)
        yield helper
