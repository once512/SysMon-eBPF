# SPDX-License-Identifier: MIT
# 临时 BPF 宿主的启动、日志与退出工具；自保护服务不能仅依赖外部信号，需先走授权停止并等待退出。
"""Short-lived audit host used by privileged component-composition tests."""
import json
import subprocess
import tempfile
import time


class MonitorRun:
    def __init__(self, binary, extra=(), seconds=60):
        self.output = tempfile.TemporaryFile(mode='w+')
        self.errors = tempfile.TemporaryFile(mode='w+')
        self.process = None
        try:
            self.process = subprocess.Popen([str(binary), '--run-for', str(seconds), *extra],
                                            stdout=self.output, stderr=self.errors)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                diagnostics = self.diagnostics()
                if 'Audit active;' in diagnostics:
                    return
                if self.process.poll() is not None:
                    raise RuntimeError('audit startup failed:\n' + diagnostics)
                time.sleep(0.02)
            raise RuntimeError('audit startup timed out:\n' + self.diagnostics())
        except BaseException:
            self.close()
            raise

    def stop(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
                raise
        if self.process is not None and self.process.returncode != 0:
            raise RuntimeError('audit failed:\n' + self.diagnostics())

    def diagnostics(self):
        self.errors.seek(0)
        return self.errors.read()

    def events(self):
        if self.process.poll() is None:
            raise RuntimeError('stop the audit host before inspecting buffered events')
        self.output.seek(0)
        return [json.loads(line) for line in self.output.read().splitlines()]

    def close(self):
        try:
            self.stop()
        finally:
            self.output.close()
            self.errors.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
