# SPDX-License-Identifier: MIT
# 用管道驱动始终不 exec 的原生进程；每条命令有截止时间，验证预先打开的 FD 在重载后重新受检查。
import selectors
import subprocess


class WriterProcess:
    def __init__(self, binary, target):
        self.process = subprocess.Popen([str(binary), 'serve', str(target)], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        try:
            assert self.read() == 'ready'
        except BaseException:
            self.close()
            raise

    def read(self):
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            assert selector.select(5), ('writer deadline', self.process.pid)
        line = self.process.stdout.readline()
        assert line, ('writer EOF', self.process.poll())
        return line.strip()

    def request(self, command='w'):
        self.process.stdin.write(command + '\n')
        self.process.stdin.flush()
        return int(self.read())

    def close(self):
        try:
            if self.process.poll() is None:
                try:
                    self.process.stdin.write('q\n')
                    self.process.stdin.flush()
                    self.process.wait(timeout=5)
                except (BrokenPipeError, subprocess.TimeoutExpired):
                    self.process.kill()
                    self.process.wait(timeout=5)
            assert self.process.returncode == 0, self.process.stderr.read()
        finally:
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                stream.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
