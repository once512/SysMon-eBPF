# SPDX-License-Identifier: MIT
# 单主进程测试工具：等待两个对象均就绪，以授权命令停止自保护服务并保存审计/诊断。
from contextlib import contextmanager
from pathlib import Path
import subprocess
import tempfile
import time
from management_harness import call

@contextmanager
def running_service(build, config, control, extra=(), seconds=60):
    binary = Path(build) / 'secmon'
    with tempfile.TemporaryFile(mode='w+') as output, tempfile.TemporaryFile(mode='w+') as errors:
        process = subprocess.Popen([str(binary), '--policy', str(config), '--control', str(control),
                                    '--run-for', str(seconds), *extra], stdout=output, stderr=errors)
        try:
            deadline = time.monotonic() + 10
            while True:
                errors.seek(0)
                text = errors.read()
                if 'Service active;' in text:
                    break
                assert process.poll() is None, text
                assert time.monotonic() < deadline, text
                time.sleep(0.01)
            yield process, output, errors
        finally:
            if process.poll() is None:
                call(binary, 'stop', control)
                process.wait(timeout=10)
            errors.seek(0)
            assert process.returncode == 0, errors.read()
        assert not Path(control).exists()
