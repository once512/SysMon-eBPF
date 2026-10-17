#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# 同一配置的真实两层裁决：writer 例外不能覆盖 fanotify deny，fanotify allow 也不能覆盖撤销后的 BPF。
# 特别区分新 open 和预先存在的 FD：open 权限门不撤销已有写 FD，BPF file_permission 才执行普通写检查。
import argparse
import errno
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from fanotify_policy import running
from management_harness import call
from monitor_harness import MonitorRun
from writer_harness import WriterProcess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', default='build')
    args = parser.parse_args()
    assert os.geteuid() == 0
    build = Path(args.build_dir).resolve()
    with tempfile.TemporaryDirectory(prefix='secmon-writer-layers-') as tmp:
        root = Path(tmp)
        root.chmod(0o700)
        trusted, other, target = (root / p for p in ('trusted', 'other', 'data'))
        for path in (trusted, other):
            shutil.copyfile(build / 'secmon-writer-scenario', path)
            path.chmod(0o755)
        target.write_bytes(b'data')
        config, bpf_socket, fan_socket = (root / p for p in ('policy', 'bpf.sock', 'fan.sock'))

        def publish(revision, decision, writer):
            stage = root / 'staging'
            stage.write_text(f'revision {revision}\nprotect "{target}"\n' +
                             (f'allow-writer "{trusted}" 0\n' if writer else '') +
                             f'fanotify-file "{target}"\nfanotify-decision {decision}\n')
            stage.chmod(0o600)
            stage.replace(config)

        def attempt(exe, expected):
            result = subprocess.run([str(exe), 'write', str(target)], capture_output=True, timeout=5)
            assert result.returncode == expected, (result.returncode, expected, result.stderr)

        publish(1, 'deny', True)
        with WriterProcess(trusted, target) as live, WriterProcess(other, target) as outsider, \
                MonitorRun(build / 'secmon', ['--policy', str(config), '--self-protect', str(bpf_socket)]) as monitor:
            try:
                with running(build / 'secmon', config, fan_socket):
                    # BPF 的允许只表示本层不拒绝；open 门独立返回 EPERM。
                    attempt(trusted, errno.EPERM)
                    assert live.request() == 0 and outsider.request() == errno.EACCES
                    publish(2, 'allow', True)
                    assert call(build / 'secmon', 'reload', fan_socket)['revision'] == 2
                    attempt(trusted, 0)
                    attempt(other, errno.EACCES)
                    assert call(build / 'secmon', 'reload', bpf_socket)['writer_paths'] == 1
                    publish(3, 'allow', False)
                    assert call(build / 'secmon', 'reload', bpf_socket)['writer_paths'] == 0
                    attempt(trusted, errno.EACCES)
                    assert live.request() == outsider.request() == errno.EACCES
                    call(build / 'secmon', 'reload', fan_socket)
                    result = subprocess.run([str(build / 'secmon-policyctl'), '--socket', str(bpf_socket), '--expect-revision', '3'],
                                            capture_output=True, text=True, check=True, timeout=5)
                    assert json.loads(result.stdout)['code'] == 'ok'
                    publish(4, 'deny', False)
                    call(build / 'secmon', 'reload', fan_socket)
                    # 独立停止 BPF 后 open 门仍拒绝，而现有 FD 写入恢复；不是 fanotify 失效。
                    subprocess.run([str(build / 'secmon'), '--stop', str(bpf_socket)], check=True,
                                   capture_output=True, timeout=5)
                    monitor.process.wait(timeout=5)
                    attempt(trusted, errno.EPERM)
                    attempt(other, errno.EPERM)
                    assert live.request() == outsider.request() == 0
                attempt(trusted, 0)
                attempt(other, 0)
            finally:
                if monitor.process.poll() is None:
                    subprocess.run([str(build / 'secmon'), '--stop', str(bpf_socket)], check=True,
                                   capture_output=True, timeout=5)
                    monitor.process.wait(timeout=5)
        print('PASS shared config, independent BPF/fanotify decisions, revoke, consistency and existing-FD boundary')


if __name__ == '__main__':
    main()
