#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# 真实双后端核对：磁盘候选不等于活动策略，版本相等但摘要不同仍需报告分歧；工具不发重载命令。
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
from fanotify_policy import running
from management_harness import call
from monitor_harness import MonitorRun


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', default='build')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('requires root/BPF/fanotify and control-service permissions')
    build = Path(args.build_dir).resolve()
    bpf, fan, checker = [build / name for name in ('secmon', 'secmon-fanotify', 'secmon-policyctl')]
    with tempfile.TemporaryDirectory(prefix='secmon-consistency-') as temporary:
        root = Path(temporary)
        protected, target = root / 'protected', root / 'gate'
        protected.write_bytes(b'protected')
        target.write_bytes(b'clean')
        config, bpf_socket, fan_socket = [root / name for name in ('policy', 'bpf.sock', 'fan.sock')]

        def publish(revision, comment='common'):
            stage = root / 'staging'
            stage.write_text(f'# {comment}\nversion 2\nrevision {revision}\nprotect "{protected}"\n'
                             f'fanotify-file "{target}"\nfanotify-decision allow\n')
            os.chmod(stage, 0o600)
            stage.replace(config)

        def check(code='consistent', expected=None, reverse=False, missing=False):
            command = [str(checker), '--bpf-socket', str(fan_socket if reverse else bpf_socket),
                       '--fanotify-socket', str(root / 'missing' if missing else (bpf_socket if reverse else fan_socket))]
            if expected is not None:
                command += ['--expect-revision', str(expected)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=15)
            assert result.returncode == (0 if code == 'consistent' else 1), (code, result.stdout, result.stderr)
            status = json.loads(result.stdout)
            assert status['code'] == code and status['scope'] == 'active_configuration_bytes', status
            return status

        publish(1)
        with MonitorRun(bpf, ['--policy', str(config), '--self-protect', str(bpf_socket)], seconds=120) as monitor:
            try:
                with running(fan, config, fan_socket) as (process, output, errors):
                    base = len(list(Path(f'/proc/{process.pid}/fd').iterdir()))
                    first = check(expected=1)
                    assert first['bpf']['revision'] == first['fanotify']['revision'] == 1
                    publish(2)
                    check(expected=1)  # 仍是共同的活动 v1，不读取刚发布的候选 v2。
                    check('unexpected_revision', expected=2)
                    call(bpf, 'reload', bpf_socket)
                    check('revision_mismatch')
                    call(fan, 'reload', fan_socket)
                    check(expected=2)
                    publish(3, 'first backend source')
                    call(bpf, 'reload', bpf_socket)
                    publish(3, 'second backend source')
                    call(fan, 'reload', fan_socket)
                    different = check('source_mismatch')
                    assert different['bpf']['revision'] == different['fanotify']['revision'] == 3
                    assert different['bpf']['source_sha256'] != different['fanotify']['source_sha256']
                    publish(4)
                    call(bpf, 'reload', bpf_socket)
                    call(fan, 'reload', fan_socket)
                    stable = check(expected=4)
                    check('wrong_backend', reverse=True)
                    check('transport_error', missing=True)
                    for _ in range(3):
                        unchanged = check()
                        assert unchanged['bpf']['reloads'] == stable['bpf']['reloads']
                        assert unchanged['fanotify']['rejections'] == stable['fanotify']['rejections']
                        assert len(list(Path(f'/proc/{process.pid}/fd').iterdir())) == base
            finally:
                subprocess.run([str(bpf), '--stop', str(bpf_socket)], check=True, capture_output=True, timeout=5)
                monitor.process.wait(timeout=5)
    print('PASS read-only double collection, active revisions/digests, expected version, role checks and FD recovery')


if __name__ == '__main__':
    main()
