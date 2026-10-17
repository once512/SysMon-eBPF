#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# 一个主进程的一份活动快照：磁盘候选不影响查询，统一提交后两个模块共享 revision/摘要。
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from management_harness import call
from service_harness import running_service


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', default='build')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('requires root/BPF/fanotify permissions')
    build = Path(args.build_dir).resolve()
    binary, checker = build / 'secmon', build / 'secmon-policyctl'
    with tempfile.TemporaryDirectory(prefix='secmon-single-source-') as temporary:
        root = Path(temporary)
        protected, target, config, control = [root / name for name in ('protected', 'target', 'policy', 'control')]
        protected.write_bytes(b'protected')
        target.write_bytes(b'clean')

        def publish(revision):
            text = f'revision {revision}\nprotect "{protected}"\nfanotify-file "{target}"\nfanotify-decision allow\n'
            stage = root / 'staging'
            stage.write_text(text)
            os.chmod(stage, 0o600)
            stage.replace(config)
            return hashlib.sha256(text.encode()).hexdigest()

        def check(code='ok', expected=None, missing=False):
            command = [str(checker), '--socket', str(root / 'missing' if missing else control)]
            if expected is not None:
                command += ['--expect-revision', str(expected)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=5)
            assert result.returncode == (0 if code == 'ok' else 1), (result.stdout, result.stderr)
            reply = json.loads(result.stdout)
            assert reply['code'] == code, reply
            return reply.get('status')

        first_digest = publish(1)
        with running_service(build, config, control) as (process, output, errors):
            first = check(expected=1)
            assert first['backend'] == 'combined' and first['pid'] == process.pid
            assert first['source_sha256'] == first_digest
            assert first['protected_paths'] == 1 and first['decision'] == 'allow'
            digest = publish(2)
            unchanged = check(expected=1)  # 只读查询不会加载磁盘上的新候选。
            assert unchanged['reloads'] == 0 and unchanged['source_sha256'] == first_digest
            check('unexpected_revision', expected=2)
            updated = call(binary, 'reload', control)
            assert updated['revision'] == 2 and updated['source_sha256'] == digest
            assert updated['instance_ns'] == first['instance_ns'] and updated['pid'] == process.pid
            for _ in range(5):
                reply = check(expected=2)
                assert reply['reloads'] == 1 and reply['rejections'] == 0
                assert reply['source_sha256'] == digest
            check('transport_error', missing=True)
        # 非配置模式仍可查询状态，但核对工具明确报告 unconfigured。
        result = subprocess.run([str(checker), '--bpf-socket', str(control), '--fanotify-socket', str(control)],
                                capture_output=True, timeout=5)
        assert result.returncode == 2
    print('PASS single-process snapshot, active source digest, unified reload, read-only policy check and obsolete CLI rejection')


if __name__ == '__main__':
    main()
