#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# 真实同进程双模块：联合重载、准备失败/忙队列回滚、分析器隔离以及启动失败后的资源回收。
import argparse
import errno
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
from fanotify_harness import begin_open, finish_open, open_errno
from management_harness import call
from service_harness import running_service


def write_errno(path):
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CLOEXEC)
    except OSError as error:
        return error.errno
    os.close(fd)
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', default='build')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('requires root/BPF/fanotify permissions')
    build = Path(args.build_dir).resolve()
    binary = build / 'secmon'
    with tempfile.TemporaryDirectory(prefix='secmon-one-service-') as temporary:
        root = Path(temporary)
        a, b, target, config, control = [root / name for name in ('a', 'b', 'target', 'policy', 'control')]
        for path in (a, b, target):
            path.write_bytes(b'clean')

        def publish(revision, protected=a, decision='allow', delay=0, event='open', analyzer=False, fallback='deny', include_gate=True):
            text = f'revision {revision}\nprotect "{protected}"\n'
            if include_gate:
                text += f'fanotify-file "{target}"\nfanotify-event {event}\nfanotify-timeout-ms 5000\n'
                text += (f'fanotify-analyzer "{build / "secmon-analyzer"}"\nfanotify-marker "BLOCK"\nfanotify-error-decision {fallback}\n'
                         if analyzer else f'fanotify-decision {decision}\nfanotify-delay-ms {delay}\n')
            stage = root / 'staging'
            stage.write_text(text)
            os.chmod(stage, 0o600)
            stage.replace(config)

        publish(1)
        with running_service(build, config, control) as (process, output, errors):
            initial = call(binary, 'status', control)
            assert initial['backend'] == 'combined' and initial['pid'] == process.pid
            assert initial['self_protected'] and initial['protected_paths'] == 1
            assert write_errno(a) == errno.EACCES and write_errno(b) == 0
            assert open_errno(target) == 0
            # BPF 候选准备失败时，fanotify 不得提前从 allow 变成 deny。
            publish(2, root / 'missing', 'deny')
            call(binary, 'reload', control, 'prepare_failed')
            assert open_errno(target) == 0 and write_errno(a) == errno.EACCES
            assert call(binary, 'status', control)['revision'] == 1
            # 固定后端检查失败时，BPF 不得先把保护对象从 a 切成 b。
            publish(2, b, 'deny', event='access')
            call(binary, 'reload', control, 'restart_required')
            assert write_errno(a) == errno.EACCES and write_errno(b) == 0
            publish(2, b, 'deny')
            updated = call(binary, 'reload', control)
            assert updated['pid'] == process.pid and updated['revision'] == 2
            assert updated['decision'] == 'deny' and updated['protected_paths'] == 1
            assert write_errno(a) == 0 and write_errno(b) == errno.EACCES
            assert open_errno(target) == errno.EPERM
            # 空闲更新到延迟允许，接入旧请求后拒绝联合更新；两模块都维持旧合同。
            publish(3, a, 'allow', delay=600)
            call(binary, 'reload', control)
            opener = begin_open(target)
            try:
                deadline = time.monotonic() + 2
                while call(binary, 'status', control)['pending'] == 0:
                    assert time.monotonic() < deadline
                publish(4, b, 'deny')
                call(binary, 'reload', control, 'busy')
                assert write_errno(a) == errno.EACCES and write_errno(b) == 0
                assert finish_open(opener) == 0
            finally:
                if opener.poll() is None:
                    opener.kill()
                    opener.wait(timeout=5)
            call(binary, 'reload', control)
            assert open_errno(target) == errno.EPERM
            assert write_errno(a) == 0 and write_errno(b) == errno.EACCES
            # 配置自身与 mark 同 inode 时必须在读入前拒绝，不能等待自己回复。
            config.unlink()
            os.link(target, config)
            call(binary, 'reload', control, 'invalid_policy')
            publish(5, a, include_gate=False)
            call(binary, 'reload', control, 'restart_required')
            assert write_errno(b) == errno.EACCES
            # 交替更新并检查每次管理确认后的两个模块，不用背景请求推测跨钩子原子性。
            for revision in range(5, 17):
                odd = revision % 2
                publish(revision, a if odd else b, 'allow' if odd else 'deny')
                reply = call(binary, 'reload', control)
                assert reply['revision'] == revision and reply['pid'] == process.pid
                assert write_errno(a) == (errno.EACCES if odd else 0)
                assert write_errno(b) == (0 if odd else errno.EACCES)
                assert open_errno(target) == (0 if odd else errno.EPERM)
            # 自保护确实覆盖整个联合服务；root 外部信号不能绕过管理停止。
            try:
                os.kill(process.pid, signal.SIGTERM)
            except PermissionError:
                pass
            else:
                raise AssertionError('combined service lost BPF self protection')
        assert write_errno(a) == write_errno(b) == 0 and open_errno(target) == 0
        print('PASS same-process modules, unified status/reload, busy/prepare rollback, restart boundary and coordinated shutdown')

        # 分析器仍为单独的降权进程；其失败只改变 fanotify 回退，不卸载 BPF。
        publish(20, a, analyzer=True)
        with running_service(build, config, control) as (process, output, errors):
            reply = call(binary, 'status', control)
            worker = reply['analyzer_pid']
            assert worker > 0 and worker != process.pid and reply['analyzer_online']
            assert open_errno(target) == 0 and write_errno(a) == errno.EACCES
            os.kill(worker, signal.SIGKILL)
            assert open_errno(target) == errno.EPERM
            publish(21, b, analyzer=True, fallback='allow')
            call(binary, 'reload', control)
            assert open_errno(target) == 0
            assert write_errno(a) == 0 and write_errno(b) == errno.EACCES
        print('PASS separate analyzer failure/fallback while BPF and fanotify remain in the same main process')

        # fanotify 第二阶段启动失败时，先创建的 BPF 资源必须自动卸载，socket 必须移除。
        publish(30)
        config.write_text(config.read_text().replace(str(target), str(root / 'missing')))
        result = subprocess.run([str(binary), '--policy', str(config), '--control', str(control), '--run-for', '2'],
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 1 and 'Service active;' not in result.stderr, result.stderr
        assert not control.exists() and write_errno(a) == 0
        # 未启动 fanotify 的主服务不能通过在线更新偷偷新增 mark/工作进程。
        publish(40, include_gate=False)
        with running_service(build, config, control):
            publish(41)
            call(binary, 'reload', control, 'restart_required')
            assert call(binary, 'status', control)['backend'] == 'bpf'
        print('PASS failed-start cleanup and explicit restart requirement for enabling/disabling a module')


if __name__ == '__main__':
    main()
