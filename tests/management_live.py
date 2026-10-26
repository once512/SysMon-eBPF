#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# 真实双后端状态/结构化错误回归：查询只读内存，重载失败保留活动版本及原请求合同。
import argparse
import array
import errno
import hashlib
import json
import os
from pathlib import Path
import socket
import signal
import subprocess
import sys
import tempfile
import time
from fanotify_harness import begin_open, finish_open, open_errno
from fanotify_policy import running
from monitor_harness import MonitorRun
from management_harness import call


def raw(control, data, fds=()):
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
        client.settimeout(3)
        client.connect(str(control))
        ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', fds))] if fds else []
        client.sendmsg([data], ancillary)
        return client.recv(512)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', default='build')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('requires root/BPF/fanotify permissions')
    build = Path(args.build_dir).resolve()
    bpf, fan = build / 'secmon', build / 'secmon'
    with tempfile.TemporaryDirectory(prefix='secmon-management-') as temporary:
        root = Path(temporary)
        a, c, target = [root / name for name in ('protected-a', 'protected-c', 'gate')]
        for path in (a, c, target):
            path.write_bytes(b'original')
        config, bpf_socket, gate_socket = [root / name for name in ('policy', 'bpf.sock', 'gate.sock')]

        def publish(revision, paths=(a,), decision='allow', delay=0, event='open'):
            stage = root / 'staging'
            stage.write_text(f'revision {revision}\n' + ''.join(f'protect "{p}"\n' for p in paths) +
                             f'fanotify-file "{target}"\nfanotify-decision {decision}\nfanotify-event {event}\n'
                             f'fanotify-delay-ms {delay}\nfanotify-timeout-ms 5000\n')
            os.chmod(stage, 0o600)
            stage.replace(config)

        publish(1)
        with MonitorRun(bpf, ['--policy', str(config), '--self-protect', str(bpf_socket)], seconds=120) as monitor:
            try:
                with running(fan, config, gate_socket) as (process, output, errors):
                    initial_bpf = call(bpf, 'status', bpf_socket)
                    initial_fan = call(fan, 'status', gate_socket)
                    assert initial_bpf['pid'] == monitor.process.pid and initial_bpf['protected_paths'] == 1
                    assert initial_bpf['self_protected'] and initial_bpf['configured']
                    assert initial_fan['pid'] == process.pid and initial_fan['pending'] == 0
                    assert initial_fan['decision'] == 'allow' and initial_fan['timeout_ms'] == 5000
                    assert initial_bpf['revision'] == initial_fan['revision'] == 1
                    digest = hashlib.sha256(config.read_bytes()).hexdigest()
                    assert initial_bpf['source_sha256'] == initial_fan['source_sha256'] == digest
                    # 即使磁盘配置损坏/消失，status 仍报告实际已提交的内存版本。
                    config.write_text('broken\n')
                    for binary, control in ((bpf, bpf_socket), (fan, gate_socket)):
                        snapshot = call(binary, 'status', control)
                        assert snapshot['revision'] == 1 and snapshot['rejections'] == 0
                        assert snapshot['source_sha256'] == digest
                        rejected = call(binary, 'reload', control, 'invalid_policy')
                        assert rejected['revision'] == 1 and rejected['last_attempt_revision'] == 0
                        config.unlink(missing_ok=True)
                        assert call(binary, 'status', control)['last_code'] == 'invalid_policy'
                        config.write_text('broken\n')
                    publish(1)
                    assert call(bpf, 'reload', bpf_socket, 'not_newer')['last_attempt_revision'] == 1
                    assert call(fan, 'reload', gate_socket, 'not_newer')['last_attempt_revision'] == 1
                    publish(2, (a, root / 'missing'))
                    failed = call(bpf, 'reload', bpf_socket, 'prepare_failed')
                    assert failed['revision'] == 1 and failed['protected_paths'] == 1
                    publish(3, (a, c), decision='deny')
                    assert call(bpf, 'reload', bpf_socket)['revision'] == 3
                    assert call(fan, 'status', gate_socket)['revision'] == 1  # 无跨进程提交事务。
                    changed = call(fan, 'reload', gate_socket)
                    assert changed['revision'] == 3 and changed['decision'] == 'deny'
                    assert changed['source_sha256'] == hashlib.sha256(config.read_bytes()).hexdigest()
                    assert open_errno(target) == errno.EPERM
                    publish(4, (a, c), event='access')
                    assert call(fan, 'reload', gate_socket, 'restart_required')['revision'] == 3
                    publish(4, (a, c), delay=1500)
                    call(fan, 'reload', gate_socket)
                    opener = begin_open(target)
                    try:
                        deadline = time.monotonic() + 1
                        while True:
                            pending = call(fan, 'status', gate_socket)
                            if pending['pending'] == 1:
                                break
                            assert time.monotonic() < deadline
                        assert pending['revision'] == 4 and pending['decision'] == 'allow'
                        publish(5, (a,), decision='deny')
                        busy = call(fan, 'reload', gate_socket, 'busy')
                        assert busy['revision'] == 4 and busy['last_attempt_revision'] == 5
                        assert busy['pending'] == 1
                        assert finish_open(opener) == 0
                    finally:
                        if opener.poll() is None:
                            opener.kill()
                            opener.wait(timeout=5)
                    assert call(fan, 'reload', gate_socket)['revision'] == 5
                    base = len(list(Path(f'/proc/{process.pid}/fd').iterdir()))
                    held = os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC)
                    try:
                        for message, fds in ((b'unknown', ()), (b'status-extra', ()),
                                             (b'status' + b'x' * 64, ()),
                                             (b'status', (held,)), (b'status', (held,) * 9)):
                            assert raw(gate_socket, message, fds) == b''
                            assert call(fan, 'status', gate_socket)['revision'] == 5
                            assert len(list(Path(f'/proc/{process.pid}/fd').iterdir())) == base
                    finally:
                        os.close(held)
                    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as silent:
                        silent.settimeout(3)
                        silent.connect(str(gate_socket))
                        assert open_errno(target) == errno.EPERM
                        assert call(fan, 'status', gate_socket)['revision'] == 5
                        assert silent.recv(1) == b''
                    assert len(list(Path(f'/proc/{process.pid}/fd').iterdir())) == base
                    # 临时开放路径可达性，实际校验 SO_PEERCRED 而不仅是目录 DAC。
                    os.chmod(root, 0o755)
                    os.chmod(gate_socket, 0o666)
                    try:
                        code = 'import socket,sys; s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET); s.connect(sys.argv[1]); print(len(s.recv(512)))'
                        denied = subprocess.run([sys.executable, '-c', code, str(gate_socket)],
                                                capture_output=True, text=True, timeout=5,
                                                user=65534, group=65534, extra_groups=[])
                        assert denied.returncode == 0 and denied.stdout.strip() == '0', denied.stderr
                    finally:
                        os.chmod(gate_socket, 0o600)
                        os.chmod(root, 0o700)
                    # 只支持无后缀的当前命令；已删除的历史命令必须拒绝，不能触发 stop/reload。
                    before = call(fan, 'status', gate_socket)
                    for name in ('status', 'reload', 'stop'):
                        for suffix in ('v1', 'v2', 'v3'):
                            assert raw(gate_socket, f'{name}-{suffix}'.encode()) == b''
                    after = call(fan, 'status', gate_socket)
                    assert after['revision'] == before['revision']
                    assert after['reloads'] == before['reloads'] and after['rejections'] == before['rejections']
                    assert process.poll() is None
                    call(fan, 'reload', gate_socket, 'not_newer')
                    for _ in range(8):
                        snapshot = call(fan, 'status', gate_socket)
                        assert snapshot['instance_ns'] == initial_fan['instance_ns']
                        assert snapshot['last_code'] == 'not_newer'
                        assert snapshot['pid'] == process.pid and snapshot['uptime_ms'] >= initial_fan['uptime_ms']
                        assert len(list(Path(f'/proc/{process.pid}/fd').iterdir())) == base
                    # 查询完成不清除旧错误；成功重载才改变 last_code/reloads。
                    snapshot = call(bpf, 'status', bpf_socket)
                    assert snapshot['instance_ns'] == initial_bpf['instance_ns'] and snapshot['revision'] == 3
                    assert snapshot['reloads'] == 1 and snapshot['rejections'] == 3
                    print('PASS status snapshots, independent revisions, structured reload errors and busy-request contract')
                    print('PASS malformed/FD-bearing management isolation, SO_PEERCRED, single-layout commands and stable FDs')
            finally:
                subprocess.run([str(bpf), '--stop', str(bpf_socket)], check=True, capture_output=True, timeout=5)
                monitor.process.wait(timeout=5)
        # 无配置启动也可查询；重载明确返回 no_policy，且不改变活动模式。
        with tempfile.TemporaryFile(mode='w+') as output, tempfile.TemporaryFile(mode='w+') as errors:
            process = subprocess.Popen([str(fan), '--fanotify-only', '--file', str(target), '--decision', 'deny', '--run-for', '10',
                                        '--control', str(gate_socket)], stdout=output, stderr=errors)
            try:
                deadline = time.monotonic() + 5
                while not gate_socket.exists():
                    assert process.poll() is None and time.monotonic() < deadline
                    time.sleep(0.01)
                snapshot = call(fan, 'status', gate_socket)
                assert snapshot['revision'] == 0 and not snapshot['configured'] and snapshot['source_sha256'] is None
                assert call(fan, 'reload', gate_socket, 'no_policy')['decision'] == 'deny'
            finally:
                subprocess.run([str(fan), '--stop', str(gate_socket)], check=True, capture_output=True, timeout=5)
                process.wait(timeout=5)
        print('PASS command-line policy status and no-policy rejection')
        stage = root / 'staging'
        stage.write_text(f'revision 20\nfanotify-file "{target}"\n'
                         f'fanotify-analyzer "{build / "secmon-analyzer"}"\nfanotify-marker "BLOCK"\n'
                         'fanotify-scan-limit-bytes 4\n')
        os.chmod(stage, 0o600)
        stage.replace(config)
        with running(fan, config, gate_socket) as (process, output, errors):
            assert open_errno(target) == errno.EPERM
            scanned = call(fan, 'status', gate_socket)
            assert scanned['last_scan_error'] == 'oversized' and scanned['last_scan_errno'] == 0
            assert scanned['scan_error_counts']['oversized'] == scanned['analyzer_error'] == 1
            assert scanned['backend_error_requests'] == 0 and scanned['analyzer_online']
            owned = os.pidfd_open(scanned['analyzer_pid'])
            try:
                signal.pidfd_send_signal(owned, signal.SIGKILL)
            finally:
                os.close(owned)
            assert open_errno(target) == errno.EPERM
            failed = call(fan, 'status', gate_socket)
            assert not failed['analyzer_online'] and failed['backend_error_requests'] == 1
            readiness = subprocess.run([str(build / 'secmon-policyctl'), '--socket', str(gate_socket), '--require-ready'],
                                       capture_output=True, text=True, timeout=3)
            assert readiness.returncode == 1 and json.loads(readiness.stdout)['code'] == 'analyzer_offline', readiness
            assert failed['analyzer_error'] == 2 and failed['last_scan_error'] == 'oversized'
            assert failed['last_code'] == 'ok' and failed['revision'] == 20
        print('PASS live scan reasons and backend-error accounting preserve policy state')


if __name__ == '__main__':
    main()
