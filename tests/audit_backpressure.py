#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# 堵住/断开审计 stdout，确认同一主进程仍能 fanotify 裁决、联合重载和授权停止；同时观察可诊断丢失。
import argparse
import errno
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from fanotify_harness import open_errno
from management_harness import call


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
    assert os.geteuid() == 0
    binary = Path(args.build_dir).resolve() / 'secmon'
    with tempfile.TemporaryDirectory(prefix='secmon-audit-pressure-') as temporary:
        root = Path(temporary)
        a, b, gate, anchor, config, control = [root / name for name in ('a', 'b', 'gate', 'anchor', 'policy', 'control')]
        for path in (a, b, gate, anchor):
            path.write_bytes(b'data')

        def publish(revision, path, decision):
            stage = root / 'staging'
            stage.write_text(f'revision {revision}\nprotect "{anchor}"\nprotect "{path}"\nfanotify-file "{gate}"\nfanotify-decision {decision}\n')
            stage.chmod(0o600)
            stage.replace(config)

        for mode in ('recover', 'blocked-stop', 'closed-peer', 'continuous'):
            publish(1, a, 'allow')
            with tempfile.TemporaryFile(mode='w+') as errors:
                process = subprocess.Popen([str(binary), '--policy', str(config), '--control', str(control), '--run-for', '30'],
                                           stdout=subprocess.PIPE, stderr=errors, pipesize=4096)
                flood = None
                try:
                    deadline = time.monotonic() + 10
                    while True:
                        errors.seek(0)
                        text = errors.read()
                        if 'Service active;' in text:
                            break
                        assert process.poll() is None and time.monotonic() < deadline, text
                        time.sleep(0.01)
                    assert open_errno(gate) == 0 and write_errno(a) == errno.EACCES
                    if mode == 'closed-peer':
                        process.stdout.close()
                    # 真实拒绝事件洪流；不读取 stdout，避免把“消费足够快”误作无背压验证。
                    code = """import errno, os, sys, time
until = time.monotonic() + 20
for index in range(100000000 if sys.argv[2] == 'continuous' else 8000):
 if time.monotonic() >= until: break
 try:
  fd = os.open(sys.argv[1], os.O_WRONLY); os.close(fd)
 except OSError as error:
  assert error.errno == errno.EACCES
 else:
  raise AssertionError('write permission unexpectedly allowed')
"""
                    command = ['python3', '-c', code, str(anchor), mode]
                    if mode == 'continuous':
                        flood = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                    else:
                        producer = subprocess.run(command, capture_output=True, text=True, timeout=10)
                        assert producer.returncode == 0, producer.stderr
                    deadline = time.monotonic() + 5
                    while True:
                        snapshot = call(binary, 'status', control)
                        if snapshot['audit_dropped'] > 0 and (mode != 'closed-peer' or snapshot['audit_errno'] == errno.EPIPE):
                            break
                        assert time.monotonic() < deadline, snapshot
                    assert snapshot['audit_queued'] <= 1024 and snapshot['backend'] == 'combined'
                    assert open_errno(gate) == 0
                    publish(2, b, 'deny')
                    updated = call(binary, 'reload', control)
                    assert updated['revision'] == 2 and updated['audit_dropped'] >= snapshot['audit_dropped']
                    assert write_errno(a) == 0 and write_errno(b) == errno.EACCES
                    assert open_errno(gate) == errno.EPERM
                    if mode == 'recover':
                        os.set_blocking(process.stdout.fileno(), False)
                        contents = bytearray()
                        deadline = time.monotonic() + 5
                        while True:
                            try:
                                chunk = os.read(process.stdout.fileno(), 65536)
                            except BlockingIOError:
                                chunk = b''
                            contents.extend(chunk)
                            status = call(binary, 'status', control)
                            if status['audit_queued'] == 0 and status['audit_written'] > snapshot['audit_written']:
                                break
                            assert time.monotonic() < deadline, status
                        assert status['audit_errno'] == 0
                    if flood is not None:
                        assert flood.poll() is None, 'continuous flood ended before responsiveness checks'
                        flood.terminate()
                        flood.communicate(timeout=5)
                    started = time.monotonic()
                    call(binary, 'stop', control)
                    process.wait(timeout=5)
                    assert time.monotonic() - started < 3 and process.returncode == 0
                    if mode == 'recover':
                        # 管道写端都已关闭，非阻塞读取不会等新数据；每条已输出记录仍是完整 JSONL。
                        while True:
                            chunk = os.read(process.stdout.fileno(), 65536)
                            if not chunk:
                                break
                            contents.extend(chunk)
                        lines = contents.splitlines()
                        assert lines and all(json.loads(line)['event'] in ('exec_check', 'exec_success', 'file_denied', 'self_denied') for line in lines)
                    errors.seek(0)
                    diagnostics = errors.read()
                    assert 'audit_dropped=' in diagnostics and 'audit_queued=0' in diagnostics
                    print(f'PASS audit {mode}: fanotify/reload/stop remain available; observed drops={snapshot["audit_dropped"]} errno={snapshot["audit_errno"]}', flush=True)
                finally:
                    if flood is not None and flood.poll() is None:
                        flood.terminate()
                        flood.communicate(timeout=5)
                    # 若验证失败，先关闭读端使任何等待写入退出，再经同一 root 管理通道清理。
                    if not process.stdout.closed:
                        process.stdout.close()
                    if process.poll() is None:
                        call(binary, 'stop', control)
                        process.wait(timeout=10)
                    assert not control.exists()


if __name__ == '__main__':
    main()
