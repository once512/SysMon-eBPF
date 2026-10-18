#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# 不读取真实 stderr 管道，覆盖启动已满、运行错误洪流、周期报告、恢复、断开和授权退出。
import argparse
import concurrent.futures
import errno
import fcntl
import os
from pathlib import Path
import subprocess
import tempfile
import time
from fanotify_harness import open_errno
from management_harness import call


def drain(fd):
    result = bytearray()
    while True:
        try:
            chunk = os.read(fd, 65536)
        except BlockingIOError:
            return result
        if not chunk:
            return result
        result.extend(chunk)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', default='build')
    parser.add_argument('--reload-count', type=int, default=400, help='400..10000 failed reloads per stderr scenario')
    args = parser.parse_args()
    assert os.geteuid() == 0
    if not 400 <= args.reload_count <= 10000:
        parser.error('reload-count must be 400..10000')
    binary = Path(args.build_dir).resolve() / 'secmon'
    with tempfile.TemporaryDirectory(prefix='secmon-diagnostic-pressure-') as temporary:
        root = Path(temporary)
        gate, protected, config, control = [root / name for name in ('gate', 'protected', 'policy', 'control')]
        gate.write_bytes(b'clean')
        protected.write_bytes(b'data')

        def publish(revision, decision):
            stage = root / 'staging'
            stage.write_text(f'revision {revision}\nprotect "{protected}"\nfanotify-file "{gate}"\nfanotify-decision {decision}\n')
            stage.chmod(0o600)
            stage.replace(config)

        for mode in ('startup-full', 'recover', 'blocked-stop', 'closed-peer'):
            publish(1, 'deny')
            reader, writer = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
            fcntl.fcntl(writer, fcntl.F_SETPIPE_SZ, 4096)
            fcntl.fcntl(writer, fcntl.F_SETFL, fcntl.fcntl(writer, fcntl.F_GETFL) & ~os.O_NONBLOCK)
            filler = os.open(f'/proc/self/fd/{writer}', os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC)

            def fill():
                while True:
                    try:
                        os.write(filler, b'X' * 4096)
                    except BlockingIOError:
                        return

            if mode == 'startup-full':
                fill()
            with tempfile.TemporaryFile() as output:
                process = subprocess.Popen([str(binary), '--policy', str(config), '--control', str(control), '--run-for', str(60 + args.reload_count // 5)],
                                           stdout=output, stderr=writer)
                try:
                    # 启动就堵住 stderr，不能依赖读取启动行来判断是否就绪。
                    deadline = time.monotonic() + 10
                    while True:
                        assert process.poll() is None, process.returncode
                        if control.exists():
                            try:
                                initial = call(binary, 'status', control)
                            except (AssertionError, subprocess.TimeoutExpired):
                                pass
                            else:
                                break
                        assert time.monotonic() < deadline, 'startup blocked on stderr'
                        time.sleep(0.01)
                    assert initial['backend'] == 'combined'
                    assert open_errno(gate) == errno.EPERM
                    baseline_fds = len(list(Path(f'/proc/{process.pid}/fd').iterdir()))
                    if mode == 'closed-peer':
                        os.close(reader)
                        reader = -1
                    elif mode != 'startup-full':
                        drain(reader)
                        fill()

                    def rejected_reload_flood():
                        for _ in range(args.reload_count):
                            reply = call(binary, 'reload', control, 'not_newer')
                            assert reply['revision'] == 1 and reply['last_code'] == 'not_newer'

                    probes = 0
                    peak_fds = baseline_fds
                    next_report = time.monotonic() + 30
                    started = time.monotonic()
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                        flood = pool.submit(rejected_reload_flood)
                        while not flood.done():
                            assert open_errno(gate) == errno.EPERM
                            current = call(binary, 'status', control)
                            assert current['revision'] == 1 and current['diagnostic_queued'] <= 256
                            probes += 1
                            current_fds = len(list(Path(f'/proc/{process.pid}/fd').iterdir()))
                            peak_fds = max(peak_fds, current_fds)
                            assert current_fds <= baseline_fds + 2, (baseline_fds, current_fds)
                            if time.monotonic() >= next_report:
                                print(f'progress diagnostics {mode}: probes={probes} rejections={current["rejections"]} '
                                      f'queued={current["diagnostic_queued"]} dropped={current["diagnostic_dropped"]} '
                                      f'peak_fds={peak_fds}', flush=True)
                                next_report += 30
                        flood.result()
                    status = call(binary, 'status', control)
                    assert status['rejections'] == args.reload_count and status['diagnostic_dropped'] > 0, status
                    assert probes > 0 and status['diagnostic_invalid'] == 0, status
                    assert len(list(Path(f'/proc/{process.pid}/fd').iterdir())) == baseline_fds
                    if mode == 'closed-peer':
                        assert status['diagnostic_errno'] == errno.EPIPE, status
                    else:
                        assert status['diagnostic_errno'] == 0, status
                    # 保持输出堵住跨过 10s 周期报告；活跃事件循环也必须仍可管理/裁决。
                    if mode == 'startup-full':
                        while time.monotonic() - started < 11:
                            assert open_errno(gate) == errno.EPERM
                            call(binary, 'status', control)
                            time.sleep(0.1)
                    publish(2, 'allow')
                    updated = call(binary, 'reload', control)
                    assert updated['revision'] == 2 and updated['reloads'] == 1
                    assert open_errno(gate) == 0
                    if mode == 'recover':
                        deadline = time.monotonic() + 5
                        contents = bytearray()
                        while True:
                            contents.extend(drain(reader))
                            recovered = call(binary, 'status', control)
                            if recovered['diagnostic_queued'] == 0:
                                break
                            assert time.monotonic() < deadline, recovered
                        assert recovered['diagnostic_written'] > status['diagnostic_written']
                        assert recovered['diagnostic_errno'] == 0
                        assert b'Policy reload rejected:' in contents
                    started_stop = time.monotonic()
                    call(binary, 'stop', control)
                    process.wait(timeout=5)  # 此处故意不排空管道，退出必须自己完成。
                    assert process.returncode == 0 and time.monotonic() - started_stop < 3
                    assert not control.exists() and open_errno(gate) == 0
                    print(f'PASS diagnostics {mode}: {probes} concurrent probes, '
                          f'reloads={args.reload_count}, dropped={status["diagnostic_dropped"]}, errno={status["diagnostic_errno"]}, '
                          f'fds={baseline_fds}/{peak_fds}; '
                          'reload/status/permission/stop remain responsive', flush=True)
                finally:
                    if reader >= 0:
                        drain(reader)
                    if process.poll() is None:
                        try:
                            call(binary, 'stop', control)
                            process.wait(timeout=5)
                        finally:
                            # 独立运行期限限制失败场景；不能外部 kill 受自保护的服务。
                            if process.poll() is None:
                                if reader >= 0:
                                    os.close(reader)
                                    reader = -1
                                process.wait(timeout=65 + args.reload_count // 5)
                    os.close(filler)
                    os.close(writer)
                    if reader >= 0:
                        os.close(reader)


if __name__ == '__main__':
    main()
