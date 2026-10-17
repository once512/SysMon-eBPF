#!/usr/bin/env python3
# 持续并发请求并核对回复数、队列与 FD 峰值；这些负载数据是回归证据，不是通用吞吐基准。
# SPDX-License-Identifier: MIT
"""Bounded-duration concurrent workload with FD-budget and response accounting."""
import argparse
import concurrent.futures
import errno
import json
import os
from pathlib import Path
import threading
import time
import tempfile
from fanotify_harness import start, stop


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', default='build')
    parser.add_argument('--duration', type=int, default=30)
    parser.add_argument('--backend', choices=('static', 'analysis'), default='static')
    parser.add_argument('--event', choices=('open', 'access'), default='open')
    parser.add_argument('--mode', choices=('policy', 'timeout'), default='policy')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('requires root/CAP_SYS_ADMIN')
    if args.backend == 'static' and args.event != 'open':
        parser.error('static workload only supports open events')
    if args.backend == 'analysis' and args.mode != 'policy':
        parser.error('analysis workload uses actual contents, not synthetic timeouts')
    if not 1 <= args.duration <= 1800:
        parser.error('duration must be 1..1800 seconds')
    binary = (Path(args.build_dir) / 'secmon-fanotify').resolve()
    with tempfile.TemporaryDirectory(prefix='secmon-soak-') as temporary:
        path = Path(temporary) / 'target'
        path.write_bytes(b'clean payload'.ljust(32, b'.'))
        with tempfile.TemporaryFile(mode='w+') as output, tempfile.TemporaryFile(mode='w+') as errors:
            delay, timeout = ('20', '200') if args.mode == 'policy' else ('1000', '30')
            writer = os.open(path, os.O_RDWR | os.O_CLOEXEC)
            extra = ['--decision-delay-ms', delay, '--request-timeout-ms', timeout, '--max-pending', '4']
            if args.backend == 'analysis':
                extra = ['--analyzer', str(binary.parent / 'secmon-analyzer'), '--deny-marker', 'SECMON_BLOCK',
                         '--request-timeout-ms', '1000', '--max-pending', '4', '--event', args.event]
            try:
                listener = start(binary, path, 'allow' if args.backend == 'static' else None,
                                 output, errors, seconds=args.duration + 10, extra=extra)
            except BaseException:
                os.close(writer)
                raise
            baseline_fds = len(list(Path(f'/proc/{listener.pid}/fd').iterdir()))
            peak_fds = baseline_fds
            halt = threading.Event()
            counts = [0, 0]
            lock = threading.Lock()

            def worker():
                while not halt.is_set():
                    fd = -1
                    try:
                        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
                        if args.event == 'access':
                            os.read(fd, 1)
                    except OSError as error:
                        if error.errno != errno.EPERM:
                            raise
                        index = 1
                    else:
                        index = 0
                    finally:
                        if fd >= 0:
                            os.close(fd)
                    with lock:
                        counts[index] += 1
                    halt.wait(0.005)  # Bound load instead of busy-looping overload replies.

            pool = concurrent.futures.ThreadPoolExecutor(max_workers=8)
            workers = [pool.submit(worker) for _ in range(8)]
            started = time.monotonic()
            next_report = started + 30
            previous_phase = -1
            try:
                while time.monotonic() - started < args.duration:
                    if args.backend == 'analysis':
                        phase = int(time.monotonic() - started) % 2
                        if phase != previous_phase:
                            contents = b'SECMON_BLOCK' if phase else b'clean payload'
                            assert os.pwrite(writer, contents.ljust(32, b'.'), 0) == 32
                            previous_phase = phase
                    assert listener.poll() is None, 'listener exited during workload'
                    for future in workers:
                        if future.done():
                            future.result()
                            raise RuntimeError('worker stopped early')
                    current_fds = len(list(Path(f'/proc/{listener.pid}/fd').iterdir()))
                    peak_fds = max(peak_fds, current_fds)
                    # Four deferred FDs plus at most one event currently being admitted.
                    assert current_fds <= baseline_fds + 5, (baseline_fds, current_fds)
                    if time.monotonic() >= next_report:
                        with lock:
                            snapshot = tuple(counts)
                        print(f'progress mode={args.mode} seconds={time.monotonic() - started:.0f}'
                              f' opens={sum(snapshot)} peak_fds={peak_fds}', flush=True)
                        next_report += 30
                    time.sleep(0.1)
                halt.set()
                _, unfinished = concurrent.futures.wait(workers, timeout=5)
                assert not unfinished, 'permission waits did not finish'
                for future in workers:
                    future.result()
            finally:
                halt.set()
                # Kill the group before joining workers if a listener regression strands them.
                stop(listener)
                pool.shutdown(wait=True)
                os.close(writer)
            errors.seek(0)
            assert listener.returncode == 0, errors.read()
            output.seek(0)
            stats = json.load(output)
            assert stats['allowed'] == counts[0] and stats['denied'] == counts[1], (stats, counts)
            assert stats['peak_pending'] <= 4 and stats['overflow'] == 0
            assert stats['shutdown_denied'] == 0
            if args.backend == 'static':
                assert stats['overloaded'] > 0
            else:
                assert stats['analyzed'] > 0 and stats['analysis_denied'] > 0
                assert stats['allowed'] > 0 and stats['denied'] > 0
                assert stats['analyzer_failures'] == 0
            if args.mode == 'timeout':
                assert stats['timed_out'] > 0 and stats['allowed'] == 0
            else:
                assert stats['allowed'] > 0
            print(json.dumps({'backend': args.backend, 'event': args.event, 'mode': args.mode, 'duration_seconds': args.duration,
                              'opens': sum(counts), 'baseline_fds': baseline_fds,
                              'peak_fds': peak_fds, 'stats': stats}), flush=True)
            print('PASS sustained workload, FD budget and complete response accounting', flush=True)


if __name__ == '__main__':
    main()
