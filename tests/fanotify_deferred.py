#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real permission waits: deadlines, capacity fallbacks and graceful shutdown."""
import argparse
import concurrent.futures
import errno
import json
import os
from pathlib import Path
import select
import subprocess
import tempfile
import time
from fanotify_harness import start, open_errno, stop


class GateRun:
    def __init__(self, binary, path, decision, extra, seconds=20):
        self.output = tempfile.TemporaryFile(mode='w+')
        self.errors = tempfile.TemporaryFile(mode='w+')
        try:
            self.process = start(binary, path, decision, self.output, self.errors,
                                 seconds=seconds, extra=extra)
        except BaseException:
            self.output.close()
            self.errors.close()
            raise

    def finish(self):
        try:
            stop(self.process)
            self.errors.seek(0)
            assert self.process.returncode == 0, self.errors.read()
            self.output.seek(0)
            return json.load(self.output)
        finally:
            self.output.close()
            self.errors.close()


def begin_open(path):
    code = '''import errno, os, sys
print('ready', flush=True)
try:
    fd = os.open(sys.argv[1], os.O_RDONLY)
    os.close(fd)
except OSError as error:
    print(error.errno, flush=True)
else:
    print(0, flush=True)
'''
    process = subprocess.Popen(['python3', '-c', code, str(path)], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    readable, _, _ = select.select([process.stdout], [], [], 5)
    if not readable or process.stdout.readline().strip() != 'ready':
        process.kill()
        process.wait(timeout=5)
        raise RuntimeError('opener did not become ready')
    return process


def finish_open(process):
    output, error = process.communicate(timeout=5)
    assert process.returncode == 0, error
    return int(output)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', default='build')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('requires root/CAP_SYS_ADMIN')
    binary = (Path(args.build_dir) / 'secmon-fanotify').resolve()
    with tempfile.TemporaryDirectory(prefix='secmon-deferred-') as temporary:
        path = Path(temporary) / 'target'
        path.write_bytes(b'deferred experiment')
        for decision in ('allow', 'deny'):
            run = GateRun(binary, path, decision,
                          ['--decision-delay-ms', '150', '--request-timeout-ms', '1500'])
            try:
                started = time.monotonic()
                assert open_errno(path) == (0 if decision == 'allow' else errno.EPERM)
                elapsed = time.monotonic() - started
                assert 0.12 <= elapsed < 3, elapsed
            finally:
                stats = run.finish()
            assert stats['timed_out'] == stats['overloaded'] == 0
            assert stats['allowed' if decision == 'allow' else 'denied'] == 1
            assert stats['peak_pending'] == 1
            print(f'PASS delayed {decision}: elapsed={elapsed:.3f}s')
        for fallback in ('allow', 'deny'):
            # The synthetic policy answer would arrive after the deadline.
            decision = 'deny' if fallback == 'allow' else 'allow'
            run = GateRun(binary, path, decision,
                          ['--decision-delay-ms', '1000', '--request-timeout-ms', '100',
                           '--timeout-decision', fallback])
            try:
                started = time.monotonic()
                assert open_errno(path) == (0 if fallback == 'allow' else errno.EPERM)
                elapsed = time.monotonic() - started
                assert 0.08 <= elapsed < 0.9, elapsed
            finally:
                stats = run.finish()
            assert stats['timed_out'] == 1 and stats['overloaded'] == 0
            print(f'PASS timeout {fallback}: elapsed={elapsed:.3f}s')
        for fallback in ('allow', 'deny'):
            decision = 'deny' if fallback == 'allow' else 'allow'
            run = GateRun(binary, path, decision,
                          ['--decision-delay-ms', '1000', '--request-timeout-ms', '3000',
                           '--max-pending', '1', '--overload-decision', fallback])
            first = None
            try:
                first = begin_open(path)
                time.sleep(0.15)
                assert first.poll() is None
                started = time.monotonic()
                assert open_errno(path) == (0 if fallback == 'allow' else errno.EPERM)
                assert time.monotonic() - started < 0.8
                assert finish_open(first) == (0 if decision == 'allow' else errno.EPERM)
            finally:
                stats = run.finish()
                if first is not None and first.poll() is None:
                    first.kill()
                    first.wait(timeout=5)
            assert stats['overloaded'] == 1 and stats['timed_out'] == 0
            assert stats['peak_pending'] == 1 and stats['allowed'] == stats['denied'] == 1
            print(f'PASS capacity {fallback}: one pending slot, prompt fallback')
        # Bound owned event FDs under an actual burst, then account for all replies.
        run = GateRun(binary, path, 'allow', ['--decision-delay-ms', '300',
                      '--request-timeout-ms', '2000', '--max-pending', '2'])
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                results = list(pool.map(open_errno, [path] * 32))
            assert all(result in (0, errno.EPERM) for result in results)
        finally:
            stats = run.finish()
        assert stats['peak_pending'] <= 2 and stats['overloaded'] > 0
        assert stats['allowed'] == results.count(0)
        assert stats['denied'] == results.count(errno.EPERM)
        assert stats['allowed'] + stats['denied'] == 32
        print('PASS concurrent burst: bounded pending budget and complete accounting')
        for internal in (False, True):
            run = GateRun(binary, path, 'allow', ['--decision-delay-ms', '4000',
                          '--request-timeout-ms', '5000'], seconds=1 if internal else 20)
            opener = None
            try:
                opener = begin_open(path)
                time.sleep(0.15)
                assert opener.poll() is None
                if internal:
                    run.process.wait(timeout=5)
                else:
                    run.process.terminate()
                assert finish_open(opener) == errno.EPERM
            finally:
                stats = run.finish()
                if opener is not None and opener.poll() is None:
                    opener.kill()
                    opener.wait(timeout=5)
            assert stats['shutdown_denied'] == 1 and stats['denied'] == 1
            assert stats['timed_out'] == 0
            assert open_errno(path) == 0
            print(f'PASS {"deadline" if internal else "SIGTERM"}: deny delivered pending request, remove mark')


if __name__ == '__main__':
    main()
