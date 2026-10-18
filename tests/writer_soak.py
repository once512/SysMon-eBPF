#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# 持续存活的 root/nobody 授权程序与未授权程序并行写入，在线轮换 EUID/撤销，验证边界和 FD 不积累。
import argparse
from collections import Counter
from contextlib import ExitStack
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import time
from monitor_harness import MonitorRun
from management_harness import call
from writer_harness import WriterProcess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', default='build')
    parser.add_argument('--duration', type=int, default=30)
    args = parser.parse_args()
    assert os.geteuid() == 0 and 5 <= args.duration <= 1800
    build = Path(args.build_dir).resolve()
    with tempfile.TemporaryDirectory(prefix='secmon-writer-soak-') as tmp, ExitStack() as stack:
        root = Path(tmp)
        root.chmod(0o755)
        private = root / 'private'
        private.mkdir(mode=0o700)
        trusted, other, target = (root / p for p in ('trusted', 'other', 'data'))
        for path in (trusted, other):
            shutil.copyfile(build / 'secmon-writer-scenario', path)
            path.chmod(0o755)
        target.write_bytes(b'data')
        target.chmod(0o666)
        config, control = private / 'policy', private / 'control'

        def publish(revision, uid, broken=False):
            text = f'revision {revision}\nprotect "{target}"\n'
            if uid is not None:
                text += f'allow-writer "{trusted}" {uid} "{target}" all\n'
            if broken:
                text += f'allow-writer "{root / "missing"}" 0 "{target}" all\n'
            stage = private / 'staging'
            stage.write_text(text)
            stage.chmod(0o600)
            stage.replace(config)
            return hashlib.sha256(text.encode()).hexdigest()

        workers = [stack.enter_context(WriterProcess(trusted, target)),
                   stack.enter_context(WriterProcess(trusted, target, 65534)),
                   stack.enter_context(WriterProcess(other, target))]
        publish(1, None)
        monitor = stack.enter_context(MonitorRun(build / 'secmon',
            ['--policy', str(config), '--self-protect', str(control)], seconds=args.duration + 60))
        def fd_count(): return len(list(Path(f'/proc/{monitor.process.pid}/fd').iterdir()))
        baseline = peak = fd_count()
        first = call(build / 'secmon', 'status', control)
        for worker in workers:
            assert worker.request() == errno.EACCES
        stop = threading.Event()
        failures, counters = [], [Counter() for _ in workers]

        def probe(index):
            worker = workers[index]
            try:
                while not stop.is_set():
                    # 在同一常驻 mm 上交替测试既有 FD 写入与重新打开。
                    result = worker.request('w' if sum(counters[index].values()) % 2 else 'o')
                    assert result in (0, errno.EACCES), (index, result)
                    assert index != 2 or result == errno.EACCES, 'unauthorized writer allowed during swap'
                    counters[index][result] += 1
                    stop.wait(0.02)
            except BaseException as error:
                failures.append(repr(error))
                stop.set()

        threads = [threading.Thread(target=probe, args=(i,)) for i in range(len(workers))]
        for thread in threads:
            thread.start()
        started, revision, rejected = time.monotonic(), 1, 0
        next_report = started + 30
        try:
            while time.monotonic() - started < args.duration:
                assert not failures, failures
                uid = (0, 65534, None)[(revision - 1) % 3]
                if revision % 7 == 0:
                    publish(revision + 1, uid, True)
                    reply = call(build / 'secmon', 'reload', control, 'prepare_failed')
                    assert reply['revision'] == revision
                    rejected += 1
                digest = publish(revision + 1, uid)
                reply = call(build / 'secmon', 'reload', control)
                revision += 1
                assert reply['revision'] == revision and reply['writer_paths'] == int(uid is not None)
                assert reply['source_sha256'] == digest and reply['instance_ns'] == first['instance_ns']
                assert reply['rejections'] == rejected and reply['protected_paths'] == 1
                # request 的锁串行化每条管道；本条检查在成功 reload 后开始，不能用在途旧版本解释结果。
                for worker, euid in zip(workers, (0, 65534, -1)):
                    expected = 0 if uid is not None and euid == uid else errno.EACCES
                    assert worker.request() == expected
                    assert worker.request('o') == expected
                current = fd_count()
                peak = max(peak, current)
                assert current == baseline + int(uid is not None), (baseline, current, uid)
                status = call(build / 'secmon', 'status', control)
                assert status['revision'] == revision and status['source_sha256'] == digest
                assert status['reloads'] == revision - 1 and status['rejections'] == rejected
                if time.monotonic() >= next_report:
                    print(f'progress writer seconds={time.monotonic() - started:.0f} updates={revision - 1} '
                          f'rejected={rejected} idle_fds={current} peak_idle_fds={peak}', flush=True)
                    next_report += 30
                stop.wait(0.25)
        finally:
            stop.set()
            for thread in threads:
                thread.join(timeout=6)
            subprocess.run([str(build / 'secmon'), '--stop', str(control)], check=True, capture_output=True, timeout=5)
            monitor.process.wait(timeout=5)
        assert all(not thread.is_alive() for thread in threads) and not failures, failures
        assert all(counter[errno.EACCES] for counter in counters)
        assert all(counter[0] for counter in counters[:2]) and not counters[2][0]
        print(json.dumps({'duration_seconds': args.duration, 'elapsed_seconds': round(time.monotonic() - started, 3),
                          'updates': revision - 1, 'rejected_candidates': rejected, 'baseline_fds': baseline,
                          'peak_idle_fds': peak, 'background_results': [dict(c) for c in counters], 'status': status}))
        print('PASS live EUID rotation/revoke, existing/new FDs, uninterrupted outsider denial, candidate rollback and exact idle FD recovery')


if __name__ == '__main__':
    main()
