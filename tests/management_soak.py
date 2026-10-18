#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# 持续业务负载中查询状态并在线重载；阶段排空后切换，让回复对账和旧请求合同都可确定验证。
import argparse
import concurrent.futures
from contextlib import ExitStack
import errno
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile
import threading
import time
from fanotify_harness import stop
from management_harness import call
from scoped_writer_probe import ScopedWriterProbe


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', default='build')
    parser.add_argument('--duration', type=int, default=30)
    parser.add_argument('--backend', choices=('static', 'analysis'), default='static')
    parser.add_argument('--verify-audit-output', action='store_true', help='require healthy current audit queue and kernel counters throughout the load')
    parser.add_argument('--audit-permissions', action='store_true', help='verify each permission audit record against replies')
    parser.add_argument('--combined', action='store_true', help='run both modules with scoped native writer probes')
    parser.add_argument('--event', choices=('open', 'access'), default='open')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('requires root/fanotify permissions')
    if args.verify_audit_output and not args.combined:
        parser.error('--verify-audit-output requires --combined')
    if not 5 <= args.duration <= 1800:
        parser.error('duration must be 5..1800 seconds')
    build = Path(args.build_dir).resolve()
    binary = build / 'secmon'
    with tempfile.TemporaryDirectory(prefix='secmon-management-soak-') as temporary, ExitStack() as stack:
        root = Path(temporary)
        target, config, control = [root / name for name in ('target', 'policy', 'control')]
        target.write_bytes(b'clean'.ljust(32, b'.'))
        writer = os.open(target, os.O_RDWR | os.O_CLOEXEC)
        revision = 1
        probe = ScopedWriterProbe(build, root, stack) if args.combined else None

        def publish():
            text = f'revision {revision}\nfanotify-file "{target}"\nfanotify-event {args.event}\n'
            if probe:
                text += probe.policy(revision)
            if args.backend == 'analysis':
                text += f'fanotify-analyzer "{build / "secmon-analyzer"}"\nfanotify-marker "BLOCK"\n'
            else:
                text += 'fanotify-decision ' + ('allow' if revision % 2 else 'deny') + '\nfanotify-delay-ms 20\n'
            text += 'fanotify-timeout-ms 1000\nfanotify-max-pending 4\n'
            stage = root / 'staging'
            stage.write_text(text)
            os.chmod(stage, 0o600)
            stage.replace(config)
        publish()
        with tempfile.TemporaryFile(mode='w+') as output, tempfile.TemporaryFile(mode='w+') as errors:
            process = subprocess.Popen([str(binary), *([] if args.combined else ['--fanotify-only']),
                                        *(['--audit-permissions'] if args.audit_permissions else []), '--policy', str(config), '--control', str(control),
                                        '--run-for', str(args.duration + 30)], stdout=output, stderr=errors)
            halt = threading.Event()
            condition = threading.Condition()
            paused = False
            in_flight = 0
            counts = [0, 0]
            workers = []
            pool = None
            try:
                deadline = time.monotonic() + 5
                while True:
                    errors.seek(0)
                    if 'Service active;' in errors.read():
                        break
                    assert process.poll() is None and time.monotonic() < deadline
                    time.sleep(0.01)
                base = len(list(Path(f'/proc/{process.pid}/fd').iterdir()))
                peak = base
                initial = call(binary, 'status', control)
                assert initial['permission_audit'] == args.audit_permissions
                if probe:
                    assert initial['backend'] == 'combined' and initial['pid'] == process.pid
                    probe.check(revision)
                max_latency = 0.0
                queries = 1
                updates = 0

                def worker():
                    nonlocal in_flight
                    while not halt.is_set():
                        with condition:
                            condition.wait_for(lambda: not paused or halt.is_set())
                            if halt.is_set():
                                return
                            in_flight += 1
                        fd = -1
                        try:
                            try:
                                fd = os.open(target, os.O_RDONLY | os.O_CLOEXEC)
                                if args.event == 'access':
                                    os.read(fd, 1)
                            except OSError as error:
                                assert error.errno == errno.EPERM, error
                                result = 1
                            else:
                                result = 0
                            finally:
                                if fd >= 0:
                                    os.close(fd)
                            with condition:
                                counts[result] += 1
                        finally:
                            with condition:
                                in_flight -= 1
                                condition.notify_all()
                        halt.wait(0.005)

                pool = concurrent.futures.ThreadPoolExecutor(max_workers=8)
                workers = [pool.submit(worker) for _ in range(8)]
                started = time.monotonic()
                next_update = started + 2
                next_report = started + 30
                while time.monotonic() - started < args.duration:
                    assert process.poll() is None
                    for future in workers:
                        if future.done():
                            future.result()
                            raise AssertionError('worker exited early')
                    before = time.monotonic()
                    snapshot = call(binary, 'status', control)
                    queries += 1
                    max_latency = max(max_latency, time.monotonic() - before)
                    assert snapshot['revision'] == revision and snapshot['instance_ns'] == initial['instance_ns']
                    assert snapshot['pending'] <= 4 and snapshot['peak_pending'] <= 4
                    assert snapshot['analyzer_failures'] == 0 and snapshot['overflow'] == 0
                    assert snapshot['diagnostic_dropped'] == snapshot['diagnostic_invalid'] == snapshot['diagnostic_errno'] == 0, snapshot
                    assert snapshot['diagnostic_queued'] <= 256, snapshot
                    if args.verify_audit_output:
                        assert snapshot['audit_invalid'] == snapshot['audit_dropped'] == snapshot['audit_errno'] == 0, snapshot
                        assert snapshot['audit_queued'] <= 1024, snapshot
                    current = len(list(Path(f'/proc/{process.pid}/fd').iterdir()))
                    peak = max(peak, current)
                    # 四个 pending FD、一个正在接管的事件 FD、一个临时管理连接的保守总预算。
                    assert current <= base + 6, (base, current)
                    if time.monotonic() >= next_update:
                        with condition:
                            paused = True
                            assert condition.wait_for(lambda: in_flight == 0, timeout=5), 'requests did not drain'
                        # 已送出的业务均完成后，确认 pending 已空，再提交新版本。
                        snapshot = call(binary, 'status', control)
                        queries += 1
                        assert snapshot['pending'] == 0
                        revision += 1
                        if args.backend == 'analysis':
                            assert os.pwrite(writer, (b'BLOCK' if revision % 2 == 0 else b'clean').ljust(32, b'.'), 0) == 32
                        publish()
                        updated = call(binary, 'reload', control)
                        assert updated['revision'] == revision and updated['reloads'] == revision - 1
                        assert updated['source_sha256'] == hashlib.sha256(config.read_bytes()).hexdigest()
                        updates += 1
                        # 同版本错误也必须有状态，且不能影响下一次合法重载。
                        refused = call(binary, 'reload', control, 'not_newer')
                        assert refused['revision'] == revision and refused['rejections'] == updates
                        if probe:
                            probe.check(revision)
                            assert updated['writer_paths'] == revision % 2 and updated['protected_paths'] == 2
                        assert len(list(Path(f'/proc/{process.pid}/fd').iterdir())) == base - (int(args.combined) if revision % 2 == 0 else 0)
                        with condition:
                            paused = False
                            condition.notify_all()
                        next_update = time.monotonic() + 2
                    if time.monotonic() >= next_report:
                        print(f'progress backend={args.backend} event={args.event} seconds={time.monotonic()-started:.0f}'
                              f' queries={queries} updates={updates} peak_fds={peak}', flush=True)
                        next_report += 30
                    halt.wait(0.1)
                halt.set()
                with condition:
                    paused = False
                    condition.notify_all()
                _, unfinished = concurrent.futures.wait(workers, timeout=5)
                assert not unfinished
                for future in workers:
                    future.result()
                final = call(binary, 'status', control)
                assert final['pending'] == 0 and final['reloads'] == updates and final['rejections'] == updates
                assert final['allowed'] == counts[0] and final['denied'] == counts[1], (final, counts)
                assert len(list(Path(f'/proc/{process.pid}/fd').iterdir())) == base - (int(args.combined) if revision % 2 == 0 else 0)
                print(json.dumps({'combined': args.combined, 'backend': args.backend, 'event': args.event, 'seconds': args.duration,
                                  'requests': sum(counts), 'queries': queries, 'updates': updates,
                                  'base_fds': base, 'peak_fds': peak,
                                  'max_query_ms': round(max_latency * 1000, 3), 'status': final}), flush=True)
            finally:
                halt.set()
                with condition:
                    paused = False
                    condition.notify_all()
                if args.combined and process.poll() is None:
                    call(binary, 'stop', control)
                    process.wait(timeout=10)
                stop(process)  # 先关闭 group，再 join，确保失败路径也解除业务等待。
                if pool:
                    pool.shutdown(wait=True)
                os.close(writer)
            errors.seek(0)
            assert process.returncode == 0, errors.read()
            if args.combined or args.audit_permissions:
                errors.seek(0)
                reports = [json.loads(line) for line in errors.read().splitlines() if line.startswith('{')]
                stats = next(report for report in reports if 'shutdown_denied' in report)
            else:
                output.seek(0)
                stats = json.load(output)
            assert stats['allowed'] == counts[0] and stats['denied'] == counts[1]
            assert stats['shutdown_denied'] == stats['overflow'] == stats['analyzer_failures'] == 0
            assert stats['allowed'] > 0 and stats['denied'] > 0
            if args.audit_permissions:
                output.seek(0)
                # 逐行校验，不把长测的全部 JSON 对象载入内存；标记数组按实际回复总量分配，每个请求一字节。
                seen = bytearray(sum(counts))
                recorded, allowed = 0, 0
                for line in output:
                    event = json.loads(line)
                    if event['event'] != 'fanotify_decision':
                        continue
                    request_id = event['request_id']
                    assert 1 <= request_id <= len(seen) and not seen[request_id - 1]
                    seen[request_id - 1] = 1
                    recorded += 1
                    allowed += event['decision'] == 'allow'
                    assert event['instance_ns'] == initial['instance_ns'] and event['listener_pid'] == process.pid
                    assert event['requester_pid'] == os.getpid() and 1 <= event['revision'] <= revision
                    assert event['permission_event'] == args.event
                    if event['reason'] in ('policy', 'analysis'):
                        assert (event['decision'] == 'allow') == bool(event['revision'] % 2), event
                assert recorded == sum(counts) and allowed == counts[0]
                print(json.dumps({'event': 'permission-audit-health', 'backend': args.backend, 'permission_event': args.event,
                                  'records': recorded, 'updates': updates, 'unique_ids': True, 'reply_accounting': True}), flush=True)
            if args.verify_audit_output:
                errors.seek(0)
                diagnostics = errors.read()
                health = {}
                for name in ('ringbuf_dropped', 'baseline_update_failed', 'audit_dropped', 'audit_invalid', 'audit_queued', 'audit_errno'):
                    values = re.findall(r'\b' + name + r'=(\d+)', diagnostics)
                    assert values and int(values[-1]) == 0, (name, values)
                    health[name] = int(values[-1])
                print(json.dumps({'event': 'output-health', 'backend': args.backend, 'permission_event': args.event, **health}), flush=True)
            print('PASS management under load, repeated revision commits, idle FD recovery and response accounting', flush=True)


if __name__ == '__main__':
    main()
