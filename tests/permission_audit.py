#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Account real fanotify permission replies against bounded per-request JSONL."""
import argparse
import concurrent.futures
from collections import Counter
import errno
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import time
from management_harness import call


def contents(file):
    # 不改变与写线程共享的 open-file-description 偏移，避免读取测试日志时覆盖历史记录。
    return os.pread(file.fileno(), os.fstat(file.fileno()).st_size, 0).decode()


def begin_request(path, event='open'):
    code = '''import json, os, sys
try:
 if sys.argv[2] == 'exec': os.execv(sys.argv[1], [sys.argv[1]])
 fd = os.open(sys.argv[1], os.O_RDONLY)
 try:
  if sys.argv[2] == 'access': os.read(fd, 1)
 finally: os.close(fd)
except OSError as error: result = error.errno
else: result = 0
print(json.dumps({'pid': os.getpid(), 'errno': result}), flush=True)
'''
    return subprocess.Popen(['python3', '-B', '-c', code, str(path), event],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def finish_request(process):
    try:
        output, error = process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate(timeout=5)
        raise
    assert process.returncode == 0, error
    return json.loads(output) if output else {'pid': process.pid, 'errno': 0}


def request(path, event='open'):
    return finish_request(begin_request(path, event))


class AuditedService:
    def __init__(self, build, root, target, fields, combined=False):
        self.build, self.root, self.target = build, root, target
        self.binary = build / 'secmon'
        self.policy, self.control = root / 'policy', root / 'control'
        self.event = next((line.split()[1] for line in fields.splitlines() if line.startswith('fanotify-event ')), 'open')
        self.identity = target.stat()
        self.expected = {}
        self.combined = combined
        self.publish(1, fields)
        self.output, self.errors = tempfile.TemporaryFile(), tempfile.TemporaryFile()
        self.process = subprocess.Popen([str(self.binary), *([] if combined else ['--fanotify-only']),
                                         '--policy', str(self.policy), '--control', str(self.control),
                                         '--audit-permissions', '--run-for', '60'], stdout=self.output, stderr=self.errors)
        try:
            deadline = time.monotonic() + 10
            while 'Service active;' not in contents(self.errors):
                assert self.process.poll() is None and time.monotonic() < deadline, contents(self.errors)
                time.sleep(0.01)
            self.initial = self.status()
            assert self.initial['permission_audit'] is True and self.initial['audit_errno'] == 0
            assert self.initial['backend'] == ('combined' if combined else 'fanotify')
        except BaseException:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, kind, value, trace):
        try:
            self.stop()
            if kind is None:
                self.verify()
        finally:
            self.close()

    def close(self):
        if self.process.poll() is None:
            call(self.binary, 'stop', self.control)
            self.process.wait(timeout=5)
        self.output.close()
        self.errors.close()

    def publish(self, revision, fields):
        stage = self.root / 'staging'
        stage.write_text(f'revision {revision}\nfanotify-file "{self.target}"\n{fields}\n')
        stage.chmod(0o600)
        stage.replace(self.policy)

    def status(self):
        return call(self.binary, 'status', self.control)

    def wait_pending(self, count):
        deadline = time.monotonic() + 3
        while self.status()['pending'] != count:
            assert time.monotonic() < deadline, 'pending deadline'
            time.sleep(0.005)

    def expect(self, result, reason, revision=1, scan_error='none'):
        assert result['pid'] not in self.expected
        self.expected[result['pid']] = (result['errno'], reason, revision, scan_error)

    def stop(self):
        if self.process.poll() is None:
            call(self.binary, 'stop', self.control)
            self.process.wait(timeout=5)
        assert self.process.returncode == 0, contents(self.errors)
        assert not self.control.exists()

    def verify(self):
        all_events = [json.loads(line) for line in contents(self.output).splitlines()]
        events = [event for event in all_events if event['event'] == 'fanotify_decision']
        if not self.combined:
            assert len(events) == len(all_events)
        else:
            assert any(event['event'] in ('exec_check', 'exec_success') for event in all_events)
        assert len(events) == len(self.expected), (events, self.expected)
        assert sorted(event['request_id'] for event in events) == list(range(1, len(events) + 1))
        observed = {}
        for event in events:
            assert event['instance_ns'] == self.initial['instance_ns']
            assert event['listener_pid'] == self.process.pid
            assert (event['major'], event['minor'], event['inode']) == (
                os.major(self.identity.st_dev), os.minor(self.identity.st_dev), self.identity.st_ino)
            assert event['permission_event'] == self.event
            assert event['received_ns'] <= event['responded_ns']
            assert event['latency_us'] == (event['responded_ns'] - event['received_ns']) // 1000
            assert event['requester_pid'] not in observed
            observed[event['requester_pid']] = (
                0 if event['decision'] == 'allow' else errno.EPERM,
                event['reason'], event['revision'], event['scan_error'])
            assert event['scan_errno'] == 0
        assert observed == self.expected, (observed, self.expected)
        reports = [json.loads(line) for line in contents(self.errors).splitlines() if line.startswith('{')]
        stats = next(report for report in reports if 'shutdown_denied' in report)
        reasons = Counter(event['reason'] for event in events)
        assert stats['allowed'] == sum(event['decision'] == 'allow' for event in events)
        assert stats['denied'] == sum(event['decision'] == 'deny' for event in events)
        for reason, counter in (('timeout', 'timed_out'), ('capacity', 'overloaded'), ('shutdown', 'shutdown_denied'),
                                ('analysis', 'analyzed'), ('analyzer_error', 'analyzer_error')):
            assert stats[counter] == reasons[reason], (reason, stats, reasons)
        for field in ('audit_dropped', 'audit_invalid', 'audit_queued', 'audit_errno'):
            values = re.findall(r'\b' + field + r'=(\d+)', contents(self.errors))
            assert values and int(values[-1]) == 0, (field, values)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', default='build')
    args = parser.parse_args()
    assert os.geteuid() == 0
    build = Path(args.build_dir).resolve()
    with tempfile.TemporaryDirectory(prefix='secmon-permission-audit-') as temporary:
        root = Path(temporary)
        target = root / 'target'
        target.write_bytes(b'clean')
        alias = root / 'alias'
        os.link(target, alias)
        for combined in (False, True):
            with AuditedService(build, root, target, 'fanotify-decision deny', combined) as service:
                for path in (target, alias):
                    result = request(path)
                    assert result['errno'] == errno.EPERM
                    service.expect(result, 'policy')
                service.publish(2, 'fanotify-decision allow')
                assert call(service.binary, 'reload', service.control)['revision'] == 2
                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                    for result in pool.map(request, [alias] * 24):
                        assert result['errno'] == 0
                        service.expect(result, 'policy', 2)
                if combined:
                    service.publish(3, f'fanotify-decision deny\nprotect "{root / "missing"}"')
                    failed = call(service.binary, 'reload', service.control, 'prepare_failed')
                    assert failed['revision'] == 2
                    result = request(target)
                    assert result['errno'] == 0
                    service.expect(result, 'policy', 2)
                    service.publish(3, 'fanotify-decision deny')
                    assert call(service.binary, 'reload', service.control)['revision'] == 3
                    result = request(alias)
                    assert result['errno'] == errno.EPERM
                    service.expect(result, 'policy', 3)
            print(f'PASS permission audit combined={combined}: aliases, revisions, concurrent identities and totals', flush=True)
        moved = root / 'moved'
        with AuditedService(build, root, target, 'fanotify-decision deny') as service:
            target.rename(moved)
            target.write_bytes(b'replacement')
            result = request(moved)
            assert result['errno'] == errno.EPERM
            service.expect(result, 'policy')
            assert request(target)['errno'] == 0
        moved.replace(target)
        print('PASS permission audit: rename retains fixed object identity; replacement inode is unrelated', flush=True)
        fields = 'fanotify-decision allow\nfanotify-delay-ms 300\nfanotify-timeout-ms 1500\nfanotify-max-pending 1'
        with AuditedService(build, root, target, fields) as service:
            first = begin_request(target)
            service.wait_pending(1)
            service.publish(2, 'fanotify-decision deny')
            refused = call(service.binary, 'reload', service.control, 'busy')
            assert refused['revision'] == 1
            overloaded = request(alias)
            assert overloaded['errno'] == errno.EPERM
            service.expect(overloaded, 'capacity')
            old = finish_request(first)
            assert old['errno'] == 0
            service.expect(old, 'policy')
            assert call(service.binary, 'reload', service.control)['revision'] == 2
            result = request(target)
            assert result['errno'] == errno.EPERM
            service.expect(result, 'policy', 2)
            service.publish(3, fields.replace('300', '4000').replace('1500', '5000'))
            assert call(service.binary, 'reload', service.control)['revision'] == 3
            pending = begin_request(target)
            service.wait_pending(1)
            service.stop()
            result = finish_request(pending)
            assert result['errno'] == errno.EPERM
            service.expect(result, 'shutdown', 3)
        print('PASS permission audit: capacity IDs, busy reload preserves received revision, graceful pending denial', flush=True)
        with AuditedService(build, root, target,
                            'fanotify-decision allow\nfanotify-delay-ms 300\nfanotify-timeout-ms 50') as service:
            result = request(target)
            assert result['errno'] == errno.EPERM
            service.expect(result, 'timeout')
        print('PASS permission audit: timeout fallback recorded once', flush=True)
        for event in ('open', 'access'):
            writer = os.open(target, os.O_RDWR | os.O_CLOEXEC)
            try:
                os.ftruncate(writer, 5)
                os.pwrite(writer, b'clean', 0)
                fields = (f'fanotify-event {event}\nfanotify-analyzer "{build / "secmon-analyzer"}"\n'
                          'fanotify-marker "BLOCK"\nfanotify-scan-limit-bytes 32')
                with AuditedService(build, root, target, fields) as service:
                    clean = request(target, event)
                    assert clean['errno'] == 0
                    service.expect(clean, 'analysis')
                    os.pwrite(writer, b'BLOCK', 0)
                    blocked = request(target, event)
                    assert blocked['errno'] == errno.EPERM
                    service.expect(blocked, 'analysis')
                    os.ftruncate(writer, 64)
                    error = request(target, event)
                    assert error['errno'] == errno.EPERM
                    service.expect(error, 'analyzer_error', scan_error='oversized')
                    os.kill(service.status()['analyzer_pid'], signal.SIGKILL)
                    deadline = time.monotonic() + 3
                    while service.status()['analyzer_online']:
                        assert time.monotonic() < deadline
                        time.sleep(0.005)
                    offline = request(target, event)
                    assert offline['errno'] == errno.EPERM
                    service.expect(offline, 'analyzer_error')
                print(f'PASS permission audit {event}: scan allow/deny, typed error and offline fallback', flush=True)
            finally:
                os.close(writer)
        with AuditedService(build, root, target,
                            f'fanotify-analyzer "{build / "secmon-analyzer"}"\nfanotify-marker "BLOCK"\n'
                            'fanotify-scan-limit-bytes 1\nfanotify-error-decision allow') as service:
            result = request(target)
            assert result['errno'] == 0
            service.expect(result, 'analyzer_error', scan_error='oversized')
        print('PASS permission audit: typed scanner error with explicit allow fallback', flush=True)
        executable = root / 'true'
        shutil.copyfile('/usr/bin/true', executable)
        executable.chmod(0o755)
        with AuditedService(build, root, executable, 'fanotify-event exec\nfanotify-decision deny') as service:
            result = request(executable, 'exec')
            assert result['errno'] == errno.EPERM
            service.expect(result, 'policy')
        print('PASS permission audit exec: direct execution identity and denial', flush=True)


if __name__ == '__main__':
    main()
