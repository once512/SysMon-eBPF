#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Progress probes detect a stopped reader, recover, and never invent verdicts."""
import argparse
from contextlib import ExitStack
import errno
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
from permission_audit import AuditedService, begin_request, finish_request, contents, request
from management_harness import call


def wait_state(service, state):
    until = time.monotonic() + 4
    while True:
        status = service.status()
        if status['reader_state'] == state:
            return status
        assert service.process.poll() is None and time.monotonic() < until, status
        time.sleep(.02)


def experiment(build, analysis, pidfd):
    with tempfile.TemporaryDirectory(prefix='secmon-reader-health-') as tmp, ExitStack() as stack:
        root = Path(tmp); target = root / 'target'; target.write_bytes(b'clean')
        fields = 'fanotify-timeout-ms 700\n' + ('' if analysis else 'fanotify-decision allow\n')
        if analysis:
            fields += f'fanotify-analyzer "{build / "secmon-analyzer"}"\nfanotify-marker "BLOCK"\n'
        service = AuditedService(build, root, target, fields, requester_pidfd=pidfd)
        stack.callback(service.close)
        reader = service.status()['reader_pid']; stopped = False; pending = None
        def cleanup():
            if stopped:
                try: os.kill(reader, signal.SIGCONT)
                except ProcessLookupError: pass
            if service.process.poll() is None:
                call(build / 'secmon', 'stop', service.control); service.process.wait(timeout=5)
            if pending is not None and pending.poll() is None:
                pending.kill(); pending.wait(timeout=5)
        stack.callback(cleanup)
        assert reader > 0 and reader != service.process.pid
        assert request(target)['errno'] == 0
        wait_state(service, 'responsive')
        # Prove an idle reader keeps reporting progress, not just startup age.
        time.sleep(2.1)
        healthy = service.status()
        assert healthy['reader_state'] == 'responsive' and healthy['reader_progress_age_ms'] < 1000, healthy
        os.kill(reader, signal.SIGSTOP); stopped = True
        until = time.monotonic() + 2
        while 'State:\tT' not in Path(f'/proc/{reader}/status').read_text():
            assert time.monotonic() < until
            time.sleep(.005)
        pending = begin_request(target)
        degraded = wait_state(service, 'unresponsive')
        assert degraded['reader_pid'] == reader and degraded['reader_progress_age_ms'] >= 2000
        assert degraded['pending'] == 0 and degraded['allowed'] == 1 and degraded['denied'] == 0, degraded
        assert pending.poll() is None, 'reader failure silently allowed an unreceived request'
        checked = subprocess.run([str(build / 'secmon-policyctl'), '--socket', str(service.control), '--require-ready'],
                                 capture_output=True, text=True, timeout=3)
        assert checked.returncode == 1 and json.loads(checked.stdout)['code'] == 'reader_unresponsive', checked
        begin = time.monotonic(); service.status(); status_ms = (time.monotonic() - begin) * 1000
        assert status_ms < 500
        os.kill(reader, signal.SIGCONT); stopped = False
        assert finish_request(pending)['errno'] == 0
        recovered = wait_state(service, 'responsive')
        assert recovered['reader_pid'] == reader and recovered['allowed'] == 2, recovered
        os.kill(reader, signal.SIGSTOP); stopped = True
        until = time.monotonic() + 2
        while 'State:\tT' not in Path(f'/proc/{reader}/status').read_text():
            assert time.monotonic() < until
            time.sleep(.005)
        pending = begin_request(target)
        time.sleep(.08)
        begin = time.monotonic(); call(build / 'secmon', 'stop', service.control)
        ack_ms = (time.monotonic() - begin) * 1000
        service.process.wait(timeout=3)
        assert service.process.returncode == 0 and ack_ms < 500, contents(service.errors)
        stopped = False # shutdown kills/reaps the stopped reader
        final = finish_request(pending)['errno']
        assert final in (0, errno.EPERM, errno.EINTR), final
        events = [json.loads(line) for line in contents(service.output).splitlines()]
        assert len(events) == 2 and all(e['decision'] == 'allow' for e in events), events
        assert [e['request_id'] for e in events] == [1, 2]
        print(json.dumps({'analysis': analysis, 'pidfd': pidfd, 'idle_progress': True, 'stalled_detected': True,
                          'recovered': True, 'status_ms': round(status_ms, 2), 'stop_ms': round(ack_ms, 2),
                          'unpublished_stop_errno': final, 'audited': len(events)}))


def death(build):
    with tempfile.TemporaryDirectory(prefix='secmon-reader-death-') as tmp:
        root = Path(tmp); target = root / 'target'; target.write_bytes(b'clean')
        service = AuditedService(build, root, target, 'fanotify-decision allow\n')
        try:
            reader = service.status()['reader_pid']
            os.kill(reader, signal.SIGKILL)
            service.process.wait(timeout=3)
            assert service.process.returncode == 1, contents(service.errors)
            assert 'unusable group' in contents(service.errors) or 'disconnected fanotify reader' in contents(service.errors), contents(service.errors)
            assert not service.control.exists() and request(target)['errno'] == 0
        finally:
            service.close()
    print('PASS reader death is a reported fatal backend failure; no implicit restart or persistent protection claim')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, default=Path('build'))
    args = parser.parse_args()
    if os.geteuid() != 0 or not __debug__: parser.error('run as root without Python optimization')
    build = args.build_dir.resolve()
    for analysis in (False, True):
        for pidfd in (False, True):
            experiment(build, analysis, pidfd)
    death(build)
    print('PASS reader heartbeat supervision, idle progress, no fabricated audit, recovery and stopped-reader shutdown')


if __name__ == '__main__': main()
