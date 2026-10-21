#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real canary mutation -> kernel thread-group write response, expiry and release."""
import argparse
from contextlib import ExitStack
import errno
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import threading
import time

from file_policy_map import PolicyMapView, policy_outer_ids
from management_harness import call
from monitor_harness import MonitorRun
from writer_harness import WriterProcess


class ResponseProcess(WriterProcess):
    def __init__(self, binary, trap, victim, late=False, prefix=()):
        self.lock = threading.Lock()
        self.process = subprocess.Popen([*prefix, str(binary), str(trap), str(victim)] + (["late"] if late else []), stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        try:
            assert self.read() == 'ready'
        except BaseException:
            self.close()
            raise


def experiment(build, paused=False, leader=False):
    with tempfile.TemporaryDirectory(prefix='secmon-response-') as temporary, ExitStack() as stack:
        root = Path(temporary)
        trap, victim, protected = (root / name for name in ('trap', 'victim', 'protected'))
        for path in (trap, victim, protected):
            path.write_bytes(b'original' + b'\0' * 8192)
        alias = root / 'alias'
        os.link(trap, alias)
        actor = stack.enter_context(ResponseProcess(build / 'secmon-response-scenario', alias, victim))
        outsider = stack.enter_context(ResponseProcess(build / 'secmon-response-scenario', trap, victim))
        ordinary = stack.enter_context(ResponseProcess(build / 'secmon-response-scenario', protected, victim))
        management = root / 'management'
        management.mkdir(mode=0o700)
        policy, control = root / 'policy', management / 'control'
        revision = 0
        def publish(epoch=1, duration=4000, extra='', canaries=True):
            nonlocal revision
            revision += 1
            text = f'revision {revision}\nprotect "{protected}"\n'
            if canaries:
                text += f'canary "{trap}"\n'
            if epoch:
                text += f'canary-response {epoch} {duration}\n'
            stage = root / 'stage'
            stage.write_text(text + extra)
            stage.chmod(0o600)
            stage.replace(policy)
        publish(duration=1200 if paused else 10000)
        before = policy_outer_ids()
        monitor = stack.enter_context(MonitorRun(build / 'secmon', ['--policy', str(policy)] +
                                                  ([] if paused else ['--control', str(control)])))
        stopped = False
        def cleanup():
            nonlocal stopped
            if stopped:
                os.kill(monitor.process.pid, signal.SIGCONT)
                stopped = False
            if not paused and monitor.process.poll() is None:
                call(build / 'secmon', 'stop', control)
                monitor.process.wait(timeout=5)
        stack.callback(cleanup)
        outer_ids = policy_outer_ids() - before
        assert len(outer_ids) == 1
        outer = next(iter(outer_ids))
        def expect(client, commands, expected):
            for command in commands:
                actual = client.request(command)
                assert actual == expected, (client.process.pid, command, actual, expected)
        expect(actor, 'rRwWfFjJ', 0)
        expect(ordinary, 'c', errno.EACCES)
        expect(ordinary, 'wW', 0)  # Ordinary denial does not trigger containment.
        if leader:
            expect(actor, 'L', 0)
        expect(actor, 'b', 0)  # Existing mapping is deliberately not revoked.
        if paused:
            os.kill(monitor.process.pid, signal.SIGSTOP)
            stopped = True
        expect(actor, 'c', errno.EACCES)
        expect(actor, 'wWootmMfFxX', errno.EACCES)
        # pthread_create may translate EACCES from clone to EAGAIN in glibc.
        assert actor.request('j') in (errno.EACCES, errno.EAGAIN)
        expect(actor, 'rRhHaAd', 0)
        assert victim.read_bytes()[0:1] == b'M'
        expect(outsider, 'wW', 0)
        if paused:
            time.sleep(1.35)
            expect(actor, 'wWfFjJ', 0)
            cleanup()
            monitor.stop()
        else:
            state = call(build / 'secmon', 'status', control)
            assert (state['canary_paths'], state['response_epoch'], state['response_duration_ms'],
                    state['response_started'], state['response_failed']) == (1, 1, 10000, 1, 0), state
            publish(duration=10000)
            call(build / 'secmon', 'reload', control)
            expect(actor, 'w', errno.EACCES)
            for epoch, duration, extra in ((1, 11000, ''), (0, 10000, ''),
                    (2, 10000, f'protect "{root / "missing"}"\n'),
                    (1, 10000, f'vault "{alias}"\n'),
                    (1, 10000, f'protect "{alias}"\nallow-writer "{build / "secmon-response-scenario"}" 0 "{alias}" write\n')):
                publish(epoch, duration, extra)
                call(build / 'secmon', 'reload', control, 'invalid_policy' if not epoch else 'prepare_failed')
                expect(actor, 'wW', errno.EACCES)
            publish(epoch=2, duration=1000)
            call(build / 'secmon', 'reload', control)
            expect(actor, 'wWfFjJ', 0)  # Explicit new epoch releases old response.
            expect(actor, 'C', errno.EACCES)
            expect(actor, 'wW', errno.EACCES)
            time.sleep(1.15)
            expect(actor, 'wWfFjJ', 0)
            expect(actor, 'c', errno.EACCES)  # Expiry permits retriggering, no lease extension.
            expect(actor, 'w', errno.EACCES)
            publish(epoch=2, duration=1000, canaries=False)
            call(build / 'secmon', 'reload', control)
            expect(actor, 'w', errno.EACCES)  # Removing traps alone retains response.
            publish(epoch=0, canaries=False)
            call(build / 'secmon', 'reload', control)
            expect(actor, 'wW', 0)
            publish(epoch=2, duration=1000)
            call(build / 'secmon', 'reload', control, 'prepare_failed')
            publish(epoch=3, duration=1000)
            call(build / 'secmon', 'reload', control)
            expect(actor, 'w', 0)
            cleanup()
        events = monitor.events()
        own = [event for event in events if event['pid'] == actor.process.pid]
        hits = [event for event in own if event.get('canary_hit')]
        assert hits and all(event['response_started'] and not event['response_failed'] for event in hits), hits
        assert all(event['process_inode'] and event['response_deadline_boot_ns'] for event in hits)
        assert len({event['process_inode'] for event in own}) == 1
        if not paused:
            assert any(event['event'] == 'process_response_denied' and event['operation'] == 14 for event in own)
            assert any(event['event'] == 'process_response_denied' and event['operation'] == 15 for event in own)
        assert 'response_failed=0' in monitor.diagnostics()
        assert 'audit_invalid=0' in monitor.diagnostics()
        print(json.dumps({'paused': paused, 'leader_exited': leader, 'hits': len(hits),
                          'response_denials': sum(event.get('response_blocked', False) for event in own)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', default='build')
    args = parser.parse_args()
    assert os.geteuid() == 0 and __debug__
    build = Path(args.build_dir).resolve()
    experiment(build)
    experiment(build, leader=True)
    experiment(build, paused=True)
    print('PASS canary response, existing threads/FDs, leader exit, expiry, explicit release, rollback and paused controller')


if __name__ == '__main__':
    main()
