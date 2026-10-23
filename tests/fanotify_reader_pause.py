#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""A FUSE-stalled static event reader cannot stall management or old deadlines."""
import argparse
from contextlib import ExitStack
import errno
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import tempfile
import time
from decoy_harness import DecoyView
from management_harness import call
from monitor_harness import MonitorRun
from virtual_decoy import DecoyActor


def experiment(build, pidfd):
    with tempfile.TemporaryDirectory(prefix='secmon-reader-pause-') as tmp, ExitStack() as stack:
        root = Path(tmp); mountpoint = root / 'view'; mountpoint.mkdir()
        provider = stack.enter_context(DecoyView(build / 'secmon-decoyfs', mountpoint))
        trap, victim, policy = mountpoint / 'accounts.csv', root / 'victim', root / 'policy'
        victim.write_bytes(b'original' + b'\0' * 8192)
        actor = stack.enter_context(DecoyActor(build / 'secmon-virtual-decoy-scenario', trap, victim))
        management = root / 'management'; management.mkdir(mode=0o700)
        control = management / 'control'
        def publish(revision, epoch=1, delayed=False):
            text = f'revision {revision}\ncanary "{trap}"\ncanary-response {epoch} 30000\n'
            text += f'fanotify-file "{trap}"\nfanotify-file "{victim}"\nfanotify-event access\nfanotify-decision allow\n'
            text += ('fanotify-delay-ms 1500\nfanotify-timeout-ms 700\n' if delayed else
                     'fanotify-delay-ms 0\nfanotify-timeout-ms 1000\n')
            text += 'fanotify-timeout-decision deny\n'
            stage = root / 'stage'; stage.write_text(text); stage.chmod(0o600); stage.replace(policy)
        publish(1)
        wrapper = root / 'combined'; wrapper.write_text('#!/bin/sh\nshift\nexec ' + shlex.quote(str(build / 'secmon')) + ' "$@"\n'); wrapper.chmod(0o700)
        monitor = stack.enter_context(MonitorRun(wrapper, ['--policy', str(policy), '--control', str(control),
                    '--audit-permissions'] + (['--requester-pidfd'] if pidfd else [])))
        paused = False; local = None; actor_waiting = False
        def resume():
            nonlocal paused
            if paused: os.kill(provider.process.pid, signal.SIGCONT); paused = False
        def cleanup():
            resume()
            if local is not None and local.poll() is None: local.kill(); local.wait(timeout=5)
            if monitor.process.poll() is None:
                call(build / 'secmon', 'stop', control); monitor.process.wait(timeout=5)
            debug = Path('/tmp/secmon-reader-pause-debug-' + str(int(pidfd)))
            debug.mkdir(exist_ok=True)
            (debug / 'audit.jsonl').write_text(''.join(json.dumps(e) + '\n' for e in monitor.events()))
            (debug / 'diagnostics.log').write_text(monitor.diagnostics())
        stack.callback(cleanup)
        assert actor.request('r') == 0
        publish(2, delayed=True); call(build / 'secmon', 'reload', control)
        baseline = len(os.listdir(f'/proc/{monitor.process.pid}/fd'))
        local = subprocess.Popen(['cat', str(victim)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        until = time.monotonic() + 1
        while call(build / 'secmon', 'status', control)['pending'] != 1:
            assert time.monotonic() < until
        os.kill(provider.process.pid, signal.SIGSTOP); paused = True
        actor.process.stdin.write('r\n'); actor.process.stdin.flush(); actor_waiting = True
        time.sleep(.1)
        begin = time.monotonic(); state = call(build / 'secmon', 'status', control)
        latency = time.monotonic() - begin
        assert latency < .5 and state['revision'] == 2, (latency, state)
        output, error = local.communicate(timeout=1.5)
        assert local.returncode != 0 and output == b'', (output, error)
        state = call(build / 'secmon', 'status', control)
        assert state['pending'] == 0 and state['denied'] == 1 and state['allowed'] == 1, state
        # The reload helper also times out while the event reader is stuck.
        publish(3, epoch=2)
        rejected = call(build / 'secmon', 'reload', control, 'prepare_failed')
        assert rejected['revision'] == 2 and rejected['response_epoch'] == 1
        resume()
        read_result = actor.read(); actor_waiting = False
        assert read_result == str(errno.EPERM), ('resumed read', read_result, call(build / 'secmon', 'status', control))
        assert call(build / 'secmon', 'reload', control)['revision'] == 3
        assert actor.request('r') == 0
        time.sleep(.05)
        assert len(os.listdir(f'/proc/{monitor.process.pid}/fd')) == baseline
        # Stop while the reader is back inside a FUSE event-FD operation.
        os.kill(provider.process.pid, signal.SIGSTOP); paused = True
        actor.process.stdin.write('r\n'); actor.process.stdin.flush(); actor_waiting = True
        time.sleep(.1)
        begin = time.monotonic(); stopped = call(build / 'secmon', 'stop', control)
        stop_ack = time.monotonic() - begin
        assert stopped['revision'] == 3 and stop_ack < .5
        monitor.process.wait(timeout=5); assert monitor.process.returncode == 0
        resume()
        final_read = int(actor.read()); actor_waiting = False
        assert final_read in (0, errno.EPERM, errno.EINTR)
        events = monitor.events()
        permissions = [e for e in events if e['event'] == 'fanotify_decision']
        assert len(permissions) == 4, permissions
        local_events = [e for e in permissions if e['requester_pid'] == local.pid]
        assert len(local_events) == 1 and local_events[0]['reason'] == 'timeout' and local_events[0]['decision'] == 'deny'
        actor_events = [e for e in permissions if e['requester_pid'] == actor.process.pid]
        assert len(actor_events) == 3 and [e['revision'] for e in actor_events] == [1, 2, 3]
        if pidfd:
            assert len({e['requester_process_inode'] for e in actor_events}) == 1
            assert actor_events[0]['requester_process_inode'] > 0
        print(json.dumps({'pidfd': pidfd, 'status_ms': round(latency*1000, 2), 'stop_ack_ms': round(stop_ack*1000, 2),
                         'old_local_timeout': True, 'fuse_resume': True, 'fd_baseline': baseline,
                         'audited_verdicts': len(permissions), 'unpublished_stop_read_errno': final_read}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, default=Path('build'))
    args = parser.parse_args()
    if os.geteuid() != 0 or not __debug__: parser.error('run as root without Python optimization')
    for pidfd in (False, True): experiment(args.build_dir.resolve(), pidfd)
    print('PASS static FUSE event reader isolation, old deadlines, requester identity, recovery and stop')


if __name__ == '__main__': main()
