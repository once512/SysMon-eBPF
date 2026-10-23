#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""A stopped FUSE provider cannot stall management or a live permission gate."""
import argparse
from contextlib import ExitStack
import errno
import json
import os
from pathlib import Path
import signal
import shlex
import subprocess
import tempfile
import time
from decoy_harness import DecoyView
from management_harness import call
from monitor_harness import MonitorRun
from virtual_decoy import DecoyActor


def reply(process, code):
    output, error = process.communicate(timeout=4)
    value = json.loads(output)
    assert value['code'] == code and (process.returncode == 0) == (code == 'ok'), (value, error)
    return value


def experiment(build, combined):
    with tempfile.TemporaryDirectory(prefix='secmon-bounded-preparation-') as tmp, ExitStack() as stack:
        root = Path(tmp)
        mountpoint = root / 'view'; mountpoint.mkdir()
        provider = stack.enter_context(DecoyView(build / 'secmon-decoyfs', mountpoint))
        trap, victim, policy = mountpoint / 'accounts.csv', root / 'victim', root / 'policy'
        victim.write_bytes(b'original' + b'\0' * 8192)
        actor = stack.enter_context(DecoyActor(build / 'secmon-virtual-decoy-scenario', trap, victim))
        management = root / 'management'; management.mkdir(mode=0o700)
        control = management / 'control'
        def publish(revision, epoch):
            text = f'revision {revision}\ncanary "{trap}"\ncanary-response {epoch} 30000\n'
            if combined:
                text += f'fanotify-file "{victim}"\nfanotify-event access\nfanotify-decision allow\n'
                text += 'fanotify-delay-ms 150\nfanotify-timeout-ms 1000\n'
            stage = root / 'stage'; stage.write_text(text); stage.chmod(0o600); stage.replace(policy)
        publish(1, 1)
        wrapper = root / 'combined'
        wrapper.write_text('#!/bin/sh\nshift\nexec ' + shlex.quote(str(build / 'secmon')) + ' "$@"\n')
        wrapper.chmod(0o700)
        monitor = stack.enter_context(MonitorRun(wrapper if combined else build / 'secmon',
            ['--policy', str(policy), '--control', str(control)] +
            (['--audit-permissions', '--requester-pidfd'] if combined else [])))
        paused = False
        reloaders = []
        def cleanup():
            nonlocal paused
            if paused:
                os.kill(provider.process.pid, signal.SIGCONT); paused = False
            for process in reloaders:
                if process.poll() is None:
                    process.kill(); process.wait(timeout=5)
            if monitor.process.poll() is None:
                call(build / 'secmon', 'stop', control); monitor.process.wait(timeout=5)
        stack.callback(cleanup)
        assert actor.request('r') == 0  # populate page cache before provider pause
        assert actor.request('c') == actor.request('w') == errno.EACCES
        baseline = len(os.listdir(f'/proc/{monitor.process.pid}/fd'))
        def start_reload():
            process = subprocess.Popen([str(build / 'secmon'), '--reload', str(control)],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            reloaders.append(process)
            time.sleep(.15)
            assert process.poll() is None
            return process
        os.kill(provider.process.pid, signal.SIGSTOP); paused = True
        publish(2, 2)
        begin = time.monotonic(); pending = start_reload()
        status_begin = time.monotonic()
        status = call(build / 'secmon', 'status', control)
        latency = time.monotonic() - status_begin
        assert latency < .5 and status['revision'] == 1 and status['response_epoch'] == 1, (latency, status)
        busy = call(build / 'secmon', 'reload', control, 'busy')
        assert busy['revision'] == 1 and busy['rejections'] == 1
        assert actor.request('w') == errno.EACCES
        reader_pid = None
        if combined:
            # A healthy local target must continue under the OLD decision while
            # a different FUSE inode is stuck in candidate preparation.
            reader = subprocess.Popen(['cat', str(victim)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            reader_pid = reader.pid
            try:
                output, error = reader.communicate(timeout=1.5)
            finally:
                if reader.poll() is None: reader.kill(); reader.wait(timeout=5)
            assert reader.returncode == 0 and len(output) == 8200, error
            gate = call(build / 'secmon', 'status', control)
            assert gate['allowed'] >= 1 and gate['pending'] == 0
        rejected = reply(pending, 'prepare_failed')
        elapsed = time.monotonic() - begin
        assert 1.5 <= elapsed < 3 and rejected['revision'] == 1 and rejected['response_epoch'] == 1
        assert rejected['rejections'] == 2
        time.sleep(.1)  # normal-loop reap of the killed preparation child
        assert len(os.listdir(f'/proc/{monitor.process.pid}/fd')) == baseline
        os.kill(provider.process.pid, signal.SIGCONT); paused = False
        assert actor.request('w') == errno.EACCES  # failure never releases the old response
        success = call(build / 'secmon', 'reload', control)
        assert success['revision'] == 2 and success['response_epoch'] == 2
        assert actor.request('w') == 0
        # A worker must not reinterpret proc/self as its own process.
        stage = root / 'stage'
        stage.write_text(f'revision 3\nprotect "/proc/self/status"\ncanary "{trap}"\ncanary-response 3 30000\n' +
                         (f'fanotify-file "{victim}"\nfanotify-event access\nfanotify-decision allow\n' if combined else ''))
        stage.chmod(0o600); stage.replace(policy)
        assert call(build / 'secmon', 'reload', control, 'prepare_failed')['revision'] == 2
        # Cancel another blocked preparation via stop, while provider stays stopped.
        os.kill(provider.process.pid, signal.SIGSTOP); paused = True
        publish(4, 3); pending_stop = start_reload()
        stop_begin = time.monotonic()
        stopped = call(build / 'secmon', 'stop', control)
        assert stopped['revision'] == 2 and time.monotonic() - stop_begin < .5
        assert reply(pending_stop, 'prepare_failed')['revision'] == 2
        monitor.process.wait(timeout=5)
        assert monitor.process.returncode == 0
        os.kill(provider.process.pid, signal.SIGCONT); paused = False
        events = monitor.events()
        starts = [event for event in events if event.get('response_started')]
        assert len(starts) == 1 and starts[0]['response_epoch'] == 1
        if combined:
            permissions = [e for e in events if e['event'] == 'fanotify_decision']
            assert permissions and all(e['decision'] == 'allow' and e['revision'] == 1 and
                                      e['requester_pid'] == reader_pid for e in permissions)
        print(json.dumps({'combined': combined, 'status_latency_ms': round(latency * 1000, 2),
                          'preparation_timeout_seconds': round(elapsed, 3), 'busy_counted': True,
                          'old_response_preserved': True, 'stop_cancelled': True,
                          'service_fd_baseline': baseline}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, default=Path('build'))
    args = parser.parse_args()
    if os.geteuid() != 0 or not __debug__:
        parser.error('run as root without Python optimization')
    for combined in (False, True):
        experiment(args.build_dir.resolve(), combined)
    print('PASS bounded FUSE preparation, responsive management, old permission gate and cancellation')


if __name__ == '__main__':
    main()
