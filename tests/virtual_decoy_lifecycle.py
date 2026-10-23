#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pinned old mount, explicit rebinding and independent provider failure."""
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
from decoy_harness import DecoyView, mounted
from management_harness import call
from monitor_harness import MonitorRun
from virtual_decoy import DecoyActor


def lifecycle(build):
    with tempfile.TemporaryDirectory(prefix='secmon-virtual-lifecycle-') as tmp, ExitStack() as stack:
        root = Path(tmp)
        mountpoint = root / 'view'; mountpoint.mkdir()
        first = stack.enter_context(DecoyView(build / 'secmon-decoyfs', mountpoint))
        trap, victim = mountpoint / 'accounts.csv', root / 'victim'
        victim.write_bytes(b'original' + b'\0' * 8192)
        old_key = (trap.stat().st_dev, trap.stat().st_ino)
        old_actor = stack.enter_context(DecoyActor(build / 'secmon-virtual-decoy-scenario', trap, victim))
        policy = root / 'policy'
        management = root / 'management'; management.mkdir(mode=0o700)
        control = management / 'control'
        def publish(revision, epoch):
            stage = root / 'stage'
            stage.write_text(f'revision {revision}\ncanary "{trap}"\ncanary-response {epoch} 30000\n')
            stage.chmod(0o600); stage.replace(policy)
        publish(1, 1)
        monitor = stack.enter_context(MonitorRun(build / 'secmon', ['--policy', str(policy), '--control', str(control)]))
        def stop():
            if monitor.process.poll() is None:
                call(build / 'secmon', 'stop', control); monitor.process.wait(timeout=5)
        stack.callback(stop)
        assert old_actor.request('c') == old_actor.request('w') == errno.EACCES
        # A normal unmount cannot remove a mount with policy O_PATH and actor FDs.
        busy = subprocess.run(['fusermount3', '-u', str(mountpoint)], capture_output=True, timeout=5)
        assert busy.returncode != 0 and mounted(mountpoint)
        # Lazy detach is a deliberate exceptional administrative operation.
        subprocess.run(['fusermount3', '-uz', str(mountpoint)], check=True, capture_output=True, timeout=5)
        assert not mounted(mountpoint)
        # Detached connection may keep serving existing references until killed.
        if first.process.poll() is None:
            first.process.kill(); first.process.wait(timeout=5)
        assert old_actor.request('w') == errno.EACCES  # kernel response survives provider death.
        failed = call(build / 'secmon', 'status', control)
        assert failed['response_started'] == 1
        second = stack.enter_context(DecoyView(build / 'secmon-decoyfs', mountpoint))
        new_key = (trap.stat().st_dev, trap.stat().st_ino)
        assert old_key != new_key, (old_key, new_key)
        new_actor = stack.enter_context(DecoyActor(build / 'secmon-virtual-decoy-scenario', trap, victim))
        assert new_actor.request('c') == errno.EACCES  # immutable provider, not yet a selected canary.
        assert new_actor.request('w') == 0
        assert call(build / 'secmon', 'status', control)['response_started'] == 1
        publish(2, 2); call(build / 'secmon', 'reload', control)
        assert old_actor.request('w') == 0  # explicit epoch release, not implicit provider release.
        assert new_actor.request('c') == new_actor.request('w') == errno.EACCES
        # Server death while still mounted produces ENOTCONN on a fresh lookup;
        # containment remains until explicit epoch advance/expiry/service exit.
        second.process.kill(); second.process.wait(timeout=5)
        probe = subprocess.run(['cat', str(trap)], capture_output=True, timeout=5)
        assert probe.returncode != 0
        assert new_actor.request('w') == errno.EACCES
        publish(3, 3)
        reply = call(build / 'secmon', 'reload', control, 'prepare_failed')
        assert reply['revision'] == 2 and reply['response_epoch'] == 2
        assert new_actor.request('w') == errno.EACCES
        stop()
        events = monitor.events()
        starts = [e for e in events if e.get('response_started')]
        assert len(starts) == 2 and starts[0]['pid'] == old_actor.process.pid and starts[1]['pid'] == new_actor.process.pid
        assert [(os.makedev(e['dev_major'], e['dev_minor']), e['ino']) for e in starts] == [old_key, new_key]
        print(json.dumps({'old_key': old_key, 'new_key': new_key, 'normal_unmount_busy': True,
                          'explicit_rebind': True, 'provider_crash_does_not_release': True}))


def paused_monitor(build):
    with tempfile.TemporaryDirectory(prefix='secmon-virtual-paused-') as tmp, ExitStack() as stack:
        root = Path(tmp)
        mountpoint = root / 'view'; mountpoint.mkdir()
        stack.enter_context(DecoyView(build / 'secmon-decoyfs', mountpoint))
        trap, victim, policy = mountpoint / 'accounts.csv', root / 'victim', root / 'policy'
        victim.write_bytes(b'original' + b'\0' * 8192)
        actor = stack.enter_context(DecoyActor(build / 'secmon-virtual-decoy-scenario', trap, victim))
        policy.write_text(f'revision 1\ncanary "{trap}"\ncanary-response 1 500\n'); policy.chmod(0o600)
        # No management socket => self-protection is not enabled in this fixture.
        monitor = stack.enter_context(MonitorRun(build / 'secmon', ['--policy', str(policy)]))
        stopped = False
        def resume():
            nonlocal stopped
            if stopped:
                os.kill(monitor.process.pid, signal.SIGCONT); stopped = False
        stack.callback(resume)
        os.kill(monitor.process.pid, signal.SIGSTOP); stopped = True
        assert actor.request('c') == actor.request('w') == errno.EACCES
        assert actor.request('r') == 0
        time.sleep(.6)
        assert actor.request('w') == 0
        resume(); monitor.stop()
        assert len([e for e in monitor.events() if e.get('response_started')]) == 1
        print('PASS virtual canary response and absolute expiry with monitor SIGSTOP')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, default=Path('build'))
    args = parser.parse_args()
    assert os.geteuid() == 0 and __debug__
    lifecycle(args.build_dir.resolve())
    paused_monitor(args.build_dir.resolve())
    print('PASS virtual canary failure and remount lifecycle')


if __name__ == '__main__':
    main()
