#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""A synthetic inode supports existing permission gates and bounded waiting."""
import argparse
from contextlib import ExitStack
import errno
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import time
from decoy_harness import DecoyView
from management_harness import call
from monitor_harness import MonitorRun
from virtual_decoy import DecoyActor


def experiment(build, event):
    with tempfile.TemporaryDirectory(prefix='secmon-virtual-fan-') as tmp, ExitStack() as stack:
        root = Path(tmp)
        mountpoint = root / 'view'; mountpoint.mkdir()
        stack.enter_context(DecoyView(build / 'secmon-decoyfs', mountpoint))
        trap, victim, policy = mountpoint / 'accounts.csv', root / 'victim', root / 'policy'
        victim.write_bytes(b'original' + b'\0' * 8192)
        actor = stack.enter_context(DecoyActor(build / 'secmon-virtual-decoy-scenario', trap, victim))
        identity = trap.stat()
        management = root / 'management'; management.mkdir(mode=0o700)
        control = management / 'control'
        def publish(revision, epoch, decision='allow'):
            stage = root / 'stage'
            stage.write_text(f'revision {revision}\ncanary "{trap}"\ncanary-response {epoch} 30000\n'
                             f'fanotify-file "{trap}"\nfanotify-event {event}\nfanotify-decision {decision}\n'
                             'fanotify-delay-ms 300\nfanotify-timeout-ms 2000\n')
            stage.chmod(0o600); stage.replace(policy)
        publish(1, 1)
        wrapper = root / 'combined'
        wrapper.write_text('#!/bin/sh\nshift\nexec ' + shlex.quote(str(build / 'secmon')) + ' "$@"\n')
        wrapper.chmod(0o700)
        monitor = stack.enter_context(MonitorRun(wrapper, ['--policy', str(policy), '--control', str(control),
                                                          '--audit-permissions', '--requester-pidfd']))
        def stop():
            if monitor.process.poll() is None:
                call(build / 'secmon', 'stop', control); monitor.process.wait(timeout=5)
        stack.callback(stop)
        before = time.monotonic()
        reader = subprocess.Popen(['cat', str(trap)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stack.callback(lambda: reader.kill() if reader.poll() is None else None)
        until = before + 2
        while True:
            state = call(build / 'secmon', 'status', control)
            if state['pending'] == 1:
                break
            assert time.monotonic() < until and reader.poll() is None, state
        assert actor.request('w') == 0
        assert actor.request('c') == actor.request('w') == errno.EACCES
        output, error = reader.communicate(timeout=5)
        assert reader.returncode == 0 and len(output) == 4096, (reader.returncode, error)
        assert time.monotonic() - before >= .25
        # A denied permission is an access decision, not a mutation contract.
        publish(2, 2, 'deny'); call(build / 'secmon', 'reload', control)
        assert actor.request('w') == 0
        denied = subprocess.run(['cat', str(trap)], capture_output=True, timeout=5)
        assert denied.returncode != 0
        assert actor.request('w') == 0
        state = call(build / 'secmon', 'status', control)
        assert state['response_started'] == 1 and state['response_failed'] == 0
        stop()
        records = monitor.events()
        permissions = [e for e in records if e['event'] == 'fanotify_decision']
        allowed = [e for e in permissions if e['decision'] == 'allow']
        denied_records = [e for e in permissions if e['decision'] == 'deny']
        # cat can issue a final EOF read: access gates audit reads, not commands.
        assert allowed and len(denied_records) == 1 and permissions[-1] == denied_records[0], permissions
        assert {e['requester_pid'] for e in allowed} == {reader.pid}
        assert denied_records[0]['requester_pid'] != reader.pid
        assert len({e['requester_process_inode'] for e in allowed}) == 1
        assert state['allowed'] == len(allowed) and state['denied'] == 1 and state['pending'] == 0
        for entry in permissions:
            assert (entry['major'], entry['minor'], entry['inode']) == (
                os.major(identity.st_dev), os.minor(identity.st_dev), identity.st_ino)
            assert entry['requester_process_inode'] > 0
        starts = [e for e in records if e.get('response_started')]
        assert len(starts) == 1 and starts[0]['pid'] == actor.process.pid
        assert starts[0]['process_inode'] not in {e['requester_process_inode'] for e in permissions}
        assert all(permissions[0][key] == permissions[-1][key] for key in ('major', 'minor', 'inode'))
        print(json.dumps({'event': event, 'pending_gate': True, 'permission_records': len(permissions),
                          'response_starts': len(starts), 'denied_read_not_mutation': True}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, default=Path('build'))
    args = parser.parse_args()
    assert os.geteuid() == 0 and __debug__
    for event in ('open', 'access'):
        experiment(args.build_dir.resolve(), event)
    print('PASS virtual FUSE inode fanotify open/access waiting, identity and BPF response')


if __name__ == '__main__':
    main()
