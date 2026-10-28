#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Managed FUSE mount identity survives pauses and distinguishes pathname reuse."""
import argparse
from contextlib import ExitStack
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
from decoy_harness import mounted, DecoyView
from managed_decoy import ManagedRun


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=4)


def state(service, expected):
    until = time.monotonic() + 3
    while True:
        reply = service.status()
        if reply['decoy_mount_state'] == expected:
            assert reply['decoy_mount_id'] > 0 and reply['decoy_mount_errno'] == 0, reply
            assert reply['decoy_mount_sample_age_ms'] < 1000, reply
            return reply
        assert service.process.poll() is None and time.monotonic() < until, reply
        time.sleep(.02)


def case(build, mode):
    with tempfile.TemporaryDirectory(prefix='secmon-mount-identity-') as tmp, ExitStack() as stack:
        root = Path(tmp)
        service = ManagedRun(build, root, combined=False, mount_relative='site/view')
        stack.callback(service.close)
        initial = service.ready()
        assert initial['decoy_mount_state'] == 'attached', initial
        service.check()
        identity = initial['decoy_mount_id']
        foreign = None
        moved = None
        try:
            if mode in ('covered', 'ancestor'):
                foreign = service.view if mode == 'covered' else root / 'site'
                command('mount', '-t', 'tmpfs', '-o', 'size=1m,nodev,nosuid,noexec', 'secmon-test-foreign', str(foreign))
                (foreign / 'foreign-marker').write_text('must survive old service stop')
                expected = 'covered'
            elif mode == 'moved':
                (root / 'site').rename(root / 'renamed-site')
                moved = root / 'renamed-site' / 'view'
                service.view.mkdir(parents=True)
                expected = 'moved'
            elif mode == 'detached':
                command('umount', '-l', str(service.view))
                command('mount', '-t', 'tmpfs', '-o', 'size=1m,nodev,nosuid,noexec', 'secmon-test-foreign', str(service.view))
                foreign = service.view
                (foreign / 'foreign-marker').write_text('must survive old service stop')
                expected = 'detached'
            elif mode == 'uncovered':
                command('mount', '-t', 'tmpfs', 'secmon-test-foreign', str(service.view))
                foreign = service.view
                state(service, 'covered')
                service.check('decoy_mount_unavailable')
                command('umount', '-l', str(foreign))
                foreign = None
                state(service, 'attached')
                service.check()
                expected = 'attached'
            elif mode == 'paused':
                os.kill(service.provider_pid, signal.SIGSTOP)
                service.wait_state('unresponsive')
                assert state(service, 'attached')['decoy_provider_state'] == 'unresponsive'
                service.check('decoy_provider_unresponsive')
                os.kill(service.provider_pid, signal.SIGCONT)
                service.wait_state('responsive')
                service.check()
                expected = 'attached'
            else:
                raise AssertionError(mode)
            reply = state(service, expected)
            assert reply['decoy_mount_id'] == identity, reply
            if expected != 'attached':
                assert reply['decoy_provider_state'] == 'responsive', reply
                service.check('decoy_mount_unavailable')
            service.stop()
            if foreign:
                assert mounted(foreign) and (foreign / 'foreign-marker').read_text() == 'must survive old service stop'
            if moved:
                assert mounted(moved), 'Moved mount must require explicit operator cleanup'
            if mode in ('paused', 'uncovered'):
                assert not mounted(service.view), 'Normal original mount must unmount'
        finally:
            # These are test-created mounts at private unique paths, not a
            # production pathname-based attempt to discover ownership.
            if foreign and mounted(foreign): command('umount', '-l', str(foreign))
            if moved and mounted(moved): command('umount', '-l', str(moved))
        print(f'PASS managed mount {mode}: exact ID, sampled readiness and replacement preservation')


def untrusted_ancestors(build):
    with tempfile.TemporaryDirectory(prefix='secmon-mount-trust-') as tmp:
        root=Path(tmp)
        for mode in ('writable','foreign-owner'):
            parent=root/mode;parent.mkdir();view=parent/'view';view.mkdir()
            if mode=='writable':parent.chmod(0o777)
            else:os.chown(parent,65534,65534)
            result=subprocess.run([str(build/'secmon-decoyfs'),'--mountpoint',str(view),'--file','trap'],capture_output=True,timeout=2)
            assert result.returncode==2 and not mounted(view),(mode,result)
        outer=root/'outer';outer.mkdir()
        with DecoyView(build/'secmon-decoyfs',outer) as provider:
            os.kill(provider.process.pid,signal.SIGSTOP)
            try:
                result=subprocess.run([str(build/'secmon-decoyfs'),'--mountpoint',str(outer/'not-looked-up'),'--file','trap'],capture_output=True,timeout=2)
                assert result.returncode==2,result
            finally:os.kill(provider.process.pid,signal.SIGCONT)
    print('PASS mount ancestors: root ownership, non-writable path and stalled FUSE rejected without trusting synthetic UID/mode')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, default=Path('build'))
    args = parser.parse_args()
    if os.geteuid() != 0 or not __debug__: parser.error('requires root without optimization')
    untrusted_ancestors(args.build_dir.resolve())
    for mode in ('covered', 'ancestor', 'moved', 'detached', 'paused', 'uncovered'):
        case(args.build_dir.resolve(), mode)


if __name__ == '__main__': main()
