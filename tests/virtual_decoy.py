#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""FUSE synthetic inode -> existing BPF canary response, no PID message bridge."""
import argparse
from contextlib import ExitStack
import errno
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
from decoy_harness import DecoyView
from management_harness import call
from monitor_harness import MonitorRun
from writer_harness import WriterProcess


class DecoyActor(WriterProcess):
    def __init__(self, binary, trap, victim, prefix=()):
        self.lock = threading.Lock()
        self.process = subprocess.Popen([*prefix, str(binary), str(trap), str(victim)],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True, bufsize=1)
        try:
            assert self.read() == 'ready'
        except BaseException:
            self.close()
            raise


def experiment(build, unprivileged=False):
    with tempfile.TemporaryDirectory(prefix='secmon-virtual-decoy-') as tmp, ExitStack() as stack:
        root = Path(tmp); root.chmod(0o755)
        mountpoint = root / 'view'; mountpoint.mkdir(mode=0o755)
        view = stack.enter_context(DecoyView(build / 'secmon-decoyfs', mountpoint, allow_other=True))
        trap, other = mountpoint / 'accounts.csv', mountpoint / 'notes.txt'
        target_stat = trap.stat()
        original = trap.read_bytes()
        victim = root / 'victim'; victim.write_bytes(b'original' + b'\0' * 8192); victim.chmod(0o666)
        prefix = ['setpriv', '--reuid=65534', '--regid=65534', '--clear-groups'] if unprivileged else []
        actor = stack.enter_context(DecoyActor(build / 'secmon-virtual-decoy-scenario', trap, victim, prefix))
        outsider = stack.enter_context(DecoyActor(build / 'secmon-virtual-decoy-scenario', trap, victim, prefix))
        control_dir = root / 'management'; control_dir.mkdir(mode=0o700)
        control, policy = control_dir / 'control', root / 'policy'
        revision = 0
        def publish(epoch=1, duration=30000, selected=trap):
            nonlocal revision
            revision += 1
            stage = root / 'stage'
            stage.write_text(f'revision {revision}\ncanary "{selected}"\ncanary-response {epoch} {duration}\n')
            stage.chmod(0o600); stage.replace(policy)
        publish()
        monitor = stack.enter_context(MonitorRun(build / 'secmon', ['--policy', str(policy), '--control', str(control)], seconds=120))
        def stop():
            if monitor.process.poll() is None:
                call(build / 'secmon', 'stop', control); monitor.process.wait(timeout=5)
        stack.callback(stop)
        for command in (['ls', '-la', str(mountpoint)], ['sha256sum', str(trap)],
                        ['cp', str(trap), str(root / 'copy')],
                        ['tar', '-cf', str(root / 'backup.tar'), '-C', str(mountpoint), '.']):
            subprocess.run([*prefix, *command] if command[0] in ('ls', 'sha256sum') else command,
                           check=True, capture_output=True, timeout=5)
        assert actor.request('s') == actor.request('r') == actor.request('w') == 0
        assert call(build / 'secmon', 'status', control)['response_started'] == 0
        # Unknown control denial is not a declaration of malicious intent.
        assert actor.request('i') == errno.EACCES
        assert actor.request('w') == 0
        assert call(build / 'secmon', 'status', control)['response_started'] == 0
        # A file in the same FUSE view is not selected implicitly.
        other_actor = stack.enter_context(DecoyActor(build / 'secmon-virtual-decoy-scenario', other, victim, prefix))
        assert other_actor.request('c') == errno.EACCES  # FUSE itself rejects.
        assert other_actor.request('w') == 0
        mutations = 'ctunladmk'
        for index, operation in enumerate(mutations, 1):
            if index > 1:
                publish(index); call(build / 'secmon', 'reload', control)
            assert actor.request('w') == 0
            assert actor.request(operation) == errno.EACCES, operation
            assert actor.request('w') == actor.request('f') == errno.EACCES
            assert actor.request('x') == errno.EACCES
            assert actor.request('r') == actor.request('s') == 0
            assert outsider.request('w') == 0
            state = call(build / 'secmon', 'status', control)
            assert state['response_started'] == index and state['response_failed'] == 0, state
            assert trap.read_bytes() == original
        # Failed replacement preserves old inode/epoch and active containment.
        publish(len(mutations) + 1, selected=mountpoint / 'missing')
        failed = call(build / 'secmon', 'reload', control, 'prepare_failed')
        assert failed['response_epoch'] == len(mutations)
        assert actor.request('w') == errno.EACCES
        # Expiry and release do not depend on another policy publication.
        publish(len(mutations) + 1, duration=200)
        call(build / 'secmon', 'reload', control)
        assert actor.request('c') == actor.request('w') == errno.EACCES
        time.sleep(.25)
        assert actor.request('w') == 0
        stop()
        events = monitor.events()
        starts = [e for e in events if e.get('response_started')]
        assert len(starts) == len(mutations) + 1
        assert {e['pid'] for e in starts} == {actor.process.pid}
        assert len({e['process_inode'] for e in starts}) == 1
        for event in starts:
            assert (event['dev_major'], event['dev_minor'], event['ino']) == (
                os.major(target_stat.st_dev), os.minor(target_stat.st_dev), target_stat.st_ino), event
        assert len({e['response_epoch'] for e in starts}) == len(mutations) + 1
        assert 'ringbuf_dropped=0' in monitor.diagnostics()
        # Filesystem immutability remains after the security service has exited;
        # this alone must not be represented as cross-file response protection.
        assert actor.request('c') == errno.EACCES and actor.request('w') == 0
        print(json.dumps({'uid': 65534 if unprivileged else 0, 'mutations': len(mutations),
                          'response_starts': len(starts), 'inode': target_stat.st_ino,
                          'dev': target_stat.st_dev, 'read_backup_harmless': True,
                          'kernel_expiry': True, 'failed_reload_preserved': True}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, default=Path('build'))
    args = parser.parse_args()
    assert os.geteuid() == 0 and __debug__
    for unprivileged in (False, True):
        experiment(args.build_dir.resolve(), unprivileged)
    print('PASS synthetic FUSE inodes use existing BPF response for root and ordinary user')


if __name__ == '__main__':
    main()
