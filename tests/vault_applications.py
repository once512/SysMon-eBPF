#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real copied cat/dd clients: full plaintext reads, scoped writes and explicit locking."""
import argparse
import errno
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from management_harness import call
from monitor_harness import MonitorRun


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, default=Path('build'))
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('requires root')
    build = args.build_dir.resolve()
    baseline = len(os.listdir('/proc/self/fd'))
    with tempfile.TemporaryDirectory(prefix='secmon-vault-apps-') as tmp:
        root = Path(tmp)
        root.chmod(0o755)
        private = root / 'management'
        private.mkdir(mode=0o700)
        reader, writer, outsider = [root / name for name in ('cat-client', 'dd-client', 'dd-outsider')]
        for path, name in ((reader, 'cat'), (writer, 'dd'), (outsider, 'dd')):
            shutil.copyfile(shutil.which(name), path)
            path.chmod(0o755)
        target, policy, control = root / 'secret', root / 'policy', private / 'control'
        initial = bytes(range(256)) * 32
        payload = b'authorized edit'
        expected = payload + initial[len(payload):]
        target.write_bytes(initial)
        target.chmod(0o666)  # Let DAC permit operations; measure this policy layer.
        def drop():
            os.setgroups([])
            os.setgid(65534)
            os.setuid(65534)
        def read(uid=65534):
            return subprocess.run([str(reader), str(target)], capture_output=True, timeout=5,
                                  preexec_fn=drop if uid == 65534 else None)
        def write(program=writer):
            return subprocess.run([str(program), f'of={target}', 'bs=1', f'count={len(payload)}',
                                   'conv=notrunc', 'status=none'], input=payload, capture_output=True,
                                  preexec_fn=drop, timeout=5)
        def declare(identity, program, mode):
            return subprocess.check_output([str(build / 'secmon-vault-session'), '--id', str(identity),
                         '--program', str(program), '--uid', '65534', '--target', str(target),
                         '--mode', mode, '--duration-ms', '10000'], text=True, timeout=5)
        def publish(revision, sessions=''):
            stage = root / 'stage'
            stage.write_text(f'revision {revision}\nvault "{target}"\n' + sessions)
            stage.chmod(0o600)
            stage.replace(policy)
        publish(1)
        with MonitorRun(build / 'secmon', ['--policy', str(policy), '--control', str(control)], seconds=60) as monitor:
            try:
                for uid in (0, 65534):
                    result = read(uid)
                    assert result.returncode != 0 and not result.stdout
                assert write().returncode != 0
                publish(2, declare(1, reader, 'read') + declare(2, writer, 'read-write'))
                opened = call(build / 'secmon', 'reload', control)
                assert opened['vault_live_sessions'] == 2
                result = read()
                assert result.returncode == 0 and result.stdout == initial
                # Same executable, wrong EUID remains denied.
                result = read(0)
                assert result.returncode != 0 and not result.stdout
                assert write().returncode == 0
                assert write(outsider).returncode != 0
                result = read()
                assert result.returncode == 0 and result.stdout == expected
                publish(3)
                closed = call(build / 'secmon', 'reload', control)
                assert closed['vault_live_sessions'] == closed['vault_sessions'] == 0
                result = read()
                assert result.returncode != 0 and not result.stdout
                assert write().returncode != 0
                try:
                    target.read_bytes()
                    raise AssertionError('root controller bypassed vault locking')
                except OSError as error:
                    assert error.errno == errno.EACCES
            finally:
                call(build / 'secmon', 'stop', control)
                monitor.process.wait(timeout=5)
            assert 'ringbuf_dropped=0' in monitor.diagnostics()
        assert target.read_bytes() == expected
    assert len(os.listdir('/proc/self/fd')) == baseline
    print('PASS actual cat/dd: full 8192-byte read, authorized edit, UID/program separation, lock and byte verification')


if __name__ == '__main__':
    main()
