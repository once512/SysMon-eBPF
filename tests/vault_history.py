#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exhaust the declared instance session history; closing must still work at capacity."""
import argparse
import os
from pathlib import Path
import shutil
import tempfile
import time

from management_harness import call
from monitor_harness import MonitorRun


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, default=Path('build'))
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('requires root')
    build = args.build_dir.resolve()
    count = len(os.listdir('/proc/self/fd'))
    with tempfile.TemporaryDirectory(prefix='secmon-vault-history-') as tmp:
        root = Path(tmp)
        program, target, policy, control = [root / name for name in ('client', 'secret', 'policy', 'control')]
        shutil.copyfile(build / 'secmon-writer-scenario', program)
        program.chmod(0o755)
        target.write_bytes(b'secret')
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        issued = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        def publish(revision, identities):
            text = f'revision {revision}\nvault "{target}"\n'
            text += ''.join(f'vault-session {ident} "{program}" 0 "{target}" read 100 {boot} {issued}\n'
                            for ident in identities)
            stage = root / 'stage'
            stage.write_text(text)
            stage.chmod(0o600)
            stage.replace(policy)
        publish(1, [])
        with MonitorRun(build / 'secmon', ['--policy', str(policy), '--control', str(control)], seconds=120) as monitor:
            try:
                def fds():
                    return len(list(Path(f'/proc/{monitor.process.pid}/fd').iterdir()))
                baseline = fds()
                for batch in range(256):
                    revision = batch + 2
                    publish(revision, range(batch * 16 + 1, batch * 16 + 17))
                    status = call(build / 'secmon', 'reload', control)
                    assert status['vault_sessions'] == 16 and status['vault_session_history'] == (batch + 1) * 16
                    assert status['revision'] == revision
                    if batch % 32 == 0:
                        assert fds() == baseline + 16
                publish(258, [4097])
                rejected = call(build / 'secmon', 'reload', control, 'prepare_failed')
                assert rejected['revision'] == 257 and rejected['vault_session_history'] == 4096
                assert fds() == baseline + 16
                publish(258, [])
                closed = call(build / 'secmon', 'reload', control)
                assert closed['vault_sessions'] == 0 and closed['vault_session_history'] == 4096
                assert fds() == baseline
                for identity in (4097, 4096):
                    publish(259, [identity])
                    rejected = call(build / 'secmon', 'reload', control, 'prepare_failed')
                    assert rejected['revision'] == 258 and rejected['vault_sessions'] == 0
                    assert fds() == baseline
            finally:
                call(build / 'secmon', 'stop', control)
                monitor.process.wait(timeout=5)
    assert len(os.listdir('/proc/self/fd')) == count
    print('PASS 4096-ID history capacity, no silent eviction/reopening, close-at-capacity, late failure and exact FD recovery')


if __name__ == '__main__':
    main()
