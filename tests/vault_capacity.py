#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Joint 256-target/64-writer/16-session capacity, slot 15 and rollback FD accounting."""
import argparse
import errno
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from file_policy_map import PolicyMapView, key_for, policy_outer_ids
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
    with tempfile.TemporaryDirectory(prefix='secmon-vault-capacity-') as tmp:
        root = Path(tmp)
        files = [root / f'data-{i}' for i in range(256)]
        writers = [root / f'writer-{i}' for i in range(64)]
        clients = [root / f'client-{i}' for i in range(16)]
        for path in files:
            path.write_bytes(b'secret')
        for path in writers + clients:
            shutil.copyfile(build / 'secmon-writer-scenario', path)
            path.chmod(0o755)
        policy, control = root / 'policy', root / 'control'
        def publish(revision, enabled=True, missing=False):
            text = f'revision {revision}\n'
            if enabled:
                text += ''.join(f'protect "{p}"\n' for p in files[:-1]) + f'vault "{files[-1]}"\n'
                text += ''.join(f'allow-writer "{p}" 0 "{files[0]}" all\n' for p in writers)
                text += ''.join(f'vault-session {i+1} "{p if not missing or i != 15 else root / "missing"}" '
                                f'{0 if i == 15 else 65534} "{files[-1]}" read 10000\n'
                                for i, p in enumerate(clients))
            stage = root / 'stage'
            stage.write_text(text)
            stage.chmod(0o600)
            stage.replace(policy)
        publish(1, enabled=False)
        before = policy_outer_ids()
        with MonitorRun(build / 'secmon', ['--policy', str(policy), '--control', str(control)], seconds=120) as monitor:
            view = None
            try:
                created = policy_outer_ids() - before
                assert len(created) == 1
                outer = next(iter(created))
                def fds():
                    return len(list(Path(f'/proc/{monitor.process.pid}/fd').iterdir()))
                baseline = fds()
                publish(2)
                opened = call(build / 'secmon', 'reload', control)
                assert (opened['protected_paths'], opened['writer_paths'], opened['vault_paths'],
                        opened['vault_sessions'], opened['vault_session_history']) == (256, 64, 1, 16, 16)
                assert fds() == baseline + 336
                view = PolicyMapView(outer)
                assert len(view.entries()) == 336
                value = view.vault_entry(files[-1])
                assert value.flags == 9
                assert all(g.access == 1 and g.deadline_boot_ns for g in value.vault_sessions)
                assert [g.euid for g in value.vault_sessions] == [65534] * 15 + [0]
                for i, client in enumerate(clients):
                    assert view.vault_entry(client).vault_subjects == 1 << i
                    result = subprocess.run([str(client), 'read', str(files[-1])], timeout=5)
                    assert result.returncode == (0 if i == 15 else errno.EACCES)
                subprocess.run([str(writers[-1]), 'write', str(files[0])], check=True, timeout=5)
                publish(3, missing=True)
                call(build / 'secmon', 'reload', control, 'prepare_failed')
                assert fds() == baseline + 336
                with PolicyMapView(outer) as same:
                    assert same.map_id == view.map_id
                publish(3, enabled=False)
                closed = call(build / 'secmon', 'reload', control)
                assert (closed['vault_paths'], closed['vault_sessions'], closed['vault_live_sessions'],
                        closed['vault_session_history'], closed['vault_next_deadline_boot_ns']) == (0, 0, 0, 16, 0)
                assert fds() == baseline
                # External old-map reference sees its complete immutable snapshot.
                assert len(view.entries()) == 336
                old_id = view.map_id
                view.close()
                view.wait_gone(old_id)
            finally:
                if view:
                    view.close()
                call(build / 'secmon', 'stop', control)
                monitor.process.wait(timeout=5)
    assert len(os.listdir('/proc/self/fd')) == count
    print('PASS joint 336-inode capacity, session bit 15, scoped UID, late failure rollback and FD/Map reclamation')


if __name__ == '__main__':
    main()
