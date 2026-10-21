#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Namespace-local root must remain an unprivileged global kuid/kgid in audit."""
import argparse
import json
import errno
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from monitor_harness import MonitorRun


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, default=Path('build'))
    args = parser.parse_args()
    if os.geteuid() != 0 or sys.flags.optimize or os.environ.get('PYTHONOPTIMIZE'):
        parser.error('run as root without Python optimization')
    build = args.build_dir.resolve()
    with tempfile.TemporaryDirectory(prefix='secmon-userns-') as directory:
        root = Path(directory)
        root.chmod(0o755)
        helper = root / 'report'
        shutil.copyfile(build / 'secmon-privilege-report', helper)
        helper.chmod(0o755)
        assert helper.stat().st_uid == 0
        writer, target, config = root / 'writer', root / 'data', root / 'policy'
        shutil.copyfile(build / 'secmon-writer-scenario', writer)
        writer.chmod(0o755)
        target.write_bytes(b'unchanged')
        target.chmod(0o666)  # DAC permits both actors; the BPF grant must decide.
        config.write_text(f'revision 1\nprotect "{target}"\nallow-writer "{writer}" 0 "{target}" open-write,write\n')
        config.chmod(0o600)
        with MonitorRun(build / 'secmon', ['--policy', str(config)]) as audit:
            process = subprocess.Popen(['unshare', '--user', '--map-root-user', '--', str(helper)],
                                       user=65534, group=65534, extra_groups=[],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                output, errors = process.communicate(timeout=5)
            except BaseException:
                process.kill()
                process.wait(timeout=5)
                raise
            assert process.returncode == 0, errors.decode(errors='replace')
            report = json.loads(output)
            assert report['pid'] == process.pid
            ids = ('uid', 'euid', 'suid', 'fsuid', 'gid', 'egid', 'sgid', 'fsgid')
            assert all(report[name] == 0 for name in ids), report
            assert report['user_namespace_inode'] != os.stat('/proc/self/ns/user').st_ino
            assert subprocess.run([str(writer), 'write', str(target)], timeout=5).returncode == 0
            allowed_bytes = target.read_bytes()
            local_root = subprocess.run(['unshare', '--user', '--map-root-user', '--', str(writer), 'write', str(target)],
                                        user=65534, group=65534, extra_groups=[], capture_output=True, timeout=5)
            assert local_root.returncode == errno.EACCES, local_root.stderr
            assert target.read_bytes() == allowed_bytes
            audit.stop()
            all_events = audit.events()
            denied = [r for r in all_events if r['event'] == 'file_denied']
            assert denied and all(r['uid'] == r['euid'] == 65534 for r in denied)
            events = [r for r in all_events if r.get('filename') == str(helper) and r['pid'] == process.pid]
            checks = [r for r in events if r['event'] == 'exec_check']
            success = [r for r in events if r['event'] == 'exec_success']
            assert checks and success
            for row in events:
                # Local namespace root maps only the unprivileged outer ID, not host root.
                assert all(row[name] == 65534 for name in ids), row
                assert row['user_namespace_inode'] == report['user_namespace_inode']
                assert row['flags'] == 0
            for row in success:
                assert row['target_euid'] == 65534
                for name in ('caps', 'caps_permitted', 'caps_inheritable', 'caps_bounding', 'caps_ambient'):
                    assert row[name] == report[name], (row, report)
            assert 'ringbuf_dropped=0' in audit.diagnostics()
            assert 'baseline_update_failed=0' in audit.diagnostics()
        print('PASS local userns root: global 65534/capability context preserved and host-root writer grant not inherited')


if __name__ == '__main__':
    main()
