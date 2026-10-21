#!/usr/bin/env python3
# 临时普通/setuid/file-capability 程序报告真实权限，用它核对执行事件；测试结束清理临时权限设置。
# SPDX-License-Identifier: MIT
"""Legitimate setuid and file-capability execs using root-owned temporary helpers."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from monitor_harness import MonitorRun


def execute(path, namespace=False):
    command = ['unshare', '--user', '--map-root-user', '--', str(path)] if namespace else [str(path)]
    options = {} if namespace else dict(user=65534, group=65534, extra_groups=[])
    child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **options)
    try:
        output, errors = child.communicate(timeout=5)
    except BaseException:
        child.kill()
        child.wait(timeout=5)
        raise
    assert child.returncode == 0, errors.decode(errors='replace')
    report = json.loads(output)
    assert report['pid'] == child.pid
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', default='build')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('requires root/BPF, setuid and file-capability setup permissions')
    if shutil.which('unshare') is None:
        parser.error('requires unshare for the user-namespace credential fixture')
    if shutil.which('setcap') is None:
        parser.error('requires setcap (libcap tools)')
    build = Path(args.build_dir).resolve()
    with tempfile.TemporaryDirectory(prefix='secmon-credentials-') as temporary:
        directory = Path(temporary)
        directory.chmod(0o755)
        plain, setuid, setgid, capability, userns = [directory / name for name in ('plain', 'setuid', 'setgid', 'capability', 'userns')]
        for path in (plain, setuid, setgid, capability, userns):
            shutil.copyfile(build / 'secmon-privilege-report', path)
            path.chmod(0o755)
            assert path.stat().st_uid == 0
        # Modes/xattrs affect only the temporary copies and disappear on cleanup.
        setuid.chmod(0o4755)
        setgid.chmod(0o2755)
        subprocess.run(['setcap', 'cap_net_bind_service=ep', str(capability)],
                       capture_output=True, text=True, check=True, timeout=5)
        with MonitorRun(build / 'secmon') as audit:
            reports = {path: execute(path) for path in (plain, setuid, setgid, capability)}
            reports[userns] = execute(userns, namespace=True)
            assert reports[userns]['user_namespace_inode'] != os.stat('/proc/self/ns/user').st_ino
            assert reports[userns]['uid'] == reports[userns]['euid'] == 0
            assert reports[setgid]['gid'] == 65534 and reports[setgid]['egid'] == 0
            assert reports[setgid]['sgid'] == reports[setgid]['fsgid'] == 0
            assert reports[plain]['uid'] == reports[plain]['euid'] == 65534
            assert reports[plain]['caps'] == 0
            assert reports[setuid]['uid'] == 65534 and reports[setuid]['euid'] == 0, \
                'setuid not applied (check nosuid/no_new_privs and mount/LSM settings)'
            assert reports[setuid]['caps'] != 0
            expected_capability = 1 << 10  # CAP_NET_BIND_SERVICE
            assert reports[capability]['uid'] == reports[capability]['euid'] == 65534
            assert reports[capability]['caps'] == expected_capability, \
                'file capability not applied (check bounding set and mount/LSM settings)'
            audit.stop()
            events = audit.events()
            for path, report in reports.items():
                matching = [event for event in events if event['pid'] == report['pid'] and
                            event.get('filename') == str(path)]
                checks = [event for event in matching if event['event'] == 'exec_check']
                successes = [event for event in matching if event['event'] == 'exec_success']
                assert checks and successes, (path, matching)
                expected_uid = 0 if path == userns else 65534
                assert all(event['uid'] == event['euid'] == expected_uid for event in checks), checks
                if path != userns:
                    assert all(event['caps'] == 0 for event in checks), checks
                # bprm_check_security precedes final setuid/file-capability calculation.
                assert all(event['target_euid'] == expected_uid for event in checks), checks
                assert all(event['uid'] == report['uid'] and event['euid'] == report['euid'] and
                           event['caps'] == report['caps'] and event['target_euid'] == report['euid']
                           for event in successes), successes
                details = ('suid', 'fsuid', 'gid', 'egid', 'sgid', 'fsgid', 'caps_permitted',
                           'caps_inheritable', 'caps_bounding', 'caps_ambient', 'user_namespace_inode')
                assert all(all(event[name] == report[name] for name in details) for event in successes), (successes, report)
                assert all(event['flags'] == 0 for event in matching), matching
                print(f'PASS {path.name}: check/completion credentials match actual process report')
            assert 'ringbuf_dropped=0' in audit.diagnostics()
            assert 'baseline_update_failed=0' in audit.diagnostics()
        print('PASS legitimate credential transitions (not an attack-detection test)')


if __name__ == '__main__':
    main()
