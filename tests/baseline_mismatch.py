#!/usr/bin/env python3
# 只修改本次测试实例 Map 中受控任务的观测值，合成凭证不一致；没有修改任务真实凭证或执行提权攻击。
# SPDX-License-Identifier: MIT
"""Synthetic divergence in this test's own Map; never changes task credentials."""
import argparse
import ctypes
import os
from pathlib import Path
from credential_map import CredentialMap, Credentials, TaskKey
from lifecycle_harness import Scenario, expect_keys, lifecycle_helper
from monitor_harness import MonitorRun


def inject_field(mapping, pid, key, original, field):
    tid, start_ns = key
    assert tid == pid and original.uid == original.euid == 0
    raw = TaskKey((pid << 32) | tid, start_ns)
    altered = Credentials.from_buffer_copy(bytes(original))
    owner, name = (altered.details, field.split('.', 1)[1]) if field.startswith('details.') else (altered, field)
    setattr(owner, name, getattr(owner, name) ^ 1)
    update = mapping.lib.bpf_map_update_elem
    update.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64]
    update.restype = ctypes.c_int
    # BPF_EXIST updates only the exact held task in this test's own Map.
    if update(mapping.fd, ctypes.byref(raw), ctypes.byref(altered), 2):
        raise OSError(ctypes.get_errno(), 'inject synthetic baseline divergence')
    assert bytes(mapping.state(pid, key)) == bytes(altered)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', default='build')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('requires root/BPF Map permissions')
    build = Path(args.build_dir).resolve()
    cases = []
    with lifecycle_helper(build) as helper, MonitorRun(build / 'secmon') as audit:
        with CredentialMap(audit.process.pid) as mapping:
            fields = [None, 'uid', 'euid', 'caps'] + ['details.' + name for name in
                      ('suid', 'fsuid', 'gid', 'egid', 'sgid', 'fsgid', 'user_namespace_inode',
                       'caps_permitted', 'caps_inheritable', 'caps_bounding', 'caps_ambient')]
            for inject in fields:
                scenario = Scenario(helper)
                pid = scenario.process.pid
                try:
                    ready = scenario.phase('threads_ready')
                    expect_keys(mapping, pid, [pid, *ready['tids']])
                    scenario.command('join')
                    scenario.phase('threads_joined')
                    key, = expect_keys(mapping, pid, [pid])
                    original = mapping.state(pid, key)
                    if inject:
                        inject_field(mapping, pid, key, original, inject)
                    scenario.command('exec-leader')
                    leader = scenario.phase('exec_leader')
                    complete = scenario.phase('exec_complete')
                    assert leader['tid'] == complete['tid'] == pid
                    current, = expect_keys(mapping, pid, [pid])
                    assert bytes(mapping.state(pid, current)) == bytes(original)
                    scenario.command('exit')
                    scenario.process.wait(timeout=5)
                    assert scenario.process.returncode == 0
                    expect_keys(mapping, pid, [])
                    cases.append((pid, inject))
                finally:
                    scenario.close()
            audit.stop()
            events = audit.events()
            for pid, inject in cases:
                checks = [event for event in events if event['event'] == 'exec_check' and
                          event['pid'] == pid and event['filename'] == str(helper)]
                successes = [event for event in events if event['event'] == 'exec_success' and
                             event['pid'] == pid and event['filename'] == str(helper)]
                assert len(checks) >= 2 and len(successes) >= 2
                latest = max(checks, key=lambda event: event['timestamp_ns'])
                assert latest['flags'] == (1 if inject else 0), latest
                assert latest['uid'] == latest['euid'] == 0
                assert all(event['flags'] == 0 for event in successes)
                print(f'PASS {inject or "clean control"}: check flags, real credentials and complete refreshed baseline')
            assert 'ringbuf_dropped=0' in audit.diagnostics()
            assert 'baseline_update_failed=0' in audit.diagnostics()
    print('PASS synthetic flag pipeline; no real credential modification or exploit')


if __name__ == '__main__':
    main()
