#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# 两个私有 PID namespace 都复用局部 PID=1，核对 BPF 使用的宿主任务身份、凭证与退出清理；不声称真实宿主 PID 复用。
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import time
from credential_map import CredentialMap
from monitor_harness import MonitorRun

HELPER = r'''
import json,os,sys
status=open('/proc/self/status').read().splitlines()
caps=int(next(x.split()[1] for x in status if x.startswith('CapEff:')),16)
print(json.dumps({'local_pid':os.getpid(),'local_ppid':os.getppid(),
                  'proc_pid':int(open('/proc/self/stat').read().split()[0]),
                  'uid':os.getuid(),'euid':os.geteuid(),'caps':caps}),flush=True)
assert sys.stdin.readline().strip()=='exit'
'''


@contextmanager
def incarnation():
    with tempfile.TemporaryFile(mode='w+') as errors:
        process = subprocess.Popen(['unshare', '--mount', '--pid', '--fork', '--mount-proc',
                                    '--propagation', 'private', '--kill-child=KILL', '--',
                                    sys.executable, '-u', '-c', HELPER], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=errors, text=True)
        try:
            ready, _, _ = select.select([process.stdout], [], [], 5)
            assert ready, 'namespace init did not report readiness'
            line = process.stdout.readline()
            if not line:
                errors.seek(0)
                raise RuntimeError(errors.read())
            local = json.loads(line)
            # unshare 监督进程留在宿主 PID namespace，仅 fork 的 init 进入新 namespace。
            children = Path(f'/proc/{process.pid}/task/{process.pid}/children').read_text().split()
            assert len(children) == 1, children
            host_pid = int(children[0])
            host_status = Path(f'/proc/{host_pid}/status').read_text().splitlines()
            mapped = [int(x) for x in next(row for row in host_status if row.startswith('NSpid:')).split()[1:]]
            assert mapped[0] == host_pid and mapped[-1] == 1, mapped
            yield process, host_pid, local
        finally:
            if process.poll() is None:
                try:
                    process.stdin.write('exit\n')
                    process.stdin.flush()
                    process.wait(timeout=5)
                except (BrokenPipeError, subprocess.TimeoutExpired):
                    process.kill()  # --kill-child 确保 namespace init 一并退出。
                    process.wait(timeout=5)
            process.stdin.close()
            process.stdout.close()
            errors.seek(0)
            assert process.returncode == 0, errors.read()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', default='build')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('requires root/BPF and mount/PID-namespace permissions')
    binary = Path(args.build_dir).resolve() / 'secmon'
    seen = []
    with MonitorRun(binary, seconds=60) as monitor:
        with CredentialMap(monitor.process.pid) as mapping:
            for _ in range(2):
                with incarnation() as (process, host_pid, local):
                    assert local['local_pid'] == local['proc_pid'] == 1 and local['local_ppid'] == 0
                    assert host_pid != local['local_pid']
                    keys = mapping.keys_for_group(host_pid)
                    assert len(keys) == 1 and next(iter(keys))[0] == host_pid, keys
                    key = next(iter(keys))
                    assert mapping.credentials(host_pid, key) == (local['uid'], local['euid'], local['caps'])
                    seen.append((host_pid, key))
                deadline = time.monotonic() + 3
                while mapping.keys_for_group(host_pid):
                    assert time.monotonic() < deadline, 'namespace task baseline survived exit'
                    time.sleep(0.01)
            assert seen[0] != seen[1] and seen[0][0] != seen[1][0]
        monitor.stop()
        events = monitor.events()
        for host_pid, _ in seen:
            success = [e for e in events if e['event'] == 'exec_success' and e['pid'] == host_pid]
            assert success and all(e['tid'] == host_pid for e in success)
        assert 'baseline_update_failed=0' in monitor.diagnostics()
    print('PASS namespace-local PID 1 maps to distinct host BPF keys, observed credentials and exec events')
    print('PASS each namespace exit deletes its baseline; no host PID-reuse or full-container claim')


if __name__ == '__main__':
    main()
