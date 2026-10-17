#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inspect actual credential keys across live threads, exit and non-leader exec."""
import argparse
import json
import os
from pathlib import Path
import select
import shutil
import tempfile
import subprocess
import time
from credential_map import CredentialMap
from monitor_harness import MonitorRun


class Scenario:
    def __init__(self, executable):
        self.process = subprocess.Popen([str(executable)], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.buffer = b''

    def phase(self, expected):
        deadline = time.monotonic() + 5
        while b'\n' not in self.buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.process.stdout], [], [], remaining)[0]:
                raise RuntimeError(f'lifecycle scenario stalled before {expected}')
            chunk = os.read(self.process.stdout.fileno(), 4096)
            if not chunk:
                self.process.wait(timeout=1)
                raise RuntimeError(f'lifecycle scenario exited before {expected}: ' +
                                   self.process.stderr.read().decode(errors='replace'))
            self.buffer += chunk
        line, self.buffer = self.buffer.split(b'\n', 1)
        data = json.loads(line)
        assert data['phase'] == expected, data
        assert data['pid'] == self.process.pid, data
        return data

    def command(self, text):
        self.process.stdin.write(text.encode() + b'\n')
        self.process.stdin.flush()

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.process.stdin.close()
        self.process.stdout.close()
        self.process.stderr.close()


def expect_keys(mapping, pid, tids):
    deadline = time.monotonic() + 3
    keys = set()
    while time.monotonic() < deadline:
        keys = mapping.keys_for_group(pid)
        if {tid for tid, _ in keys} == set(tids) and len(keys) == len(tids):
            return keys
        time.sleep(0.01)
    raise AssertionError(f'pid={pid}: expected tids={tids}, observed keys={keys}')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', default='build')
    parser.add_argument('--rounds', type=int, default=10)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('requires root/BPF Map inspection permissions')
    if not 1 <= args.rounds <= 100:
        parser.error('rounds must be 1..100')
    build = Path(args.build_dir).resolve()
    identities = []
    # The checkout may live under a 0700 home directory. Only the temporary
    # executable is made traversable for the child that drops to UID 65534.
    with tempfile.TemporaryDirectory(prefix='secmon-lifecycle-') as staging:
        Path(staging).chmod(0o755)
        helper = Path(staging) / 'scenario'
        shutil.copyfile(build / 'secmon-lifecycle-scenario', helper)
        helper.chmod(0o755)
        with MonitorRun(build / 'secmon', seconds=120) as audit:
            with CredentialMap(audit.process.pid) as mapping:
                for index in range(args.rounds):
                    scenario = Scenario(helper)
                    pid = scenario.process.pid
                    try:
                        ready = scenario.phase('threads_ready')
                        initial = expect_keys(mapping, pid, [pid, *ready['tids']])
                        assert all(start_ns > 0 for _, start_ns in initial)
                        credentials = [mapping.credentials(pid, key) for key in initial]
                        assert all(uid == 0 and euid == 0 for uid, euid, _ in credentials)
                        assert len({caps for _, _, caps in credentials}) == 1
                        scenario.command('join')
                        scenario.phase('threads_joined')
                        expect_keys(mapping, pid, [pid])
                        expected_uid = 0
                        if index % 2:
                            scenario.command('drop')
                            dropped = scenario.phase('credentials_dropped')
                            assert dropped['uid'] == dropped['euid'] == 65534
                            expected_uid = 65534
                            for key in expect_keys(mapping, pid, [pid]):
                                assert mapping.credentials(pid, key) == (65534, 65534, 0)
                        scenario.command('exec')
                        worker = scenario.phase('exec_worker')
                        complete = scenario.phase('exec_complete')
                        assert worker['tid'] != pid and complete['tid'] == pid
                        expect_keys(mapping, pid, [pid])
                        for key in expect_keys(mapping, pid, [pid]):
                            uid, euid, caps = mapping.credentials(pid, key)
                            assert uid == euid == expected_uid
                            if expected_uid:
                                assert caps == 0
                        identities.append((pid, worker['tid']))
                        scenario.command('exit')
                        scenario.process.wait(timeout=5)
                        assert scenario.process.returncode == 0
                        expect_keys(mapping, pid, [])
                    finally:
                        scenario.close()
                    print(f'PASS round {index + 1}: thread keys/credentials, join cleanup, uid={expected_uid} exec and final removal')
                audit.stop()
                events = audit.events()
                for pid, old_tid in identities:
                    assert any(event['event'] == 'exec_success' and event['pid'] == pid and
                               event['old_tid'] == old_tid and event['tid'] == pid for event in events)
                assert 'ringbuf_dropped=0' in audit.diagnostics()
                assert 'baseline_update_failed=0' in audit.diagnostics()
                # Holding an inspection FD in this test must not imply live links.
            print('PASS observed Map lifecycle keys and exec event identities, zero failure counters')


if __name__ == '__main__':
    main()
