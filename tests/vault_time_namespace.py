#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Issue and consume a session in different shifted clock namespaces; outside-clock oracle."""
import argparse
from contextlib import ExitStack
import errno
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

from management_harness import call
from writer_harness import WriterProcess
from writer_lease import wait_expired


def experiment(build, issuer_offset, service_offset):
    with tempfile.TemporaryDirectory(prefix='secmon-vault-time-') as tmp, ExitStack() as stack:
        root = Path(tmp)
        program, target, policy, control = [root / name for name in ('client', 'secret', 'policy', 'control')]
        shutil.copyfile(build / 'secmon-writer-scenario', program)
        program.chmod(0o755)
        target.write_bytes(b'secret')
        actor = stack.enter_context(WriterProcess(program, target))
        before = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        line = subprocess.check_output(['unshare', '--time', '--boottime', str(issuer_offset),
                         '--monotonic', str(issuer_offset), '--fork', '--', str(build / 'secmon-vault-session'),
                         '--id', '1', '--program', str(program), '--uid', '0', '--target', str(target),
                         '--mode', 'read-write', '--duration-ms', '3000'], text=True, timeout=5)
        after = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        issued = int(line.split()[-1])
        assert before <= issued <= after
        deadline = issued + 3_000_000_000
        def publish(revision):
            stage = root / 'stage'
            stage.write_text(f'revision {revision}\nvault "{target}"\n' + line)
            stage.chmod(0o600)
            stage.replace(policy)
        publish(1)
        errors = stack.enter_context(tempfile.TemporaryFile(mode='w+'))
        output = stack.enter_context(tempfile.TemporaryFile(mode='w+'))
        process = subprocess.Popen(['unshare', '--time', '--boottime', str(service_offset),
                         '--monotonic', str(service_offset), '--fork', '--kill-child', '--', str(build / 'secmon'),
                         '--bpf-only', '--policy', str(policy), '--control', str(control), '--run-for', '20'],
                         stdout=output, stderr=errors)
        try:
            until = time.monotonic() + 5
            while True:
                errors.seek(0)
                diagnostics = errors.read()
                if 'Audit active;' in diagnostics:
                    break
                if process.poll() is not None or time.monotonic() >= until:
                    raise RuntimeError('vault namespace service failed: ' + diagnostics)
                time.sleep(0.02)
            status = call(build / 'secmon', 'status', control)
            assert status['vault_next_deadline_boot_ns'] == deadline and status['vault_live_sessions'] == 1
            assert actor.request('h') == actor.request('w') == 0
            publish(2)
            assert call(build / 'secmon', 'reload', control)['vault_next_deadline_boot_ns'] == deadline
            wait_expired(deadline)
            assert actor.request('h') == actor.request('w') == errno.EACCES
            assert call(build / 'secmon', 'status', control)['vault_live_sessions'] == 0
        finally:
            if process.poll() is None:
                subprocess.run([str(build / 'secmon'), '--stop', str(control)], capture_output=True, timeout=5)
                try:
                    process.wait(timeout=22)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                    raise
            assert process.returncode == 0
    print(f'PASS vault issuer offset={issuer_offset}, service offset={service_offset}, independent global expiry')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, default=Path('build'))
    args = parser.parse_args()
    if os.geteuid() != 0 or sys.flags.optimize:
        parser.error('requires root and Python assertions')
    count = len(os.listdir('/proc/self/fd'))
    for pair in ((3600, -60), (-60, 3600)):
        experiment(args.build_dir.resolve(), *pair)
        assert len(os.listdir('/proc/self/fd')) == count


if __name__ == '__main__':
    main()
