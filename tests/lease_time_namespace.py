#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent outer-clock oracle for leased services in shifted time namespaces."""
import argparse
from contextlib import ExitStack
import errno
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from file_policy_map import PolicyMapView, policy_outer_ids, key_for
from management_harness import call
from writer_harness import WriterProcess


def experiment(build, offset):
    with tempfile.TemporaryDirectory(prefix='secmon-lease-time-') as temporary, ExitStack() as stack:
        root = Path(temporary)
        writer, data, policy, control = [root / name for name in ('writer', 'data', 'policy', 'control')]
        shutil.copyfile(build / 'secmon-writer-scenario', writer)
        writer.chmod(0o755)
        data.write_bytes(b'original')
        policy.write_text(f'revision 1\nprotect "{data}"\nallow-writer "{writer}" 0 "{data}" open-write,write\nwriter-lease-ms 3000\n')
        policy.chmod(0o600)
        actor = stack.enter_context(WriterProcess(writer, data))
        before = policy_outer_ids()
        errors = stack.enter_context(tempfile.TemporaryFile(mode='w+'))
        output = stack.enter_context(tempfile.TemporaryFile(mode='w+'))
        process = subprocess.Popen(['unshare', '--time', '--boottime', str(offset), '--monotonic', str(offset),
                                    '--fork', '--kill-child', '--', str(build / 'secmon'), '--bpf-only',
                                    '--policy', str(policy), '--control', str(control), '--run-for', '10'],
                                   stdout=output, stderr=errors)
        try:
            until = time.monotonic() + 5
            while True:
                errors.seek(0)
                diagnostics = errors.read()
                if 'Audit active;' in diagnostics:
                    break
                if process.poll() is not None or time.monotonic() >= until:
                    raise RuntimeError('time namespace service failed: ' + diagnostics)
                time.sleep(0.02)
            created = policy_outer_ids() - before
            assert len(created) == 1
            with PolicyMapView(next(iter(created))) as mapping:
                expiry = mapping.entries(full=True, with_deadlines=True)[key_for(writer)][-1]
            # This parent remains outside the namespace. Neither the expected
            # deadline nor its wait subtracts/reuses the service offset code.
            remaining = expiry - time.clock_gettime_ns(time.CLOCK_BOOTTIME)
            assert 0 < remaining <= 3_000_000_000, (offset, remaining)
            assert actor.request('w') == actor.request('o') == 0
            while time.clock_gettime_ns(time.CLOCK_BOOTTIME) <= expiry + 20_000_000:
                time.sleep(0.02)
            assert actor.request('w') == actor.request('o') == errno.EACCES
            call(build / 'secmon', 'stop', control)
            process.wait(timeout=5)
            assert process.returncode == 0
            errors.seek(0)
            diagnostics = errors.read()
            assert 'ringbuf_dropped=0' in diagnostics and 'baseline_update_failed=0' in diagnostics
        finally:
            if process.poll() is None:
                subprocess.run([str(build / 'secmon'), '--stop', str(control)], capture_output=True, timeout=3)
                try:
                    process.wait(timeout=12)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
                    raise
    print(f'PASS leased service offset={offset}: outside clock, before/after expiry, authorized stop and cleanup', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, default=Path('build'))
    args = parser.parse_args()
    if os.geteuid() != 0 or sys.flags.optimize or os.environ.get('PYTHONOPTIMIZE'):
        parser.error('run as root without Python optimization')
    count = len(os.listdir('/proc/self/fd'))
    for offset in (3600, -60):
        experiment(args.build_dir.resolve(), offset)
        assert len(os.listdir('/proc/self/fd')) == count


if __name__ == '__main__':
    main()
