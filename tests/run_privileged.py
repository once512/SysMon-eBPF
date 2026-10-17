#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the temporary privileged experiments sequentially with one sudo session."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

TESTS = (
    ('audit-file', 'integration.py'),
    ('self-protection', 'self_protection.py'),
    ('fanotify-open', 'fanotify.py'),
    ('fanotify-deferred', 'fanotify_deferred.py'),
    ('fanotify-events', 'fanotify_events.py'),
    ('policy-layers', 'policy_composition.py'),
    ('baseline-lifecycle', 'baseline_lifecycle.py'),
    ('credential-transitions', 'credential_transitions.py'),
    ('baseline-mismatch', 'baseline_mismatch.py'),
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', default='build')
    parser.add_argument('--soak-duration', type=int, default=0,
                        help='add both policy/timeout workloads, 0 disables (default)')
    parser.add_argument('--only', choices=[name for name, _ in TESTS], nargs='+')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run with sudo; tests temporarily load BPF and fanotify policies')
    if sys.flags.optimize or os.environ.get('PYTHONOPTIMIZE'):
        parser.error('run without Python optimization; test assertions must remain enabled')
    if not 0 <= args.soak_duration <= 1800:
        parser.error('soak-duration must be 0..1800 seconds')
    root = Path(__file__).resolve().parent
    build = Path(args.build_dir).resolve()
    commands = [(name, [sys.executable, str(root / script), '--build-dir', str(build)])
                for name, script in TESTS if args.only is None or name in args.only]
    if args.soak_duration:
        commands += [(f'soak-{mode}', [sys.executable, str(root / 'fanotify_soak.py'),
                      '--build-dir', str(build), '--duration', str(args.soak_duration), '--mode', mode])
                     for mode in ('policy', 'timeout')]
    results = []
    for name, command in commands:
        print(f'RUN {name}', flush=True)
        started = time.monotonic()
        result = subprocess.run(command)
        results.append({'test': name, 'passed': result.returncode == 0,
                        'seconds': round(time.monotonic() - started, 3)})
        if result.returncode:
            print(json.dumps({'passed': False, 'results': results}), flush=True)
            return 1
    print(json.dumps({'passed': True, 'results': results}), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
