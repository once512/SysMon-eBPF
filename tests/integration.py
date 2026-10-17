#!/usr/bin/env python3
"""Privileged integration test: temporary audit attach, no blocking policies."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', default='build')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run with sudo to load the audit programs')
    build = Path(args.build_dir).resolve()
    with tempfile.TemporaryDirectory(prefix='secmon-test-') as directory:
        output = Path(directory) / 'events.jsonl'
        errors = Path(directory) / 'stderr.log'
        with output.open('w') as stdout, errors.open('w') as stderr:
            monitor = subprocess.Popen([str(build / 'secmon')], stdout=stdout, stderr=stderr)
            try:
                deadline = time.monotonic() + 10
                while 'Audit active;' not in errors.read_text():
                    if monitor.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError('monitor did not become ready\n' + errors.read_text())
                    time.sleep(0.05)
                cases = {}
                for mode in ('exec', 'threads', 'thread-exec', 'drop-exec'):
                    child = subprocess.Popen([str(build / 'secmon-scenarios'), mode])
                    cases[mode] = child.pid
                    result = child.wait(timeout=10)
                    if result != 0:
                        raise RuntimeError(f'{mode}: helper exit {result}')
                time.sleep(0.5)
            finally:
                if monitor.poll() is None:
                    monitor.send_signal(signal.SIGTERM)
                try:
                    monitor.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    monitor.kill()
                    monitor.wait()
                    raise RuntimeError('monitor failed to stop')
        diagnostics = errors.read_text()
        if monitor.returncode != 0:
            raise RuntimeError(diagnostics)
        events = [json.loads(line) for line in output.read_text().splitlines()]
        for mode, pid in cases.items():
            matching = [e for e in events if e['pid'] == pid]
            checks = [e for e in matching if e['event'] == 'exec_check'
                      and e['filename'] == '/usr/bin/true']
            success = [e for e in matching if e['event'] == 'exec_success'
                       and e['filename'] == '/usr/bin/true']
            assert checks and success, f'{mode}: missing check or completion'
            assert all(e['flags'] == 0 for e in matching), f'{mode}: credential mismatch'
            if mode == 'thread-exec':
                assert any(e['old_tid'] != e['tid'] for e in success), 'TID change not observed'
                assert any(c['tid'] == s['old_tid'] for c in checks for s in success), \
                    'pre-exec thread not linked to completion'
            if mode == 'drop-exec':
                assert all(e['uid'] == 65534 and e['euid'] == 65534 for e in checks + success)
            print(f'PASS {mode} pid={pid}')
        assert 'ringbuf_dropped=0' in diagnostics, diagnostics
        assert 'baseline_update_failed=0' in diagnostics, diagnostics
        print('PASS audit pipeline and clean shutdown (not an attack-detection test)')


if __name__ == '__main__':
    main()
