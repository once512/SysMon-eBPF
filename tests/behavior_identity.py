#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Concurrent threads and PID namespaces through the real offline evidence boundary."""
import argparse
import io
import json
import os
from pathlib import Path
import sys
import time
from identity_threads import experiment

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from evidence import Grouper, consume


def evaluate(report, pidfd):
    source = (Path('/etc/machine-id').read_text().strip(),
              Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
              f'identity-{report["event"]}-{int(report["nested"])}-{int(pidfd)}-{report["process_inode"]}')
    result = list(consume(io.BytesIO(report['audit_jsonl'].encode()),
                          Grouper(*source, rule_window_ms=10_000)))
    groups, summary = result[:-1], result[-1]
    assert summary['invalid'] == 0 and summary['capacity_evictions'] == 0
    assert summary['grouped'] == (294 if pidfd else 147)
    assert summary['unattributed'] == (0 if pidfd else 147)
    assert len(groups) == 1
    group = groups[0]
    assert group['process_inode'] == report['process_inode']
    assert group['permission_allow'] == (147 if pidfd else 0)
    assert group['mutation_denied'] == 147
    assert group['classification'] == 'undetermined' and not group['observations_complete_for_process']
    behavior = group['behavior']
    # Independent full-history oracle: a process-level match says nothing about
    # which concurrent thread made the earlier permitted access.
    oracle = sum(any(0 < d['timestamp_ns'] - p['responded_ns'] <= 10_000_000_000
                     for p in report['permissions']) for d in report['denials']) if pidfd else 0
    assert 0 <= behavior['matches'] <= oracle
    if pidfd:
        assert behavior['matches'] > 0
    else:
        assert behavior['matches'] == 0
    for sample in behavior['evidence_samples']:
        assert 'tid' not in sample['permission']
        assert sample['permission']['requester_pid'] == report['host_pid']
        assert sample['denial']['tid'] > 0
    return dict(grouped=summary['grouped'], unattributed=summary['unattributed'],
                rule_matches=behavior['matches'], full_history_process_matches=oracle,
                history_evictions=behavior['history_evictions'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', default='build')
    parser.add_argument('--duration', type=int, default=0, help='repeat all eight variants for 0..1200 seconds')
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0 or sys.flags.optimize or os.environ.get('PYTHONOPTIMIZE'):
        parser.error('run as root without Python optimization')
    if not 0 <= args.duration <= 1200:
        parser.error('duration must be 0..1200')
    assert os.readlink('/proc/self/ns/pid') == os.readlink('/proc/1/ns/pid')
    assert Path('/proc/1/status').read_text().split('NSpid:')[1].splitlines()[0].split() == ['1']
    start, cycle, variants = time.monotonic(), 0, 0
    base_fds = len(os.listdir('/proc/self/fd'))
    while True:
        cycle += 1
        reports = []
        for pidfd in (False, True):
            for nested in (False, True):
                for event in ('open', 'access'):
                    raw = experiment(Path(args.build_dir).resolve(), event, nested, pidfd)
                    summary = evaluate(raw, pidfd)
                    row = dict(cycle=cycle, event=event, nested=nested, requester_pidfd=pidfd, **summary)
                    reports.append(dict(summary=row, raw=raw))
                    variants += 1
                    assert len(os.listdir('/proc/self/fd')) == base_fds, 'controller FD leak'
                    print(json.dumps(dict(experiment='behavior-identity', **row, passed=True)), flush=True)
        if args.report:
            args.report.write_text(json.dumps(dict(cycles=cycle, last_cycle=reports), indent=2) + '\n')
        if time.monotonic() - start >= args.duration:
            break
    print(json.dumps(dict(passed=True, cycles=cycle, variants=variants,
                          seconds=round(time.monotonic() - start, 3),
                          controller_base_fds=base_fds, controller_final_fds=len(os.listdir('/proc/self/fd')))), flush=True)


if __name__ == '__main__':
    main()
