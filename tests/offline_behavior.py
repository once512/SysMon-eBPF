#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Rule semantics: ordering, response boundaries, delivery reorder, eviction, and controls."""
import itertools
import json
import random
from pathlib import Path
import subprocess
import sys
from offline_evidence import permission, denial, run, BOOT


def check(rows, expected, **options):
    groups, summary = run(rows, rule_window_ms=1, **options)
    assert summary['rule_matches'] == expected, (groups, summary, expected)
    assert sum(row['behavior']['matches'] for row in groups) == expected
    for group in groups:
        behavior = group['behavior']
        assert behavior['response'] == 'none' and behavior['complete'] is False
        for sample in behavior['evidence_samples']:
            assert 0 < sample['delta_ns'] <= 1_000_000
            assert sample['permission']['responded_ns'] < sample['denial']['timestamp_ns']
    return groups, summary


def main():
    # Every log delivery order must find these two distinct denied observations.
    for rows in itertools.permutations([permission(), denial(), denial(timestamp_ns=800)]):
        check(rows, 2)
    for operation in (11, 12, 13):
        _, summary = check([permission(), denial(operation=operation)], 0)
        assert summary['ignored'] == 1 and summary['invalid'] == 0
    check([permission(), permission(), denial()], 1)
    check([denial(), permission(), permission()], 1)
    # Receive time is insufficient: the permission response must strictly precede denial.
    for timestamp in (499, 500, 599, 600):
        check([permission(), denial(timestamp_ns=timestamp)], 0)
    check([permission(), denial(timestamp_ns=1_000_600)], 1)
    check([permission(), denial(timestamp_ns=1_000_601)], 0)
    check([permission(permission_event='exec'), denial()], 0)
    check([permission(decision='deny'), denial()], 0)
    check([permission(), denial(cookie=78), denial(inode=100)], 0)
    check([permission(), denial(cookie=0)], 0)
    check([permission(cookie=0, requester_reference='unavailable'), denial()], 0)
    check([permission(), denial(cookie=78), denial()], 0, max_groups=1)
    # Keep evidence pairs even after ordinary samples have rolled off.
    groups, _ = check([permission(), denial(), permission(decision='deny')], 1, samples=1)
    assert groups[0]['evidence_samples'][0]['decision'] == 'deny'
    assert groups[0]['behavior']['evidence_samples'][0]['permission']['line'] == 1
    # Both histories are bounded; an evicted observation can cause a missing match.
    _, summary = check([permission(), permission(received_ns=1000, responded_ns=1100), denial()],
                       0, rule_history=1)
    assert summary['rule_history_evictions'] == 1
    _, summary = check([denial(), denial(timestamp_ns=500), permission()], 0, rule_history=1)
    assert summary['rule_history_evictions'] == 1
    groups, summary = check([permission(), *[denial() for _ in range(100)]], 100, samples=2)
    assert len(groups[0]['behavior']['evidence_samples']) == 2
    assert summary['rule_history_evictions'] == 0
    # Count duplicated denials as separate observations, just like base grouping.
    check([permission(), denial(), denial()], 2)
    groups, summary = run([permission(), denial()])
    assert 'behavior' not in groups[0] and summary['rule_matches'] == 0
    for options in ({'rule_window_ms': -1}, {'rule_window_ms': 3_600_001},
                    {'rule_history': 0}, {'rule_history': 129}):
        try:
            run([], **options)
        except ValueError:
            pass
        else:
            raise AssertionError('invalid rule bounds accepted')
    command = [sys.executable, '-B', str(Path(__file__).resolve().parents[1] / 'tools/evidence.py'),
               '--machine-id', 'test', '--boot-id', BOOT, '--capture-id', 'rule', '--rule-window-ms', '1']
    result = subprocess.run(command, input='\n'.join(map(json.dumps, [permission(), denial()])),
                            text=True, capture_output=True, check=True)
    assert json.loads(result.stdout.splitlines()[-1])['rule_matches'] == 1
    # An independent full-history oracle checks arbitrary interleaving and keys.
    rng = random.Random(20261019)
    for _ in range(120):
        rows = []
        for _ in range(30):
            cookie, inode = rng.randrange(1, 4), rng.randrange(90, 93)
            if rng.randrange(2):
                timestamp = rng.randrange(1, 4_000_000)
                rows.append(permission(cookie=cookie, inode=inode, received_ns=timestamp,
                                       responded_ns=timestamp + 100, decision=rng.choice(('allow', 'deny')),
                                       permission_event=rng.choice(('open', 'access', 'exec'))))
            else:
                rows.append(denial(cookie=cookie, inode=inode, timestamp_ns=rng.randrange(1, 4_000_000)))
        expected = sum(any(a['event'] == 'fanotify_decision' and a['decision'] == 'allow' and
                           a['permission_event'] in ('open', 'access') and
                           a['requester_process_inode'] == d['process_inode'] and a['inode'] == d['ino'] and
                           0 < d['timestamp_ns'] - a['responded_ns'] <= 1_000_000
                           for a in rows) for d in rows if d['event'] == 'file_denied')
        rng.shuffle(rows)
        check(rows, expected)
    print('PASS temporal rule boundaries, reordered delivery, retained pairs, bounded history and negative controls')


if __name__ == '__main__':
    main()
