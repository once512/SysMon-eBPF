#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Epoch isolation, reordered delivery and incomplete/corrupt boundary rejection."""
import copy
import itertools
import json
from pathlib import Path
import random
import subprocess
import sys
from offline_evidence import BOOT, permission, denial, run

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from evidence import SubscriptionIndex, Grouper, MAX_HANDOVERS
from evaluate_capture import compare, DELIVERIES
from chain_capture import summarize


def handover(generation=1, timestamp=1000, request_id=2, **changes):
    row = dict(event='fanotify_target_handover', listener_pid=200, instance_ns=300,
               pid_namespace_inode=400, from_generation=generation, to_generation=generation + 1,
               from_revision=generation, to_revision=generation + 1, old_targets=1,
               new_targets=1, retained_targets=1, next_request_id=request_id,
               timestamp_ns=timestamp, kernel_unread='released_under_prior_allow',
               individual_audit_complete=False)
    row.update(changes)
    return row


def rows_of(records):
    return [(i, r, (json.dumps(r) + '\n').encode()) for i, r in enumerate(records, 1)]


def main():
    old = permission(subscription_generation=1)
    switch = handover()
    new = permission(subscription_generation=2, request_id=2, revision=2,
                     received_ns=1100, responded_ns=1200)
    before = denial(timestamp_ns=700)
    after = denial(timestamp_ns=1300)
    # Delivery order must not create a cross-epoch pair or hide a real same-epoch pair.
    for records in itertools.permutations([old, switch, after]):
        groups, summary = run(records, rule_window_ms=1)
        assert summary['rule_matches'] == 0 and summary['subscription_handovers'] == 1
        assert {r['subscription_generation'] for r in groups} == {1, 2}
    for records in itertools.permutations([old, before, switch, new, after]):
        groups, summary = run(records, rule_window_ms=1)
        assert summary['rule_matches'] == 2 and summary['invalid'] == 0
        assert len(groups) == 2
        for group in groups:
            assert group['behavior']['matches'] == 1
            assert all(s['permission']['subscription_generation'] == s['denial']['subscription_generation']
                       for s in group['behavior']['evidence_samples'])
    # Even retained targets start a conservative new epoch, not certified lifetime continuity.
    groups, summary = run([old, switch, denial(timestamp_ns=1000)], rule_window_ms=1)
    assert summary['rule_matches'] == 0
    assert any(r['subscription_generation'] == 0 for r in groups)
    assert all(r['object_lifetime_verified'] is False for r in groups)
    # Remove/readd can refer to exactly the same device/inode without reusing old access history.
    second = handover(2, timestamp=2000, request_id=3, retained_targets=0)
    groups, summary = run([old, switch, new, second, denial(timestamp_ns=2300)], rule_window_ms=1)
    assert summary['rule_matches'] == 0
    assert {r['subscription_generation'] for r in groups} == {1, 2, 3}
    # Missing boundaries cannot be hidden even when requester identity is unavailable.
    for records in ([old, new], [permission(cookie=0, requester_reference='unavailable',
                                          subscription_generation=2)]):
        _, summary = run(records, rule_window_ms=1)
        assert summary['invalid'] >= 1
    malformed = [dict(switch, to_generation=3), dict(switch, from_generation=2, to_generation=3),
                 dict(switch, next_request_id=0), dict(switch, retained_targets=2),
                 dict(switch, individual_audit_complete=True), dict(switch, from_generation=True),
                 dict(switch, to_revision=1), dict(switch, pid_namespace_inode=0)]
    for marker in malformed:
        try:
            run([old, marker, after], rule_window_ms=1)
        except ValueError:
            pass
        else:
            raise AssertionError('invalid marker accepted')
    for markers in ([switch, switch], [switch, dict(second, timestamp_ns=1000)],
                    [switch, dict(second, next_request_id=1)],
                    [switch, dict(second, listener_pid=201)],
                    [switch, dict(second, from_revision=1)]):
        try:
            SubscriptionIndex(markers)
        except ValueError:
            pass
        else:
            raise AssertionError('inconsistent boundary index accepted')
    _, summary = run([switch, dict(new, subscription_generation=1)], rule_window_ms=1)
    assert summary['invalid'] == 1
    _, summary = run([switch, dict(new, received_ns=900)], rule_window_ms=1)
    assert summary['invalid'] == 1
    _, summary = run([switch, dict(old, responded_ns=1000)], rule_window_ms=1)
    assert summary['invalid'] == 1
    # Several no-request handovers share next_request_id; the last epoch owns the next request.
    _, summary = run([switch, dict(second, next_request_id=2),
                      dict(new, request_id=2, revision=3, subscription_generation=3,
                           received_ns=2100, responded_ns=2200), denial(timestamp_ns=2300)],
                     rule_window_ms=1)
    assert summary['invalid'] == 0 and summary['rule_matches'] == 1
    source = dict(machine_id='test', boot_id=BOOT, capture_id='generation')
    reports = compare(rows_of([old, before, switch, new, after]), source, {}, 1, 128, 1024,
                      DELIVERIES, 1)
    assert all(r['bounded_matches'] == (0 if r['delivery'].startswith('drop-') else 2) for r in reports)
    # Independent interval reference across arbitrary generations and input reorder.
    rng = random.Random(20261021)
    for _ in range(80):
        records = [handover(g, timestamp=g * 10000, request_id=g * 10 + 1)
                   for g in range(1, 6)]
        expected = 0
        for epoch in range(1, 7):
            start = (epoch - 1) * 10000
            if rng.randrange(2):
                records.append(permission(subscription_generation=epoch, revision=epoch,
                                          request_id=(epoch-1)*10+1, received_ns=start+100,
                                          responded_ns=start+200))
                expected += 1
            records.append(denial(timestamp_ns=start+300))
        rng.shuffle(records)
        _, summary = run(records, rule_window_ms=1)
        assert summary['invalid'] == 0 and summary['rule_matches'] == expected
    # Spread aggregation is partitioned too; different epochs cannot manufacture a multi-object chain.
    chain = summarize([old, before, switch, dict(new, inode=100), denial(inode=100, timestamp_ns=1300)],
                      min_objects=2)
    assert len(chain['processes']) == 2
    assert all(not p['multi_object_access_then_denial_observed'] for p in chain['processes'])
    assert {p['subscription_generation'] for p in chain['processes']} == {1, 2}
    # Index budget and CLI must reject before emitting apparently successful evidence.
    try:
        SubscriptionIndex(handover() for _ in range(MAX_HANDOVERS + 1))
    except ValueError:
        pass
    else:
        raise AssertionError('unbounded handovers accepted')
    command = [sys.executable, '-B', str(Path(__file__).resolve().parents[1] / 'tools/evidence.py'),
               '--machine-id', 'test', '--boot-id', BOOT, '--capture-id', 'epochs', '--rule-window-ms', '1']
    result = subprocess.run(command, input='\n'.join(map(json.dumps, [old, switch, switch, after])),
                            text=True, capture_output=True)
    assert result.returncode == 1 and not result.stdout
    result = subprocess.run(command, input='\n'.join(map(json.dumps, [after, switch, old])),
                            text=True, capture_output=True, check=True)
    assert json.loads(result.stdout.splitlines()[-1])['rule_matches'] == 0
    print('PASS subscription epoch isolation, reordered capture, incomplete/corrupt boundaries, chain partition and budgets')


if __name__ == '__main__':
    main()
