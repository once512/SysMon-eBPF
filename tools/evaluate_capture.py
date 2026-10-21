#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare a bounded observation rule with a full-history reference on verified captures."""
import argparse
from bisect import bisect_left
from collections import Counter, defaultdict
import hashlib
import io
import json
from pathlib import Path
import random
import re
import sys

from evidence import Grouper, SubscriptionIndex, observation, finite_float, reject_constant, unique_object
from replay_capture import MAX_MANIFEST, verify_capture

MAX_BYTES = 32 * 1024 * 1024
MAX_RECORDS = 50_000
DELIVERIES = ('original', 'reverse', 'chronological', 'permissions-last', 'shuffle',
              'drop-permissions', 'drop-denials')


def decode(raw):
    return json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object,
                      parse_constant=reject_constant, parse_float=finite_float)


def labels_from(manifest):
    labels = {}
    scenarios, tools = manifest.get('scenarios', []), manifest.get('tools', [])
    if not isinstance(scenarios, list) or not isinstance(tools, list):
        raise ValueError('workload label collections must be lists')
    for row in [*scenarios, *tools]:
        if not isinstance(row, dict):
            raise ValueError('workload label entries must be objects')
        cookie, role = row.get('process_inode'), row.get('role')
        if type(cookie) is not int or not 1 <= cookie < 2 ** 64:
            raise ValueError('invalid process inode in declared workload labels')
        if not isinstance(role, str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,64}', role):
            raise ValueError('invalid declared workload label')
        if cookie in labels and labels[cookie] != role:
            raise ValueError('conflicting roles for one process lifetime')
        labels[cookie] = role
        if len(labels) > 128:
            raise ValueError('at most 128 declared process labels are supported')
    return labels


def oracle(rows, window_ms, labels):
    """Full-history timestamp reference, independent of delivery order and bounded queues."""
    subscriptions = SubscriptionIndex(row[1] for row in rows)
    allows = defaultdict(list)
    denials = []
    counts = defaultdict(Counter)
    for line, record, _ in rows:
        item = observation(record, line, subscriptions)
        if item is None:
            continue
        key, fact = item
        if fact['event'] == 'file_denied':
            role = labels.get(key[0], 'unlabelled') if key else 'unattributed'
            counts[role]['denials'] += 1
            if key:
                denials.append((key, fact, role))
        elif key and fact['decision'] == 'allow' and fact['permission_event'] in ('open', 'access'):
            allows[key].append(fact['responded_ns'])
    for values in allows.values():
        values.sort()
    if window_ms:
        for key, fact, role in denials:
            values = allows[key]
            index = bisect_left(values, fact['timestamp_ns']) - 1
            if index >= 0 and fact['timestamp_ns'] - values[index] <= window_ms * 1_000_000:
                counts[role]['eligible'] += 1
    return counts


def delivery(rows, mode, seed):
    if mode == 'original':
        return rows
    if mode == 'reverse':
        return rows[::-1]
    if mode == 'chronological':
        subscriptions = SubscriptionIndex(row[1] for row in rows)
        def timestamp(row):
            if row[1].get('event') == 'fanotify_target_handover':
                return (row[1]['timestamp_ns'], row[0])
            item = observation(row[1], row[0], subscriptions)
            if item is None:
                return (0, row[0])
            fact = item[1]
            return (fact.get('responded_ns', fact['timestamp_ns']), row[0])
        return sorted(rows, key=timestamp)
    if mode == 'permissions-last':
        return sorted(rows, key=lambda r: r[1].get('event') == 'fanotify_decision')
    if mode == 'shuffle':
        result = rows.copy()
        random.Random(seed).shuffle(result)
        return result
    removed = 'fanotify_decision' if mode == 'drop-permissions' else 'file_denied'
    return [r for r in rows if r[1].get('event') != removed]


def compare(rows, source, labels, window_ms, history, max_groups, modes, seed):
    original = oracle(rows, window_ms, labels)
    results = []
    for mode in modes:
        delivered = delivery(rows, mode, seed)
        reference = oracle(delivered, window_ms, labels)
        grouper = Grouper(source['machine_id'], source['boot_id'], source['capture_id'],
                          max_groups=max_groups, samples=1, rule_window_ms=window_ms, rule_history=history)
        grouper.subscriptions = SubscriptionIndex(row[1] for row in delivered)
        observed = Counter()

        def collect(row):
            observed[labels.get(row['process_inode'], 'unlabelled')] += row.get('behavior', {}).get('matches', 0)

        for _, _, raw in delivered:
            for row in grouper.accept(raw):
                collect(row)
        summary = None
        for row in grouper.finish():
            if row['event'] == 'evidence_summary':
                summary = row
            else:
                collect(row)
        if summary['invalid']:
            raise ValueError('delivery produced invalid input')
        roles = []
        for role in sorted(set(labels.values()) | set(original) | set(reference) | set(observed)):
            before, after = original[role], reference[role]
            eligible, matches = after['eligible'], observed[role]
            if matches > eligible or eligible > before['eligible'] or after['denials'] > before['denials']:
                raise ValueError('bounded rule contradicts full-history reference')
            roles.append(dict(role=role, source_denials=before['denials'], delivered_denials=after['denials'],
                              removed_denials=before['denials'] - after['denials'],
                              source_eligible=before['eligible'], delivered_eligible=eligible,
                              eligibility_lost_with_input=before['eligible'] - eligible,
                              bounded_matches=matches, missed_with_bounded_state=eligible - matches))
        results.append(dict(delivery=mode, synthetic=mode != 'original', seed=seed if mode == 'shuffle' else None,
                            window_ms=window_ms, history_per_kind=history, max_groups=max_groups,
                            input_records=len(delivered), capacity_evictions=summary['capacity_evictions'],
                            grouped=summary['grouped'], unattributed=summary['unattributed'],
                            history_evictions=summary['rule_history_evictions'],
                            roles=roles, bounded_matches=summary['rule_matches'],
                            delivered_eligible=sum(r['delivered_eligible'] for r in roles),
                            missed_with_bounded_state=sum(r['missed_with_bounded_state'] for r in roles),
                            eligibility_lost_with_input=sum(r['eligibility_lost_with_input'] for r in roles)))
    return results


def evaluate_capture(directory, windows=(1000,), histories=(32,), max_groups=1024, modes=DELIVERIES, seed=20261020):
    if not windows or len(windows) > 8 or not histories or len(histories) > 8 or not modes or len(modes) > 7:
        raise ValueError('at most eight windows, eight histories and seven deliveries are supported')
    if any(type(w) is not int or not 0 <= w <= 3_600_000 for w in windows):
        raise ValueError('window must be an integer in 0..3600000')
    if any(type(h) is not int or not 1 <= h <= 128 for h in histories):
        raise ValueError('history must be an integer in 1..128')
    if type(max_groups) is not int or not 1 <= max_groups <= 4096 or type(seed) is not int:
        raise ValueError('invalid group capacity or shuffle seed')
    if any(m not in DELIVERIES for m in modes):
        raise ValueError('unknown delivery mode')
    if (directory / 'audit.jsonl').stat().st_size > MAX_BYTES:
        raise ValueError('evaluation capture exceeds 32 MiB')
    if (directory / 'evidence.jsonl').stat().st_size > 2 * MAX_BYTES:
        raise ValueError('evaluation evidence exceeds 64 MiB')
    with (directory / 'audit.jsonl').open('rb') as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError('evaluation capture exceeds 32 MiB')
    if raw.count(b'\n') + int(bool(raw and not raw.endswith(b'\n'))) > MAX_RECORDS:
        raise ValueError('evaluation capture exceeds 50000 records')
    verified = verify_capture(directory)
    with (directory / 'manifest.json').open('rb') as stream:
        manifest_raw = stream.read(MAX_MANIFEST + 1)
    if hashlib.sha256(manifest_raw).hexdigest() != verified['manifest_sha256']:
        raise ValueError('manifest changed during evaluation')
    manifest = decode(manifest_raw)
    if hashlib.sha256(raw).hexdigest() != verified['audit_sha256']:
        raise ValueError('audit changed during evaluation')
    lines = list(io.BytesIO(raw))
    rows = [(i, decode(line), line) for i, line in enumerate(lines, 1)]
    labels = labels_from(manifest)
    results = []
    for window in dict.fromkeys(windows):
        for history in dict.fromkeys(histories):
            results.extend(compare(rows, verified['source'], labels, window, history, max_groups,
                                   tuple(dict.fromkeys(modes)), seed))
    return dict(event='capture_evaluation', source=verified['source'], audit_sha256=verified['audit_sha256'],
                manifest_sha256=verified['manifest_sha256'], baseline_reproduced=True,
                baseline_summary=verified['summary'], authenticity_verified=False,
                labels='operator-declared-workload-roles', classification='undetermined', response='none',
                interpretation='timestamp-pattern coverage; not attack detection accuracy', results=results)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture_directory', type=Path)
    parser.add_argument('--window-ms', type=int, nargs='+', default=[1000])
    parser.add_argument('--history', type=int, nargs='+', default=[32])
    parser.add_argument('--max-groups', type=int, default=1024)
    parser.add_argument('--delivery', choices=DELIVERIES, nargs='+', default=list(DELIVERIES))
    parser.add_argument('--seed', type=int, default=20261020)
    args = parser.parse_args()
    try:
        result = evaluate_capture(args.capture_directory, args.window_ms, args.history,
                                  args.max_groups, args.delivery, args.seed)
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as error:
        print('capture evaluation failed: ' + str(error), file=sys.stderr)
        return 1
    print(json.dumps(result, separators=(',', ':'), ensure_ascii=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
