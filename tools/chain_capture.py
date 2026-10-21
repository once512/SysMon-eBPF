#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Process-level object spread on a verified, bounded capture; observation only."""
import argparse
from bisect import bisect_left
from collections import Counter, defaultdict, deque
import hashlib
import io
from itertools import islice
import json
from pathlib import Path
import sys

from evidence import SubscriptionIndex, observation
from evaluate_capture import MAX_BYTES, MAX_RECORDS, decode, evaluate_capture, labels_from
from replay_capture import MAX_MANIFEST


def peak(events, span_ns):
    """Maximum distinct objects in an inclusive timestamp window, independent of delivery."""
    queue, counts = deque(), Counter()
    best = dict(distinct_objects=0, begin_ns=None, end_ns=None)
    for timestamp, target in sorted(events):
        queue.append((timestamp, target))
        counts[target] += 1
        while timestamp - queue[0][0] > span_ns:
            _, old = queue.popleft()
            counts[old] -= 1
            if not counts[old]:
                del counts[old]
        if len(counts) > best['distinct_objects']:
            best = dict(distinct_objects=len(counts), begin_ns=queue[0][0], end_ns=timestamp)
    return best


def summarize(records, labels=None, pair_window_ms=1000, chain_window_ms=10000, min_objects=3):
    for name, value, low, high in (
        ('pair-window-ms', pair_window_ms, 1, 3_600_000),
        ('chain-window-ms', chain_window_ms, 1, 3_600_000),
        ('min-objects', min_objects, 2, 4096),
    ):
        if type(value) is not int or not low <= value <= high:
            raise ValueError(f'{name} must be an integer in {low}..{high}')
    records = list(islice(records, MAX_RECORDS + 1))
    if len(records) > MAX_RECORDS:
        raise ValueError('chain input exceeds 50000 records')
    subscriptions = SubscriptionIndex(records)
    objects = {}
    unattributed = ignored = count = 0
    listener = None
    for line, record in enumerate(records, 1):
        count += 1
        if count > MAX_RECORDS:
            raise ValueError('chain input exceeds 50000 records')
        if not isinstance(record, dict):
            raise ValueError('JSON object required')
        item = observation(record, line, subscriptions)
        if item is None:
            ignored += 1
            continue
        key, fact = item
        if fact['event'] == 'fanotify_decision':
            current = tuple(fact[name] for name in ('pid_namespace_inode', 'listener_pid', 'instance_ns'))
            if listener is not None and current != listener:
                raise ValueError('mixed listener instances')
            listener = current
        if key is None:
            unattributed += 1
            continue
        if key not in objects:
            if len(objects) == 4096:
                raise ValueError('chain input exceeds 4096 process/object keys')
            objects[key] = dict(allows=[], denials=[], operations=Counter(), revisions=Counter())
        group = objects[key]
        if fact['event'] == 'file_denied':
            group['denials'].append(fact['timestamp_ns'])
            group['operations'][fact['operation']] += 1
        elif fact['decision'] == 'allow' and fact['permission_event'] in ('open', 'access'):
            group['allows'].append(fact['responded_ns'])
            group['revisions'][fact['revision']] += 1
    processes = defaultdict(lambda: dict(objects=[], denials=[], paired=[]))
    for key, group in sorted(objects.items()):
        process, *target, generation = key
        target = tuple(target)
        allows = sorted(group['allows'])
        paired = []
        for timestamp in sorted(group['denials']):
            index = bisect_left(allows, timestamp) - 1
            if index >= 0 and timestamp - allows[index] <= pair_window_ms * 1_000_000:
                paired.append(timestamp)
        row = dict(target=dict(major=target[0], minor=target[1], inode=target[2]),
                   access_allows=len(allows), mutation_denials=len(group['denials']),
                   paired_denials=len(paired), denial_operations=dict(sorted(group['operations'].items())),
                   access_revisions={str(k): v for k, v in sorted(group['revisions'].items())})
        state = processes[(process, generation)]
        state['objects'].append(row)
        state['denials'].extend((t, target) for t in group['denials'])
        state['paired'].extend((t, target) for t in paired)
    output = []
    for (process, generation), state in sorted(processes.items()):
        denied_peak = peak(state['denials'], chain_window_ms * 1_000_000)
        paired_peak = peak(state['paired'], chain_window_ms * 1_000_000)
        output.append(dict(process_inode=process, subscription_generation=generation, role=(labels or {}).get(process, 'unlabelled'),
                           objects=state['objects'], mutation_denials=len(state['denials']),
                           paired_denials=len(state['paired']),
                           distinct_denied_objects=sum(r['mutation_denials'] > 0 for r in state['objects']),
                           distinct_accessed_objects=sum(r['access_allows'] > 0 for r in state['objects']),
                           denial_spread_peak=denied_peak, paired_spread_peak=paired_peak,
                           multi_object_denials_observed=denied_peak['distinct_objects'] >= min_objects,
                           multi_object_access_then_denial_observed=paired_peak['distinct_objects'] >= min_objects,
                           classification='undetermined', response='none'))
    return dict(processes=output, subscription_handovers=len(subscriptions.boundaries), records=count, ignored=ignored, unattributed=unattributed,
                pair_window_ms=pair_window_ms, chain_window_ms=chain_window_ms, min_objects=min_objects,
                analysis_scope='complete provided input, not complete process history',
                observations_complete_for_process=False, read_completion_verified=False,
                code_identity_verified=False, deduplication='none',
                classification='undetermined', response='none')


def chain_capture(directory, pair_window_ms=1000, chain_window_ms=10000, min_objects=3):
    # Reuse bounded capture verification and exact baseline reproduction. This
    # does not merge captures or trust grouped samples as complete raw history.
    verified = evaluate_capture(directory, windows=(pair_window_ms,), histories=(128,), modes=('original',))
    with (directory / 'audit.jsonl').open('rb') as stream:
        raw = stream.read(MAX_BYTES + 1)
    with (directory / 'manifest.json').open('rb') as stream:
        manifest_raw = stream.read(MAX_MANIFEST + 1)
    if (len(raw) > MAX_BYTES or len(manifest_raw) > MAX_MANIFEST or
        hashlib.sha256(raw).hexdigest() != verified['audit_sha256'] or
        hashlib.sha256(manifest_raw).hexdigest() != verified['manifest_sha256']):
        raise ValueError('capture changed during chain analysis')
    manifest = decode(manifest_raw)
    result = summarize((decode(line) for line in io.BytesIO(raw)), labels_from(manifest),
                       pair_window_ms, chain_window_ms, min_objects)
    return dict(event='capture_object_chains', source=verified['source'],
                audit_sha256=verified['audit_sha256'], manifest_sha256=verified['manifest_sha256'],
                baseline_reproduced=True, authenticity_verified=False,
                labels='operator-declared-workload-roles', object_lifetime_verified=False,
                interpretation='object spread is not malicious intent or confirmed attack', **result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture_directory', type=Path)
    parser.add_argument('--pair-window-ms', type=int, default=1000)
    parser.add_argument('--chain-window-ms', type=int, default=10000)
    parser.add_argument('--min-objects', type=int, default=3)
    args = parser.parse_args()
    try:
        result = chain_capture(args.capture_directory, args.pair_window_ms, args.chain_window_ms, args.min_objects)
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as error:
        print('chain analysis failed: ' + str(error), file=sys.stderr)
        return 1
    print(json.dumps(result, separators=(',', ':'), ensure_ascii=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
