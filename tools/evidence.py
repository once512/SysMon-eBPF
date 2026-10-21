#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded offline grouping of audit facts by declared boot, pidfs process, and file object."""
import argparse
from bisect import bisect_left, bisect_right
from collections import OrderedDict, deque
import json
import math
import re
import sys
import tempfile
import uuid
from behavior import AccessThenDenial

MAX_LINE = 4096
OPERATIONS = {1: 'open-write', 2: 'write', 3: 'truncate', 4: 'unlink',
              5: 'rename', 6: 'link', 7: 'setattr', 8: 'mmap-write'}


def integer(record, name, bits=64, minimum=0, signed=False, default=None):
    value = record.get(name, default)
    maximum = (1 << (bits - int(signed))) - 1
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError('invalid numeric field: ' + name)
    return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError('non-finite JSON number')


def finite_float(value):
    result = float(value)
    if not math.isfinite(result):
        raise ValueError('non-finite JSON number')
    return result


MAX_INPUT_BYTES = 128 * 1024 * 1024
MAX_INPUT_RECORDS = 1_000_000
MAX_HANDOVERS = 4096


class SubscriptionIndex:
    """Conservative whole-group epochs, validated before any evidence is emitted.

    The index does not certify file lifetimes. Even retained targets cross an
    epoch boundary. BPF timestamps equal to a boundary are deliberately unpaired.
    """
    def __init__(self, records=()):
        self.boundaries = []
        self.listener = None
        for record in records:
            if not isinstance(record, dict) or record.get('event') != 'fanotify_target_handover':
                continue
            if len(self.boundaries) == MAX_HANDOVERS:
                raise ValueError('at most 4096 subscription handovers are supported')
            identity = (integer(record, 'pid_namespace_inode', minimum=1),
                        integer(record, 'listener_pid', 32, minimum=1, signed=True),
                        integer(record, 'instance_ns', minimum=1))
            if self.listener is not None and identity != self.listener:
                raise ValueError('mixed subscription listener instances')
            self.listener = identity
            previous = integer(record, 'from_generation', minimum=1)
            following = integer(record, 'to_generation', minimum=2)
            old_revision = integer(record, 'from_revision', minimum=1)
            new_revision = integer(record, 'to_revision', minimum=1)
            timestamp = integer(record, 'timestamp_ns', minimum=1)
            request = integer(record, 'next_request_id', minimum=1)
            old_targets = integer(record, 'old_targets', 32, minimum=1)
            new_targets = integer(record, 'new_targets', 32, minimum=1)
            retained = integer(record, 'retained_targets', 32)
            if (following != previous + 1 or following >= 2**64 or new_revision <= old_revision or
                max(old_targets, new_targets) > 64 or retained > min(old_targets, new_targets) or
                record.get('kernel_unread') != 'released_under_prior_allow' or
                record.get('individual_audit_complete') is not False):
                raise ValueError('invalid subscription handover contract')
            self.boundaries.append((previous, following, timestamp, request, old_revision, new_revision))
        self.boundaries.sort()
        for i, boundary in enumerate(self.boundaries):
            if boundary[0] != i + 1:
                raise ValueError('missing or duplicate subscription generation boundary')
            if i:
                older = self.boundaries[i - 1]
                if boundary[2] <= older[2] or boundary[3] < older[3] or boundary[4] < older[5]:
                    raise ValueError('non-monotonic subscription boundary')
        self.times = [row[2] for row in self.boundaries]
        self.requests = [row[3] for row in self.boundaries]

    def generation(self, record):
        if record['event'] == 'fanotify_decision':
            generation = integer(record, 'subscription_generation', minimum=1, default=1)
            if self.listener is not None and tuple(record[name] for name in
                ('pid_namespace_inode', 'listener_pid', 'instance_ns')) != self.listener:
                raise ValueError('permission outside subscription listener instance')
            expected = bisect_right(self.requests, record['request_id']) + 1
            if generation != expected:
                raise ValueError('missing subscription boundary or mismatched request generation')
            lower = self.times[generation - 2] if generation > 1 else 0
            upper = self.times[generation - 1] if generation <= len(self.times) else 2**64
            lower_revision = self.boundaries[generation - 2][5] if generation > 1 else 1
            upper_revision = self.boundaries[generation - 1][4] if generation <= len(self.times) else 2**64 - 1
            if not lower_revision <= record['revision'] <= upper_revision:
                raise ValueError('permission revision contradicts subscription boundary')
            if record['received_ns'] < lower or record['responded_ns'] >= upper:
                raise ValueError('permission crosses or contradicts subscription boundary')
            return generation
        timestamp = record['timestamp_ns']
        position = bisect_left(self.times, timestamp)
        if position < len(self.times) and self.times[position] == timestamp:
            return 0
        return position + 1


def decoded_record(raw):
    return json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object,
                      parse_constant=reject_constant, parse_float=finite_float)


def observation(record, line_number, subscriptions=None):
    """Return (object key, compact fact), None for unsupported events, or an unattributed fact."""
    kind = record.get('event')
    if kind not in ('fanotify_decision', 'file_denied'):
        return None
    if kind == 'fanotify_decision':
        if record.get('decision') not in ('allow', 'deny') or record.get('permission_event') not in ('open', 'access', 'exec'):
            raise ValueError('invalid permission fact')
        integer(record, 'listener_pid', 32, minimum=1, signed=True)
        integer(record, 'requester_pid', 32, minimum=-(1 << 31), signed=True)
        integer(record, 'request_id', minimum=1)
        integer(record, 'instance_ns', minimum=1)
        integer(record, 'pid_namespace_inode', minimum=1)
        integer(record, 'revision', minimum=1)
        if record.get('reason') not in ('policy', 'timeout', 'capacity', 'shutdown', 'analysis', 'analyzer_error'):
            raise ValueError('invalid permission reason')
        received = integer(record, 'received_ns')
        integer(record, 'responded_ns', minimum=received)
        target = (integer(record, 'major', 32), integer(record, 'minor', 32), integer(record, 'inode', minimum=1))
        state = record.get('requester_reference', 'disabled')
        if state not in ('disabled', 'present', 'unavailable', 'error'):
            raise ValueError('invalid reference state')
        process = integer(record, 'requester_process_inode', default=0)
        error = integer(record, 'requester_identity_errno', 12, default=0)
        if state == 'present':
            if (process == 0) == (error == 0):
                raise ValueError('inconsistent reference identity')
        elif process or error:
            raise ValueError('identity without a reference')
        if record.get('requester_pid_kind') != 'tgid':
            raise ValueError('unsupported requester coordinate')
        fact = dict(line=line_number, event=kind, timestamp_field='received_ns', timestamp_ns=received,
                    responded_ns=record['responded_ns'], decision=record['decision'], permission_event=record['permission_event'],
                    listener_pid=record['listener_pid'], instance_ns=record['instance_ns'],
                    pid_namespace_inode=record['pid_namespace_inode'], request_id=record['request_id'])
        fact.update(revision=record['revision'], reason=record['reason'], requester_pid=record['requester_pid'])
        fact['subscription_generation'] = (subscriptions or SubscriptionIndex()).generation(record)
        if not process:
            return None, dict(fact, unattributed_reason='inspection_failed' if error else 'reference_' + state)
    else:
        if record.get('errno') != 13 or type(record.get('errno')) is not int:
            raise ValueError('invalid file denial errno')
        operation = integer(record, 'operation', 32, minimum=1)
        # Vault read denials are valid audit facts, but this tool's rule is
        # exclusively about denied mutations. Never count a read as a mutation.
        if operation in (11, 12, 13):
            return None
        if operation not in OPERATIONS:
            raise ValueError('unknown file operation')
        integer(record, 'pid', 32, minimum=1)
        integer(record, 'tid', 32, minimum=1)
        integer(record, 'start_ns')
        timestamp = integer(record, 'timestamp_ns')
        target = (integer(record, 'dev_major', 32), integer(record, 'dev_minor', 32), integer(record, 'ino', minimum=1))
        process = integer(record, 'process_inode', default=0)
        fact = dict(line=line_number, event=kind, timestamp_field='timestamp_ns', timestamp_ns=timestamp,
                    operation=OPERATIONS[operation], pid=record['pid'], tid=record['tid'], start_ns=record['start_ns'])
        fact['subscription_generation'] = (subscriptions or SubscriptionIndex()).generation(record)
        if not process:
            return None, dict(fact, unattributed_reason='process_inode_unavailable')
    return (process, *target, fact['subscription_generation']), fact


class Grouper:
    def __init__(self, machine_id, boot_id, capture_id, max_groups=1024, samples=8,
                 rule_window_ms=0, rule_history=32):
        if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', machine_id):
            raise ValueError('machine-id must be an explicit 1..128 character identifier')
        if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', capture_id):
            raise ValueError('capture-id must explicitly identify one service-instance capture')
        boot = uuid.UUID(boot_id)
        if not boot.int:
            raise ValueError('boot-id must be nonzero')
        if any(type(value) is not int for value in (max_groups, samples, rule_window_ms, rule_history)):
            raise ValueError('group, sample and rule limits must be integers')
        if not 1 <= max_groups <= 4096 or not 1 <= samples <= 32:
            raise ValueError('max-groups must be 1..4096; samples must be 1..32')
        if not 0 <= rule_window_ms <= 3_600_000 or not 1 <= rule_history <= 128:
            raise ValueError('rule-window-ms must be 0..3600000; rule-history must be 1..128')
        self.source = dict(machine_id=machine_id, boot_id=str(boot), capture_id=capture_id, assurance='operator-declared')
        self.subscriptions = SubscriptionIndex()
        self.listener_instance = None
        self.mixed_listener_instances = False
        self.max_groups, self.samples = max_groups, samples
        self.rule_window_ms, self.rule_history = rule_window_ms, rule_history
        self.rule_matches = self.rule_history_evictions = 0
        self.groups = OrderedDict()
        self.unattributed_reasons = {}
        self.counts = dict(records=0, grouped=0, unattributed=0, ignored=0, invalid=0, segments=0, capacity_evictions=0)

    def segment(self, key, group, reason):
        process, major, minor, inode, generation = key
        self.counts['segments'] += 1
        result = dict(event='process_object_evidence', source=self.source, process_inode=process,
                    target=dict(major=major, minor=minor, inode=inode), subscription_generation=generation, segment_id=self.counts['segments'],
                    segment_end=reason, first_line=group['first'], last_line=group['last'],
                    permission_allow=group['allow'], permission_deny=group['deny'], mutation_denied=group['mutation'],
                    denial_operations=group['operations'],
                    allow_and_mutation_denial_observed=bool(group['allow'] and group['mutation']),
                    classification='undetermined', observations_complete_for_process=False, object_lifetime_verified=False,
                    evidence_samples=list(group['evidence']))
        if group['rule'] is not None:
            result['behavior'] = group['rule'].report()
        return result

    def accept(self, raw, oversized=False):
        self.counts['records'] += 1
        line_number = self.counts['records']
        try:
            if oversized:
                raise ValueError('oversized record')
            record = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object,
                                parse_constant=reject_constant, parse_float=finite_float)
            if not isinstance(record, dict):
                raise ValueError('JSON object required')
            if record.get('event') == 'fanotify_target_handover' and not self.subscriptions.boundaries:
                raise ValueError('handover requires a prevalidated complete capture')
            result = observation(record, line_number, self.subscriptions)
            if result is not None and record.get('event') == 'fanotify_decision':
                listener = (record['pid_namespace_inode'], record['listener_pid'], record['instance_ns'])
                if self.listener_instance is None:
                    self.listener_instance = listener
                elif self.listener_instance != listener:
                    self.mixed_listener_instances = True
            if self.mixed_listener_instances:
                raise ValueError('multiple listener instances in one declared capture')
        except (ValueError, UnicodeError, RecursionError, TypeError):
            self.counts['invalid'] += 1
            return []
        if result is None:
            self.counts['ignored'] += 1
            return []
        key, fact = result
        if key is None:
            self.counts['unattributed'] += 1
            reason = fact['unattributed_reason']
            self.unattributed_reasons[reason] = self.unattributed_reasons.get(reason, 0) + 1
            return []
        self.counts['grouped'] += 1
        output = []
        if key not in self.groups:
            if len(self.groups) == self.max_groups:
                old_key, old_group = self.groups.popitem(last=False)
                output.append(self.segment(old_key, old_group, 'capacity'))
                self.counts['capacity_evictions'] += 1
            self.groups[key] = dict(first=line_number, last=line_number, allow=0, deny=0, mutation=0,
                                    operations={}, evidence=deque(maxlen=self.samples),
                                    rule=AccessThenDenial(self.rule_window_ms, self.rule_history, self.samples)
                                    if self.rule_window_ms else None)
        group = self.groups[key]
        self.groups.move_to_end(key)
        group['last'] = line_number
        if fact['event'] == 'fanotify_decision':
            group[fact['decision']] += 1
        else:
            group['mutation'] += 1
            operation = fact['operation']
            group['operations'][operation] = group['operations'].get(operation, 0) + 1
        group['evidence'].append(fact)
        if group['rule'] is not None:
            rule = group['rule']
            before_matches, before_evictions = rule.matches, rule.history_evictions
            rule.accept(fact)
            self.rule_matches += rule.matches - before_matches
            self.rule_history_evictions += rule.history_evictions - before_evictions
        return output

    def finish(self):
        while self.groups:
            key, group = self.groups.popitem(last=False)
            yield self.segment(key, group, 'eof')
        yield dict(event='evidence_summary', source=self.source, **self.counts,
                   max_groups=self.max_groups, samples_per_group=self.samples,
                   rule_window_ms=self.rule_window_ms, rule_history=self.rule_history,
                   rule_matches=self.rule_matches, rule_history_evictions=self.rule_history_evictions,
                   deduplication='none', classification='undetermined', unattributed_reasons=self.unattributed_reasons,
                   subscription_handovers=len(self.subscriptions.boundaries),
                   subscription_partition='whole-group timestamp epochs; equal-boundary denials unpaired',
                   listener_instance=self.listener_instance, mixed_listener_instances=self.mixed_listener_instances)


def consume(stream, grouper):
    # An offline batch needs its complete boundary index before it can safely
    # interpret reordered records. Spool to bounded disk, not an unbounded list.
    with tempfile.TemporaryFile(mode='w+b') as spool:
        total = records = 0
        handovers = []
        while True:
            raw = stream.readline(MAX_LINE + 1)
            if not raw:
                break
            total += len(raw)
            records += 1
            oversized = len(raw) > MAX_LINE
            if oversized and not raw.endswith(b'\n'):
                tail = raw
                while tail and not tail.endswith(b'\n'):
                    tail = stream.readline(MAX_LINE + 1)
                    total += len(tail)
                    if total > MAX_INPUT_BYTES:
                        raise ValueError('offline input exceeds 128 MiB')
            if total > MAX_INPUT_BYTES or records > MAX_INPUT_RECORDS:
                raise ValueError('offline input exceeds 128 MiB or 1000000 records')
            stored = b'\x00\n' if oversized else raw + (b'' if raw.endswith(b'\n') else b'\n')
            spool.write(stored)
            if not oversized:
                try:
                    record = decoded_record(raw)
                except (ValueError, UnicodeError, RecursionError, TypeError):
                    continue  # Account for the invalid record in the second pass.
                if isinstance(record, dict) and record.get('event') == 'fanotify_target_handover':
                    if len(handovers) == MAX_HANDOVERS:
                        raise ValueError('at most 4096 subscription handovers are supported')
                    handovers.append(record)
        grouper.subscriptions = SubscriptionIndex(handovers)
        spool.seek(0)
        for raw in spool:
            yield from grouper.accept(raw)
        yield from grouper.finish()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--machine-id', required=True, help='declared origin of this single-source stream')
    parser.add_argument('--boot-id', required=True, help='declared origin boot UUID; never inferred from the analysis host')
    parser.add_argument('--capture-id', required=True, help='declared single-service-instance capture; do not concatenate instances')
    parser.add_argument('--max-groups', type=int, default=1024)
    parser.add_argument('--samples', type=int, default=8)
    parser.add_argument('--rule-window-ms', type=int, default=0,
                        help='observe allowed access preceding a denied mutation within this interval; 0 disables')
    parser.add_argument('--rule-history', type=int, default=32,
                        help='maximum retained allows and unmatched denials per group (1..128 each)')
    args = parser.parse_args(argv)
    try:
        grouper = Grouper(args.machine_id, args.boot_id, args.capture_id, args.max_groups, args.samples,
                          args.rule_window_ms, args.rule_history)
    except ValueError as error:
        parser.error(str(error))
    try:
        for result in consume(sys.stdin.buffer, grouper):
            print(json.dumps(result, separators=(',', ':'), ensure_ascii=True))
    except (OSError, ValueError) as error:
        print('evidence analysis failed: ' + str(error), file=sys.stderr)
        return 1
    return int(grouper.counts['invalid'] != 0)


if __name__ == '__main__':
    sys.exit(main())
