#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Streaming memory/eviction regression; input and emitted segments are never accumulated."""
import argparse
import json
from pathlib import Path
import sys
import time
import tracemalloc
from offline_evidence import permission, denial, BOOT

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from evidence import Grouper, consume


class GeneratedStream:
    def __init__(self, records, mode, history):
        self.remaining = self.records = records
        self.mode = mode
        self.history = history

    def readline(self, size):
        if self.remaining == 0:
            return b''
        index = self.records - self.remaining
        self.remaining -= 1
        if self.mode == 'hot':
            row = permission(request_id=index + 1) if index < self.records // 2 else denial()
        elif self.mode == 'churn':
            row = denial(cookie=index + 1)
        else:
            cookie = index // (2 * self.history) + 1
            if index % (2 * self.history) < self.history:
                row = permission(cookie=cookie, received_ns=1000, responded_ns=1100, request_id=index + 1)
            else:
                row = denial(cookie=cookie, timestamp_ns=700)
        raw = (json.dumps(row) + '\n').encode()
        assert len(raw) <= size
        return raw


def experiment(records, mode, memory_limit, max_groups, samples, history):
    if mode == 'saturated':
        records = 2 * max_groups * history
    tracemalloc.start()
    start = time.monotonic()
    groups = Grouper('stress-host', BOOT, 'stress-' + mode, max_groups=max_groups, samples=samples,
                    rule_window_ms=1, rule_history=history)
    segments = matches = 0
    summary = None
    for row in consume(GeneratedStream(records, mode, history), groups):
        if row['event'] == 'process_object_evidence':
            segments += 1
            matches += row['behavior']['matches']
            assert len(row['evidence_samples']) <= samples
            assert len(row['behavior']['evidence_samples']) <= samples
        else:
            summary = row
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert summary['records'] == summary['grouped'] == records
    assert summary['invalid'] == summary['unattributed'] == summary['ignored'] == 0
    assert summary['segments'] == segments == (1 if mode == 'hot' else max_groups if mode == 'saturated' else records)
    assert summary['capacity_evictions'] == (max(0, records - max_groups) if mode == 'churn' else 0)
    assert summary['rule_matches'] == matches == (records - records // 2 if mode == 'hot' else 0)
    assert summary['rule_history_evictions'] == (max(0, records // 2 - history) if mode == 'hot' else 0)
    assert peak < memory_limit * 1024 * 1024, (peak, memory_limit)
    return dict(mode=mode, records=records, max_groups=max_groups, history=history, samples=samples,
                peak_traced_bytes=peak,
                seconds=round(time.monotonic() - start, 3), passed=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--records', type=int, default=100_000)
    parser.add_argument('--memory-limit-mib', type=int, default=16)
    parser.add_argument('--mode', choices=('hot', 'churn', 'saturated'), nargs='+', default=['hot', 'churn'])
    parser.add_argument('--groups', type=int, default=64)
    parser.add_argument('--history', type=int, default=8)
    parser.add_argument('--samples', type=int, default=4)
    args = parser.parse_args()
    if not 128 <= args.records <= 2_000_000 or not 4 <= args.memory_limit_mib <= 2048:
        parser.error('records must be 128..2000000; memory-limit-mib must be 4..2048')
    if not 1 <= args.groups <= 4096 or not 1 <= args.history <= 128 or not 1 <= args.samples <= 32:
        parser.error('groups must be 1..4096; history must be 1..128; samples must be 1..32')
    if sys.flags.optimize:
        parser.error('run without Python optimization')
    for mode in args.mode:
        print(json.dumps(experiment(args.records, mode, args.memory_limit_mib,
                                    args.groups, args.samples, args.history)), flush=True)


if __name__ == '__main__':
    main()
