#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only independent accounting of metadata_soak's frozen raw artifacts."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re


def verify(root):
    summary = json.loads((root / 'summary.json').read_text())
    assert summary['passed']
    for relative, expected in json.loads((root / 'artifact_sha256.json').read_text()).items():
        assert hashlib.sha256((root / relative).read_bytes()).hexdigest() == expected, relative
    sources = json.loads((root / 'source_sha256.json').read_text())
    for path, expected in sources.items():
        assert hashlib.sha256(Path(path).read_bytes()).hexdigest() == expected, path
    journal = [json.loads(line) for line in (root / 'journal.jsonl').open()]
    assert len(journal) == summary['cycles'] and journal
    def formula(cycles):
        def n(period): return (cycles + period - 1) // period
        return dict(commands=32*cycles+2*n(3)+n(7)+n(11)+5*n(17)+3*n(29),
                    file_denied=27*cycles+2*n(3)+n(7)+n(11)+2*n(17),
                    response_started=2*cycles+n(17),
                    response_blocked=23*cycles+2*n(3)+n(7)+n(11)+n(17),
                    reloads=cycles+n(3)+n(29), rejections=n(7)+n(11)+n(29))
    trigger_order = ('x','d','a','r','i','s','c','l','v','f','b','e','n','p','t')
    for number, row in enumerate(journal, 1):
        assert row['cycle'] == number
        assert row['trigger'] == trigger_order[(number-1) % 15]
        assert row['service_fds'] == summary['service_fd_baseline']
        for key, value in formula(number).items():
            if key in row: assert row[key] == value, (number, key, row[key], value)
    expected = formula(len(journal))
    for key, value in expected.items(): assert summary[key] == value, (key, summary[key], value)
    counts = Counter(); operations = Counter(); starts = Counter(); blocked = 0
    active = {}; queries = Counter(); triggers = Counter()
    identities = summary['identities']; native, compat = identities['native'], identities['compat']
    assert len(set(identities.values())) == 3 and all(identities.values())
    operation_ids = {'x':16,'d':17,'a':18,'r':19,'i':20,'s':20,'c':20,'l':20,
                     'v':2,'f':2,'b':2,'e':2,'n':2,'p':2,'t':2}
    for number, line in enumerate((root / 'audit.jsonl').open(), 1):
        event = json.loads(line); counts[event['event']] += 1
        if event['event'] != 'file_denied': continue
        process = event['process_inode']; operation = event['operation']; operations[operation] += 1
        assert process in (native, compat), (number, process)
        assert not event['response_failed'] and event['errno'] == 13
        if event['response_started']:
            assert event['canary_hit'] and not event['response_blocked']
            assert operation in set(operation_ids.values())
            assert bool(event['ioctl_command']) == (operation == 20)
            key = (process, event['response_epoch'], event['response_deadline_boot_ns'])
            active[key] = event['timestamp_ns']; starts[process] += 1; triggers[operation] += 1
        elif event['response_blocked']:
            assert not event['canary_hit']
            assert (process, event['response_epoch'], event['response_deadline_boot_ns']) in active
            blocked += 1
        else:
            # The only ordinary denials are the two unknown-ioctl probes per round.
            assert operation == 21 and not event['canary_hit'] and event['ioctl_command'] == 0xdeadbeef
            assert not event['response_epoch'] and not event['response_deadline_boot_ns']
            queries[process] += 1
        if operation == 21: assert not event['canary_hit']
    cycles = summary['cycles']; expiry = (cycles+16)//17
    assert starts == {native:cycles+expiry, compat:cycles}
    assert queries == {native:cycles, compat:cycles}
    assert blocked == expected['response_blocked']
    assert counts['file_denied'] == expected['file_denied']
    assert counts == summary['audit_counts'] and sum(counts.values()) == summary['audit_records']
    assert {str(k):v for k,v in operations.items()} == summary['denial_operations']
    expected_triggers = Counter(operation_ids[trigger_order[i % 15]] for i in range(cycles))
    expected_triggers[16] += expiry; expected_triggers[20] += cycles
    assert triggers == expected_triggers
    diagnostic = (root / 'diagnostics.log').read_text()
    def counter(name):
        values = re.findall(r'(?<![a-z_])'+re.escape(name)+r'=(\d+)', diagnostic)
        assert values, name
        return int(values[-1])
    for name in ('ringbuf_dropped','baseline_update_failed','audit_dropped','audit_invalid','audit_errno','audit_queued','response_failed'):
        assert counter(name) == 0, name
    for name, value in {'policy_denied':expected['file_denied'], 'response_started':expected['response_started'],
                        'response_denied':blocked, 'audit_written':sum(counts.values())}.items():
        assert counter(name) == value, name
    assert summary['controller_fds_start'] == summary['controller_fds_end']
    return dict(verified=True, cycles=cycles, commands=expected['commands'], file_denied=expected['file_denied'],
                response_started=expected['response_started'], response_blocked=blocked,
                audit_records=sum(counts.values()), source_hashes=len(sources))


def main():
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('artifact', type=Path)
    args=parser.parse_args(); print(json.dumps(verify(args.artifact.resolve())))

if __name__ == '__main__': main()
