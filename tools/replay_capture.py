#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify a captured audit/evidence bundle and compare observation windows offline."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

from evidence import Grouper, consume, finite_float, reject_constant, unique_object

MAX_MANIFEST = 2 * 1024 * 1024


def digest(stream):
    result = hashlib.sha256()
    while True:
        chunk = stream.read(1024 * 1024)
        if not chunk:
            break
        result.update(chunk)
    stream.seek(0)
    return result.hexdigest()


def replay(stream, source, options):
    grouper = Grouper(source['machine_id'], source['boot_id'], source['capture_id'], **options)
    result_hash = hashlib.sha256()
    summary = None
    for row in consume(stream, grouper):
        encoded = (json.dumps(row, separators=(',', ':'), ensure_ascii=True) + '\n').encode()
        result_hash.update(encoded)
        if row['event'] == 'evidence_summary':
            summary = json.loads(encoded)
    stream.seek(0)
    return result_hash.hexdigest(), summary


def verify_capture(directory, windows=()):
    with (directory / 'manifest.json').open('rb') as manifest_file:
        raw = manifest_file.read(MAX_MANIFEST + 1)
    if len(raw) > MAX_MANIFEST:
        raise ValueError('manifest exceeds 2 MiB')
    manifest = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object,
                          parse_constant=reject_constant, parse_float=finite_float)
    if not isinstance(manifest, dict):
        raise ValueError('manifest must be a JSON object')
    source, expected = manifest['source'], manifest['summary']
    if not isinstance(source, dict) or not isinstance(expected, dict):
        raise ValueError('invalid capture source or summary')
    if source != expected['source'] or manifest['capture'] != source['capture_id']:
        raise ValueError('inconsistent capture context')
    if source.get('assurance') != 'operator-declared':
        raise ValueError('unsupported source assurance')
    options = dict(max_groups=expected['max_groups'], samples=expected['samples_per_group'],
                   rule_window_ms=expected['rule_window_ms'], rule_history=expected['rule_history'])
    if any(type(value) is not int for value in options.values()):
        raise ValueError('invalid numeric replay options')
    for window in windows:
        if type(window) is not int or not 0 <= window <= 3_600_000:
            raise ValueError('window-ms must be 0..3600000')
    with (directory / 'audit.jsonl').open('rb') as audit, (directory / 'evidence.jsonl').open('rb') as evidence:
        if digest(audit) != manifest['audit_sha256']:
            raise ValueError('audit SHA-256 does not match manifest')
        if digest(evidence) != manifest['evidence_sha256']:
            raise ValueError('evidence SHA-256 does not match manifest')
        actual_hash, summary = replay(audit, source, options)
        if actual_hash != manifest['evidence_sha256'] or summary != expected:
            raise ValueError('current implementation does not reproduce stored evidence')
        if summary['invalid'] or summary['mixed_listener_instances']:
            raise ValueError('capture contains invalid records or mixed listener instances')
        comparisons = []
        for window in dict.fromkeys(windows):
            _, compared = replay(audit, source, dict(options, rule_window_ms=window))
            comparisons.append(dict(window_ms=window, rule_matches=compared['rule_matches'],
                                    history_evictions=compared['rule_history_evictions']))
    return dict(event='capture_replay', source=source, reproduced=True,
                manifest_sha256=hashlib.sha256(raw).hexdigest(),
                audit_sha256=manifest['audit_sha256'], evidence_sha256=manifest['evidence_sha256'],
                integrity='hashes-against-operator-manifest', authenticity_verified=False,
                classification='undetermined', response='none', summary=summary, windows=comparisons)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture_directory', type=Path)
    parser.add_argument('--window-ms', type=int, nargs='+', default=[],
                        help='compare up to 16 alternative windows; 0 disables the observation rule')
    args = parser.parse_args()
    if len(args.window_ms) > 16:
        parser.error('at most 16 comparison windows')
    try:
        result = verify_capture(args.capture_directory, args.window_ms)
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as error:
        print('capture replay failed: ' + str(error), file=sys.stderr)
        return 1
    print(json.dumps(result, separators=(',', ':'), ensure_ascii=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
