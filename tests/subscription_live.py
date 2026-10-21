#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""A persistent writer must not reuse pre-handover access evidence."""
import argparse
from contextlib import ExitStack
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import time

from fanotify_handover import LiveService
from permission_audit import contents
from management_harness import call
from writer_harness import WriterProcess
from behavior_workloads import reference

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from evidence import Grouper, consume
from replay_capture import verify_capture
from evaluate_capture import compare, DELIVERIES
from chain_capture import summarize


def experiment(build, event, pidfd, artifact=None):
    with tempfile.TemporaryDirectory(prefix='secmon-epochs-') as temporary, ExitStack() as stack:
        root = Path(temporary)
        target, spare = root / 'target', root / 'spare'
        target.write_bytes(b'protected original\n')
        spare.write_bytes(b'spare\n')
        before = target.stat()
        actor = stack.enter_context(WriterProcess(build / 'secmon-writer-scenario', target))
        cookie = reference(stack, actor.process.pid)
        def fields(targets):
            return (f'protect "{target}"\n' + ''.join(f'fanotify-file "{p}"\n' for p in targets) +
                    f'fanotify-event {event}\nfanotify-decision allow\n')
        service = LiveService(build, root, target, fields([target]), combined=True,
                              requester_pidfd=pidfd)
        stack.callback(service.close)
        revision = 1
        def change(targets, expected='ok'):
            nonlocal revision
            service.publish(revision + 1, fields(targets))
            call(service.binary, 'reload', service.control, expected)
            if expected == 'ok':
                revision += 1
        def read():
            assert actor.request('r') == 0
        def write():
            assert actor.request('w') == errno.EACCES
        read(); write()                        # epoch 1: one supported pair
        change([target, spare])                # epoch 2: retained object is partitioned too
        write()                               # old access must not support this denial
        read(); write()                        # epoch 2: one new supported pair
        change([spare])                        # epoch 3: remove target subscription
        write()                               # BPF still protects target independently
        change([target, root / 'missing'], 'prepare_failed')
        change([target])                       # epoch 4: re-add exactly the same inode
        write()                               # neither epoch 1 nor 2 access is usable
        read(); write()                        # epoch 4: one fresh pair
        service.stop()
        raw = contents(service.output).encode()
        diagnostics = contents(service.errors)
        records = [json.loads(line) for line in raw.splitlines()]
        handovers = [r for r in records if r['event'] == 'fanotify_target_handover']
        assert [(r['from_generation'], r['to_generation']) for r in handovers] == [(1, 2), (2, 3), (3, 4)]
        source = dict(machine_id=Path('/etc/machine-id').read_text().strip(),
                      boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                      capture_id=f'epochs-{event}-{int(pidfd)}-{service.initial["instance_ns"]}')
        options = dict(rule_window_ms=10000, rule_history=128)
        rows = list(consume(io.BytesIO(raw), Grouper(**source, **options)))
        summary = rows[-1]
        assert summary['invalid'] == 0 and summary['subscription_handovers'] == 3
        assert summary['rule_matches'] == (3 if pidfd else 0), summary
        denials = [r for r in records if r['event'] == 'file_denied']
        assert len(denials) == 6 and all(r['process_inode'] == cookie and r['ino'] == before.st_ino for r in denials)
        assert sum(r['mutation_denied'] for r in rows[:-1]) == 6
        raw_rows = [(i, r, (json.dumps(r) + '\n').encode()) for i, r in enumerate(records, 1)]
        evaluated = compare(raw_rows, source, {cookie: 'persistent-writer'}, 10000, 128, 1024, DELIVERIES, 21)
        for report in evaluated:
            expected = 0 if report['delivery'].startswith('drop-') or not pidfd else 3
            assert report['bounded_matches'] == report['delivered_eligible'] == expected, report
        chains = summarize(records, min_objects=2, pair_window_ms=10000)
        assert all(not p['multi_object_access_then_denial_observed'] for p in chains['processes'])
        assert target.stat().st_ino == before.st_ino and target.read_bytes() == b'protected original\n'
        assert 'ringbuf_dropped=0' in diagnostics and 'baseline_update_failed=0' in diagnostics
        evidence = b''.join((json.dumps(r, separators=(',', ':'), ensure_ascii=True) + '\n').encode() for r in rows)
        if artifact:
            destination = artifact / source['capture_id']
            destination.mkdir(parents=True)
            (destination / 'audit.jsonl').write_bytes(raw)
            (destination / 'evidence.jsonl').write_bytes(evidence)
            manifest = dict(capture=source['capture_id'], source=summary['source'], summary=summary,
                            audit_sha256=hashlib.sha256(raw).hexdigest(), evidence_sha256=hashlib.sha256(evidence).hexdigest(),
                            scenarios=[dict(process_inode=cookie, role='persistent-writer')],
                            interpretation='subscription isolation experiment; not malicious classification')
            (destination / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
            assert verify_capture(destination)['reproduced']
        return dict(event=event, requester_pidfd=pidfd, handovers=3, denials=6,
                    pairs=summary['rule_matches'], delivery_checks=len(evaluated), passed=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', default='build', type=Path)
    parser.add_argument('--duration', type=int, default=0)
    parser.add_argument('--artifact-dir', type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0 or sys.flags.optimize or os.environ.get('PYTHONOPTIMIZE'):
        parser.error('run as root without Python optimization')
    if not 0 <= args.duration <= 1200:
        parser.error('duration must be 0..1200 seconds')
    started, variants = time.monotonic(), 0
    initial_fds = len(os.listdir('/proc/self/fd'))
    while True:
        for pidfd in (False, True):
            for event in ('open', 'access'):
                result = experiment(args.build_dir.resolve(), event, pidfd, args.artifact_dir)
                variants += 1
                assert len(os.listdir('/proc/self/fd')) == initial_fds
                print(json.dumps(result), flush=True)
        if time.monotonic() - started >= args.duration:
            break
    print(json.dumps(dict(passed=True, variants=variants, seconds=round(time.monotonic()-started, 3),
                          controller_fds=initial_fds)), flush=True)


if __name__ == '__main__':
    main()
