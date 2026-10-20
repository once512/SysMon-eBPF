#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent timestamp oracle and controlled delivery/loss/capacity experiments."""
import hashlib
import io
import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile
from offline_evidence import BOOT, permission, denial

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from evidence import Grouper, consume
from evaluate_capture import compare, evaluate_capture, DELIVERIES, oracle

SOURCE = dict(machine_id='test', boot_id=BOOT, capture_id='evaluation')


def rows_of(records):
    return [(i, r, (json.dumps(r) + '\n').encode()) for i, r in enumerate(records, 1)]


def main():
    records = []
    for i in range(100):
        records.extend([permission(received_ns=10 + 2*i, responded_ns=10 + 2*i, request_id=i+1),
                        denial(timestamp_ns=11 + 2*i)])
    rows = rows_of(records)
    result = {r['delivery']: r for r in compare(rows, SOURCE, {77: 'controlled'}, 1, 8, 1024, DELIVERIES, 123)}
    for mode in ('original', 'reverse', 'chronological'):
        assert result[mode]['bounded_matches'] == result[mode]['delivered_eligible'] == 100
    assert result['permissions-last']['bounded_matches'] == 8
    assert result['permissions-last']['missed_with_bounded_state'] == 92
    assert result['permissions-last']['eligibility_lost_with_input'] == 0
    assert result['drop-permissions']['eligibility_lost_with_input'] == 100
    assert result['drop-permissions']['missed_with_bounded_state'] == 0
    assert result['drop-permissions']['roles'][0]['removed_denials'] == 0
    assert result['drop-denials']['roles'][0]['removed_denials'] == 100
    assert result['drop-denials']['bounded_matches'] == 0
    assert result['shuffle'] == compare(rows, SOURCE, {77: 'controlled'}, 1, 8, 1024, ['shuffle'], 123)[0]
    unknown = compare(rows_of([dict(event='future-event', timestamp_ns=[]), *records]),
                      SOURCE, {}, 1, 128, 1024, ['chronological'], 0)[0]
    assert unknown['bounded_matches'] == 100
    eviction = compare(rows_of([permission(), permission(cookie=78), denial(), denial(cookie=78)]),
                       SOURCE, {}, 1, 8, 1, ['original'], 0)[0]
    assert eviction['bounded_matches'] == 0 and eviction['missed_with_bounded_state'] == 2
    # A quadratic oracle checks the bisect reference independently across keys,
    # permission kinds/decisions and exact equal/outside timestamp boundaries.
    rng = random.Random(20261020)
    for _ in range(60):
        records = []
        for _ in range(40):
            cookie, inode, timestamp = rng.randrange(1, 4), rng.randrange(90, 93), rng.randrange(1, 4_000_000)
            records.append(permission(cookie=cookie, inode=inode, received_ns=timestamp, responded_ns=timestamp,
                                      decision=rng.choice(('allow', 'deny')), permission_event=rng.choice(('open','access','exec')))
                           if rng.randrange(2) else denial(cookie=cookie, inode=inode, timestamp_ns=timestamp))
        expected = sum(any(a['event']=='fanotify_decision' and a['decision']=='allow' and
                           a['permission_event'] in ('open','access') and a['requester_process_inode']==d['process_inode'] and
                           a['inode']==d['ino'] and 0 < d['timestamp_ns']-a['responded_ns'] <= 1_000_000
                           for a in records) for d in records if d['event']=='file_denied')
        rows_random = rows_of(records)
        assert sum(r['eligible'] for r in oracle(rows_random, 1, {}).values()) == expected
        for result_random in compare(rows_random, SOURCE, {}, 1, 128, 1024, DELIVERIES[:5], 1):
            assert result_random['bounded_matches'] == expected
    with tempfile.TemporaryDirectory(prefix='secmon-evaluation-') as temporary:
        root = Path(temporary)
        raw = b''.join(r[2] for r in rows)
        grouped = list(consume(io.BytesIO(raw), Grouper('test', BOOT, 'evaluation', rule_window_ms=1)))
        evidence = b''.join((json.dumps(r,separators=(',',':'),ensure_ascii=True)+'\n').encode() for r in grouped)
        manifest = dict(source=grouped[-1]['source'], summary=grouped[-1], capture='evaluation',
                        audit_sha256=hashlib.sha256(raw).hexdigest(), evidence_sha256=hashlib.sha256(evidence).hexdigest(),
                        scenarios=[dict(process_inode=77,role='controlled')])
        (root/'audit.jsonl').write_bytes(raw)
        (root/'evidence.jsonl').write_bytes(evidence)
        (root/'manifest.json').write_text(json.dumps(manifest))
        report = evaluate_capture(root, [1], [8], modes=['permissions-last'])
        assert report['results'][0]['missed_with_bounded_state'] == 92
        assert report['classification'] == 'undetermined' and report['response'] == 'none'
        tool = Path(__file__).resolve().parents[1]/'tools/evaluate_capture.py'
        command = [sys.executable,'-B',str(tool),str(root),'--window-ms','1','--history','8','--delivery','permissions-last']
        result_cli = subprocess.run(command,text=True,capture_output=True,check=True)
        assert json.loads(result_cli.stdout) == report
        (root/'audit.jsonl').write_bytes(b'corrupt\n')
        result_cli = subprocess.run(command,text=True,capture_output=True)
        assert result_cli.returncode == 1 and not result_cli.stdout
    print('PASS evaluation oracle, delivery reorder, loss/capacity attribution, declared labels, reproducibility and integrity')


if __name__ == '__main__':
    main()
