#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent distinct-object window oracle and verified chain CLI boundary."""
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
from chain_capture import peak, summarize, chain_capture
from evidence import Grouper, consume


def main():
    rng = random.Random(20261020)
    for _ in range(100):
        events = [(rng.randrange(30), (1, 2, rng.randrange(8))) for _ in range(40)]
        span = rng.randrange(10)
        expected = max(len({obj for timestamp, obj in events if end-span <= timestamp <= end})
                       for end, _ in events)
        result = peak(events, span)
        assert result['distinct_objects'] == expected
        assert result == peak(events[::-1], span)
        assert result['end_ns']-result['begin_ns'] <= span
    assert peak([(1, (1,)), (2, (2,)), (3, (3,))], 2)['distinct_objects'] == 3
    assert peak([(1, (1,)), (2, (2,)), (3, (3,))], 1)['distinct_objects'] == 2
    records = []
    for inode in (90, 91, 92):
        records += [permission(inode=inode, received_ns=10, responded_ns=10),
                    denial(inode=inode, timestamp_ns=11)]
    result = summarize(records, {77: 'declared-role'})
    row = result['processes'][0]
    assert row['distinct_denied_objects'] == row['distinct_accessed_objects'] == 3
    assert row['paired_denials'] == row['paired_spread_peak']['distinct_objects'] == 3
    assert row['multi_object_denials_observed'] and row['multi_object_access_then_denial_observed']
    assert result == summarize(records[::-1], {77: 'declared-role'})
    assert summarize(records * 4)['processes'][0]['denial_spread_peak']['distinct_objects'] == 3
    for _ in range(60):
        records = []
        for _ in range(40):
            cookie, inode, stamp = rng.randrange(1,4), rng.randrange(90,95), rng.randrange(4_000_000)
            records.append(permission(cookie=cookie,inode=inode,received_ns=stamp,responded_ns=stamp,
                                      decision=rng.choice(('allow','deny')),
                                      permission_event=rng.choice(('open','access','exec')))
                           if rng.randrange(2) else denial(cookie=cookie,inode=inode,timestamp_ns=stamp))
        report = summarize(records, pair_window_ms=1, chain_window_ms=1)
        for row in report['processes']:
            denials = [d for d in records if d['event']=='file_denied' and d['process_inode']==row['process_inode']]
            paired = [d for d in denials if any(
                a['event']=='fanotify_decision' and a['decision']=='allow' and
                a['permission_event'] in ('open','access') and
                a['requester_process_inode']==d['process_inode'] and a['inode']==d['ino'] and
                0 < d['timestamp_ns']-a['responded_ns'] <= 1_000_000 for a in records)]
            assert row['paired_denials']==len(paired)
            expected = max((len({d['ino'] for d in paired if end-1_000_000 <= d['timestamp_ns'] <= end})
                            for end in [d['timestamp_ns'] for d in paired]), default=0)
            assert row['paired_spread_peak']['distinct_objects']==expected
        assert report==summarize(records[::-1],pair_window_ms=1,chain_window_ms=1)
    # Same inode on distinct devices is distinct; another process cannot lend
    # its access, exec/deny cannot lend it, equal timestamps do not qualify.
    records = [permission(inode=90, cookie=78), denial(inode=90),
               permission(inode=91, permission_event='exec'), denial(inode=91),
               permission(inode=92, decision='deny'), denial(inode=92),
               permission(inode=93, received_ns=10, responded_ns=10), denial(inode=93, timestamp_ns=10)]
    assert all(r['paired_denials']==0 for r in summarize(records)['processes'])
    records = [denial(inode=90), dict(denial(inode=90), dev_minor=9)]
    assert summarize(records)['processes'][0]['distinct_denied_objects']==2
    assert summarize([permission(cookie=0, requester_reference='disabled'), denial(cookie=0)])['unattributed']==2
    for bad in (0, -1, True, 0.5):
        try:
            summarize([], pair_window_ms=bad)
        except ValueError:
            pass
        else:
            raise AssertionError('invalid time accepted')
    for bad in ([None], [permission(), dict(permission(), instance_ns=333)]):
        try:
            summarize(bad)
        except ValueError:
            pass
        else:
            raise AssertionError('invalid/mixed input accepted')
    # Resource limits reject rather than silently dropping keys.
    try:
        summarize(denial(inode=i+1) for i in range(4097))
    except ValueError:
        pass
    else:
        raise AssertionError('object budget bypassed')
    with tempfile.TemporaryDirectory(prefix='secmon-chain-test-') as temporary:
        root = Path(temporary)
        records = [permission(inode=i, received_ns=10, responded_ns=10) for i in (90,91,92)]
        records += [denial(inode=i, timestamp_ns=11) for i in (90,91,92)]
        raw = b''.join((json.dumps(r)+'\n').encode() for r in records)
        rows = list(consume(io.BytesIO(raw), Grouper('test', BOOT, 'chain', rule_window_ms=1000)))
        evidence = b''.join((json.dumps(r,separators=(',',':'),ensure_ascii=True)+'\n').encode() for r in rows)
        manifest = dict(source=rows[-1]['source'], summary=rows[-1], capture='chain',
                        audit_sha256=hashlib.sha256(raw).hexdigest(), evidence_sha256=hashlib.sha256(evidence).hexdigest(),
                        tools=[dict(role='declared',process_inode=77)])
        (root/'audit.jsonl').write_bytes(raw)
        (root/'evidence.jsonl').write_bytes(evidence)
        (root/'manifest.json').write_text(json.dumps(manifest))
        expected = chain_capture(root)
        assert expected['processes'][0]['role']=='declared'
        assert expected['classification']=='undetermined' and expected['response']=='none'
        tool = Path(__file__).resolve().parents[1]/'tools/chain_capture.py'
        command = [sys.executable,'-B',str(tool),str(root)]
        output = subprocess.run(command,capture_output=True,check=True)
        assert json.loads(output.stdout)==expected
        (root/'audit.jsonl').write_bytes(b'corrupt\n')
        output = subprocess.run(command,capture_output=True)
        assert output.returncode==1 and not output.stdout
    print('offline object chains passed')


if __name__ == '__main__':
    main()
