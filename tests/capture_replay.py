#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture hashes, declared context and exact replay must agree before comparisons."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from offline_evidence import BOOT, denial, permission

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from evidence import Grouper, consume
from replay_capture import verify_capture


def main():
    with tempfile.TemporaryDirectory(prefix='secmon-replay-') as temporary:
        root = Path(temporary)
        raw = b''.join((json.dumps(r) + '\n').encode() for r in [permission(), denial()])
        rows = list(consume(io.BytesIO(raw), Grouper('test', BOOT, 'capture', rule_window_ms=1)))
        evidence = b''.join((json.dumps(r, separators=(',', ':'), ensure_ascii=True) + '\n').encode() for r in rows)
        manifest = dict(source=rows[-1]['source'], summary=rows[-1], capture='capture',
                        audit_sha256=hashlib.sha256(raw).hexdigest(),
                        evidence_sha256=hashlib.sha256(evidence).hexdigest())
        def publish(value):
            (root / 'manifest.json').write_text(json.dumps(value))
        def rejected():
            try:
                verify_capture(root)
            except (ValueError, KeyError, TypeError):
                return
            raise AssertionError('inconsistent capture accepted')
        (root / 'audit.jsonl').write_bytes(raw)
        (root / 'evidence.jsonl').write_bytes(evidence)
        publish(manifest)
        result = verify_capture(root, [0, 1, 1])
        assert result['reproduced'] and not result['authenticity_verified']
        assert [r['rule_matches'] for r in result['windows']] == [0, 1]
        (root / 'audit.jsonl').write_bytes(raw + b'\n')
        rejected()
        (root / 'audit.jsonl').write_bytes(raw)
        (root / 'evidence.jsonl').write_bytes(evidence + b'\n')
        rejected()
        (root / 'evidence.jsonl').write_bytes(evidence)
        changed = json.loads(json.dumps(manifest))
        changed['summary']['rule_matches'] = 99
        publish(changed)
        rejected()
        changed = dict(manifest, capture='different')
        publish(changed)
        rejected()
        # Even self-consistent hashes cannot disguise outputs not produced by this implementation.
        (root / 'evidence.jsonl').write_bytes(b'{}\n')
        publish(dict(manifest, evidence_sha256=hashlib.sha256(b'{}\n').hexdigest()))
        rejected()
        (root / 'evidence.jsonl').write_bytes(evidence)
        publish(manifest)
        tool = Path(__file__).resolve().parents[1] / 'tools/replay_capture.py'
        result = subprocess.run([sys.executable, '-B', str(tool), str(root), '--window-ms', '0', '1'],
                                capture_output=True, text=True, check=True)
        assert json.loads(result.stdout)['reproduced']
        (root / 'audit.jsonl').write_bytes(b'corrupt\n')
        result = subprocess.run([sys.executable, '-B', str(tool), str(root)], capture_output=True, text=True)
        assert result.returncode == 1 and not result.stdout and 'SHA-256' in result.stderr
    print('PASS capture integrity, source context, exact replay, window comparison and failure exit')


if __name__ == '__main__':
    main()
