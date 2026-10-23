#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""CLI rejection must not mount or cover existing data."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    args = parser.parse_args()
    binary = str(args.binary.resolve())
    assert subprocess.run([binary, '--help'], capture_output=True).returncode == 0
    with tempfile.TemporaryDirectory(prefix='secmon-decoy-cli-') as tmp:
        root = Path(tmp)
        empty = root / 'empty'; empty.mkdir()
        nonempty = root / 'nonempty'; nonempty.mkdir(); (nonempty / 'saved').write_bytes(b'keep')
        alias = root / 'alias'; alias.symlink_to(empty)
        unsafe = root / 'unsafe'; unsafe.mkdir(); unsafe.chmod(0o777)
        base = ['--mountpoint', str(empty), '--file', 'trap']
        invalid = [[], ['--help', 'extra'], base + ['--unknown'], base + ['--file', 'trap'],
                   base + ['--mountpoint', str(empty)], base + ['--allow-other', '--allow-other']]
        for name in ('', '.', '..', '../trap', 'a/b', 'a\nb', 'a b', 'a' * 256):
            invalid.append(['--mountpoint', str(empty), '--file', name])
        for path in ('relative', '/', str(alias), str(unsafe), str(nonempty), str(root / 'missing'), str(empty) + '/'):
            invalid.append(['--mountpoint', path, '--file', 'trap'])
        invalid.append(['--mountpoint', str(empty)] + sum((['--file', f'trap{i}'] for i in range(65)), []))
        for command in invalid:
            result = subprocess.run([binary, *command], capture_output=True, timeout=5)
            assert result.returncode == 2, (command, result.returncode, result.stderr)
            assert (nonempty / 'saved').read_bytes() == b'keep'
            assert not os.path.ismount(empty)
    print('PASS decoy CLI invalid namespace, capacity and unsafe mountpoints')


if __name__ == '__main__':
    main()
