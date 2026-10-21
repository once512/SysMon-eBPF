#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Session draft CLI: canonical fields, absolute clock bounds and rejection without output."""
import argparse
from pathlib import Path
import shlex
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    args = parser.parse_args()
    base = ['--id', '17', '--program', '/a program/quote"and\\slash', '--uid', '1000',
            '--target', '/a target/quote"and\\slash', '--mode', 'read', '--duration-ms', '1000']
    expected_boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    offset = 0
    for line in Path('/proc/self/timens_offsets').read_text().splitlines():
        name, seconds, nanos = line.split()
        if name == 'boottime':
            offset = int(seconds) * 10**9 + int(nanos)
    before = time.clock_gettime_ns(time.CLOCK_BOOTTIME) - offset
    result = subprocess.run([str(args.binary), *base], capture_output=True, text=True, timeout=5)
    after = time.clock_gettime_ns(time.CLOCK_BOOTTIME) - offset
    assert result.returncode == 0, result.stderr
    assert len(result.stdout.splitlines()) == 1
    fields = shlex.split(result.stdout)
    assert fields[:8] == ['vault-session', '17', base[3], '1000', base[7], 'read', '1000', expected_boot]
    assert before <= int(fields[8]) <= after
    for flag, values in (
        ('--id', ['0', '-1', '+1', '18446744073709551616']),
        ('--uid', ['-1', '4294967295', '4294967296', '1x']),
        ('--duration-ms', ['0', '99', '3600001', '+100', '100x']),
        ('--mode', ['write', 'all', 'read\nrevision 2']),
        ('--program', ['relative', '/line\nbreak', '/' + 'a' * 4095]),
        ('--target', ['relative', '/line\nbreak']),
    ):
        for value in values:
            command = list(base)
            command[command.index(flag) + 1] = value
            result = subprocess.run([str(args.binary), *command], capture_output=True, text=True, timeout=5)
            assert result.returncode == 2 and not result.stdout, (flag, value, result)
    for command in ([], base[:-1], base + ['--id', '18'], base + ['--unknown', 'x'], base[2:]):
        result = subprocess.run([str(args.binary), *command], capture_output=True, text=True, timeout=5)
        assert result.returncode == 2 and not result.stdout
    print('PASS canonical session draft, boot/time coordinate, quoting and strict invalid option rejection')


if __name__ == '__main__':
    main()
