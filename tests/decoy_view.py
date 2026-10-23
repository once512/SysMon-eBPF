#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actual unprivileged FUSE view, immutable bytes and failure lifecycle."""
import argparse
import errno
import hashlib
import json
import mmap
import os
from pathlib import Path
import subprocess
import tempfile
from decoy_harness import DecoyView, mounted


def rejected(action, expected=(errno.EACCES,)):
    try:
        action()
    except OSError as error:
        assert error.errno in expected, (error.errno, expected)
    else:
        raise AssertionError('unexpected modification success')


def experiment(build, count, long_names=False):
    with tempfile.TemporaryDirectory(prefix='secmon-decoy-view-') as tmp:
        root = Path(tmp)
        mountpoint = root / 'view'; mountpoint.mkdir()
        names = tuple((f'{i:02d}-' + 'x' * 248 + '.txt') if long_names else f'file-{i:02d}.txt' for i in range(count))
        with DecoyView(build / 'secmon-decoyfs', mountpoint, names) as view:
            assert sorted(os.listdir(mountpoint)) == list(names)
            stats, hashes = [], []
            # Reverse lookup independently of directory order; actual st_ino
            # remains the declared inode, including after repeated lookups.
            for name in reversed(names):
                path = mountpoint / name
                data = path.read_bytes()
                seed = f'SecMon synthetic decoy: {name}\n'.encode()
                expected = (seed * (4096 // len(seed) + 1))[:4096]
                assert data == expected and path.stat().st_size == 4096
                assert path.stat().st_ino == names.index(name) + 2
                rejected(lambda: os.getxattr(path, 'user.missing'), (errno.ENODATA,))
                os.listxattr(path)  # SELinux may add a synthesized label.
                with path.open('rb') as source:
                    with mmap.mmap(source.fileno(), 4096, access=mmap.ACCESS_READ) as mapped:
                        assert mapped[:] == expected
                    assert os.pread(source.fileno(), 50, 4000) == expected[4000:4050]
                    assert os.pread(source.fileno(), 50, 4096) == b''
                    rejected(lambda: mmap.mmap(source.fileno(), 4096, access=mmap.ACCESS_WRITE))
                stats.append((path.stat().st_dev, path.stat().st_ino))
                hashes.append(hashlib.sha256(data).hexdigest())
            assert len(set(stats)) == count
            target = mountpoint / names[0]
            rejected(lambda: os.open(target, os.O_WRONLY))
            rejected(lambda: os.truncate(target, 0))
            rejected(lambda: os.chmod(target, 0o600))
            rejected(lambda: os.unlink(target))
            rejected(lambda: os.rename(target, mountpoint / 'renamed'))
            rejected(lambda: os.link(target, mountpoint / 'alias'))
            rejected(lambda: os.setxattr(target, 'user.test', b'bad'))
            rejected(lambda: os.open(mountpoint / 'new', os.O_CREAT | os.O_WRONLY, 0o600))
            rejected(lambda: os.mkdir(mountpoint / 'directory'))
            rejected(lambda: os.symlink('anything', mountpoint / 'symlink'))
            assert hashlib.sha256(target.read_bytes()).hexdigest() == hashes[-1]
            # Ordinary tools must read/query/backup the view without EIO.
            for command in (['ls', '-la', str(mountpoint)], ['sha256sum', str(target)],
                            ['cp', str(target), str(root / 'copy')],
                            ['tar', '-cf', str(root / 'backup.tar'), '-C', str(mountpoint), '.']):
                subprocess.run(command, check=True, capture_output=True, timeout=5)
            assert (root / 'copy').read_bytes() == target.read_bytes()
            # Cannot accidentally cover an already mounted view.
            denied = subprocess.run([str(build / 'secmon-decoyfs'), '--mountpoint', str(mountpoint), '--file', 'hidden'],
                                    capture_output=True, timeout=5)
            assert denied.returncode == 2
            if count == 1:
                # A dead provider yields a disconnected view, never backing data.
                view.process.kill(); view.process.wait(timeout=5)
                rejected(lambda: target.read_bytes(), (errno.ENOTCONN, errno.EIO))
        assert not mounted(mountpoint) and list(mountpoint.iterdir()) == []
        with DecoyView(build / 'secmon-decoyfs', mountpoint, names) as view:
            assert (mountpoint / names[0]).stat().st_ino == 2
            # External lazy unmount makes the foreground loop exit and leaves no
            # daemon or persistent file; old handles are not a new mount's inode.
            subprocess.run(['fusermount3', '-uz', str(mountpoint)], check=True, capture_output=True, timeout=5)
            view.process.wait(timeout=5)
            assert view.process.returncode == 0
        assert not mounted(mountpoint)
        print(json.dumps({'files': count, 'long_names': long_names, 'immutable': True, 'backups': True, 'cleanup': True}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, default=Path('build'))
    args = parser.parse_args()
    for count in (1, 64):
        experiment(args.build_dir.resolve(), count)
    experiment(args.build_dir.resolve(), 64, long_names=True)
    print('PASS virtual FUSE view content, enumeration, metadata, mutations, crash and remount')


if __name__ == '__main__':
    main()
