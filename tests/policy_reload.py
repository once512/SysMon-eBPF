#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Root-only transactional policy reload and lifetime regression."""
import argparse
import errno
import os
from pathlib import Path
import subprocess
import tempfile
import sys
import threading
from monitor_harness import MonitorRun


def writable(path):
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CLOEXEC)
    except OSError as error:
        assert error.errno == errno.EACCES, error
        return False
    os.close(fd)
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', default='build')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('requires root/BPF permissions')
    binary = Path(args.build_dir).resolve() / 'secmon'
    with tempfile.TemporaryDirectory(prefix='secmon-reload-') as tmp:
        directory = Path(tmp)
        os.chmod(directory, 0o700)
        a, b, anchor = [directory / name for name in ('a with spaces', 'b', 'anchor')]
        for path in (a, b, anchor):
            path.write_bytes(b'original')
        config, sock = directory / 'policy', directory / 'control'

        def publish(revision, paths):
            staging = directory / 'staging'
            staging.write_text('version 1\nrevision ' + str(revision) + '\n' +
                               ''.join(f'protect "{path}"\n' for path in paths))
            os.chmod(staging, 0o600)
            staging.replace(config)

        def command(name, success=True, **kwargs):
            result = subprocess.run([str(binary), name, str(sock)], capture_output=True,
                                    text=True, timeout=5, **kwargs)
            assert (result.returncode == 0) == success, (result.returncode, result.stderr)

        publish(1, [a, anchor])
        with open(anchor, 'r+b', buffering=0) as existing, MonitorRun(
                binary, ['--policy', str(config), '--self-protect', str(sock)], seconds=120) as monitor:
            failures = []
            done = threading.Event()
            try:
                assert not writable(a) and writable(b) and not writable(anchor)
                try:
                    os.pwrite(existing.fileno(), b'X', 0)
                except OSError as error:
                    assert error.errno == errno.EACCES
                else:
                    raise AssertionError('protected pre-opened FD accepted write')
                base_fds = len(list(Path(f'/proc/{monitor.process.pid}/fd').iterdir()))
                # Root-only control directory rejects an unprivileged caller.
                refused = subprocess.run([sys.executable, '-c',
                    'import socket,sys; s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET); '
                    's.connect(sys.argv[1])', str(sock)], capture_output=True, text=True,
                    user=65534, group=65534, extra_groups=[], timeout=5)
                assert refused.returncode != 0 and 'PermissionError' in refused.stderr
                publish(2, [b, anchor])
                command('--reload')
                assert writable(a) and not writable(b)
                # Same/older versions, invalid file, and partially prepared candidates preserve revision 2.
                for revision, paths in ((2, [a]), (1, []), (3, [a, directory / 'missing']),
                                        (3, [a, directory]), (3, [a, directory / 'link'])):
                    link = directory / 'link'
                    if not link.exists():
                        link.symlink_to(a)
                    publish(revision, paths)
                    command('--reload', False)
                    assert writable(a) and not writable(b) and not writable(anchor)
                    assert len(list(Path(f'/proc/{monitor.process.pid}/fd').iterdir())) == base_fds
                publish(3, [a])
                os.chmod(config, 0o666)
                command('--reload', False)
                assert not writable(b)
                # Final-component config symlinks are rejected.
                config.rename(directory / 'real-policy')
                config.symlink_to(directory / 'real-policy')
                command('--reload', False)
                config.unlink()
                os.mkfifo(config, 0o600)
                command('--reload', False)
                config.unlink()

                def probe_anchor():
                    while not done.is_set():
                        try:
                            if writable(anchor):
                                failures.append('anchor writable during swap')
                                return
                        except BaseException as error:
                            failures.append(repr(error))
                            return
                        done.wait(0.002)
                thread = threading.Thread(target=probe_anchor)
                thread.start()
                try:
                    for revision in range(3, 23):
                        chosen = a if revision % 2 else b
                        publish(revision, [chosen, anchor])
                        command('--reload')
                        assert not writable(chosen)
                        assert writable(b if chosen == a else a)
                        assert len(list(Path(f'/proc/{monitor.process.pid}/fd').iterdir())) == base_fds
                finally:
                    done.set()
                    thread.join(timeout=5)
                assert not failures, failures
                publish(23, [])
                command('--reload')
                assert all(writable(path) for path in (a, b, anchor))
                assert len(list(Path(f'/proc/{monitor.process.pid}/fd').iterdir())) == base_fds - 2
                assert os.pwrite(existing.fileno(), b'X', 0) == 1
                # Exercise the actual kernel map at its full supported capacity.
                full = [directory / f'capacity-{i}' for i in range(256)]
                for path in full:
                    path.write_bytes(b'full')
                publish(24, full)
                command('--reload')
                assert all(not writable(path) for path in full)
                assert len(list(Path(f'/proc/{monitor.process.pid}/fd').iterdir())) == base_fds + 254
                publish(25, [])
                command('--reload')
                assert all(writable(path) for path in full)
                assert len(list(Path(f'/proc/{monitor.process.pid}/fd').iterdir())) == base_fds - 2
                print('PASS atomic policy replacement, rejection rollback, revisions, 256-file capacity and FD ownership')
            finally:
                command('--stop')
                monitor.process.wait(timeout=5)
            assert 'Policy active revision=25' in monitor.diagnostics()
        assert all(writable(path) for path in (a, b, anchor))
        print('PASS self-protected root control reload/stop and cleanup')


if __name__ == '__main__':
    main()
