#!/usr/bin/env python3
# 共用配置的真实双后端回归：确认空闲更新、忙时保留旧规则、固定后端、错误回退和配置自阻塞防护。
# SPDX-License-Identifier: MIT
"""Shared configuration and non-disruptive fanotify policy reload."""
import argparse
from contextlib import contextmanager
import errno
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time
from fanotify_harness import open_errno, begin_open, finish_open, stop
from monitor_harness import MonitorRun


@contextmanager
def running(binary, config, control):
    with tempfile.TemporaryFile(mode='w+') as output, tempfile.TemporaryFile(mode='w+') as errors:
        process = subprocess.Popen([str(binary), '--policy', str(config), '--control', str(control),
                                    '--run-for', '60'], stdout=output, stderr=errors)
        try:
            deadline = time.monotonic() + 5
            while True:
                errors.seek(0)
                text = errors.read()
                if 'Fanotify active;' in text:
                    break
                assert process.poll() is None, text
                assert time.monotonic() < deadline, text
                time.sleep(0.01)
            yield process, output, errors
        finally:
            stop(process)
            errors.seek(0)
            assert process.returncode == 0, errors.read()
        output.seek(0)
        stats = json.load(output)
        assert stats['overflow'] == 0 and stats['shutdown_denied'] == 0, stats


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', default='build')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('requires root/fanotify/BPF permissions')
    build = Path(args.build_dir).resolve()
    binary = build / 'secmon-fanotify'
    with tempfile.TemporaryDirectory(prefix='secmon-unified-') as tmp:
        root = Path(tmp)
        os.chmod(root, 0o700)
        target, protected = root / 'target with spaces', root / 'protected'
        target.write_bytes(b'clean')
        protected.write_bytes(b'original')
        config, control = root / 'policy', root / 'gate.sock'

        def publish(revision, extra, file=target):
            stage = root / 'staging'
            stage.write_text(f'revision {revision}\nprotect "{protected}"\n'
                             f'fanotify-file "{file}"\n' + extra + '\n')
            os.chmod(stage, 0o600)
            stage.replace(config)

        def reload(success=True):
            result = subprocess.run([str(binary), '--reload', str(control)], capture_output=True,
                                    text=True, timeout=5)
            assert (result.returncode == 0) == success, result.stderr

        def protected_write():
            try:
                fd = os.open(protected, os.O_WRONLY)
            except OSError as error:
                assert error.errno == errno.EACCES
            else:
                os.close(fd)
                raise AssertionError('fanotify update removed BPF protection')

        publish(1, 'fanotify-decision allow')
        with MonitorRun(build / 'secmon', ['--policy', str(config)]):
            with running(binary, config, control) as (process, output, errors):
                base = len(list(Path(f'/proc/{process.pid}/fd').iterdir()))
                assert open_errno(target) == 0
                protected_write()
                publish(2, 'fanotify-decision deny')
                reload()
                assert open_errno(target) == errno.EPERM
                protected_write()
                reload(False)  # Same revision.
                for extra, file in [('fanotify-decision allow\nfanotify-event access', target),
                                    ('fanotify-decision allow', protected),
                                    (f'fanotify-analyzer "{build / "secmon-analyzer"}"\nfanotify-marker "BLOCK"', target)]:
                    publish(3, extra, file)
                    reload(False)
                    assert open_errno(target) == errno.EPERM
                    assert len(list(Path(f'/proc/{process.pid}/fd').iterdir())) == base
                # A config hard link to the marked inode must fail before an open/read permission event.
                config.unlink()
                os.link(target, config)
                reload(False)
                assert open_errno(target) == errno.EPERM
                assert len(list(Path(f'/proc/{process.pid}/fd').iterdir())) == base
                # Admit a delayed request, then reject an update while it is owned by the gate.
                publish(3, 'fanotify-decision allow\nfanotify-delay-ms 1500\nfanotify-timeout-ms 5000')
                reload()
                opener = begin_open(target)
                try:
                    deadline = time.monotonic() + 1
                    while len(list(Path(f'/proc/{process.pid}/fd').iterdir())) == base:
                        assert time.monotonic() < deadline
                        time.sleep(0.005)
                    publish(4, 'fanotify-decision deny')
                    reload(False)
                    assert finish_open(opener) == 0  # Original delayed allow survives the rejection.
                finally:
                    if opener.poll() is None:
                        opener.kill()
                        opener.wait(timeout=5)
                reload()  # Reuse the rejected revision after the old queue has drained.
                assert open_errno(target) == errno.EPERM
                for revision in range(5, 15):
                    allow = revision % 2 == 1
                    publish(revision, 'fanotify-decision ' + ('allow' if allow else 'deny'))
                    reload()
                    assert open_errno(target) == (0 if allow else errno.EPERM)
                    protected_write()
                    assert len(list(Path(f'/proc/{process.pid}/fd').iterdir())) == base
                command = subprocess.run([str(binary), '--stop', str(control)], capture_output=True, timeout=5)
                assert command.returncode == 0
                process.wait(timeout=5)
            assert not control.exists()
        print('PASS shared BPF/fanotify config, idle reload, busy rejection, immutable backend and FD stability')

        # Scanner configuration uses the same parser, including error fallback updates.
        analyzer = f'fanotify-analyzer "{build / "secmon-analyzer"}"\nfanotify-marker "BLOCK"\nfanotify-scan-limit-bytes 128'
        publish(20, analyzer)
        with running(binary, config, control) as (process, output, errors):
            assert open_errno(target) == 0
            target.write_bytes(b'BLOCK')  # Its write-open is scanned while contents are still clean.
            assert open_errno(target) == errno.EPERM
            errors.seek(0)
            worker = int(re.search(r'analyzer_pid=(\d+)', errors.read()).group(1))
            for changed in [analyzer.replace('"BLOCK"', '"OTHER"'),
                            analyzer.replace('128', '129'),
                            analyzer.replace(str(build / 'secmon-analyzer'), '/unused-worker')]:
                publish(21, changed)
                reload(False)
                assert open_errno(target) == errno.EPERM
                os.kill(worker, 0)
            os.kill(worker, signal.SIGKILL)
            assert open_errno(target) == errno.EPERM
            publish(21, analyzer + '\nfanotify-error-decision allow')
            reload()
            assert open_errno(target) == 0
            errors.seek(0)
            text = errors.read()
            assert 'Fanotify policy active revision=21' in text
        print('PASS configured scanner, marker deny, worker failure and live error-fallback update')
        publish(30, 'fanotify-decision deny', file=config)
        rejected = subprocess.run([str(binary), '--policy', str(config), '--run-for', '1'],
                                  capture_output=True, text=True, timeout=5)
        assert rejected.returncode == 1 and 'Fanotify active;' not in rejected.stderr, rejected.stderr
        assert 'cannot be the marked inode' in rejected.stderr
        print('PASS self-marked policy rejected before activation; hard-link reload cannot deadlock')


if __name__ == '__main__':
    main()
