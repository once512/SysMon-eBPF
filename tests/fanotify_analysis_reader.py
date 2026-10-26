#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Direct reader-to-scanner FD relay survives blocked FUSE read and close paths."""
import argparse
from contextlib import ExitStack
import errno
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
from decoy_harness import DecoyView
from management_harness import call
from permission_audit import AuditedService, contents
from virtual_decoy import DecoyActor


def wait_for(predicate, seconds=2):
    until = time.monotonic() + seconds
    while True:
        result = predicate()
        if result:
            return result
        assert time.monotonic() < until, 'condition timed out'
        time.sleep(.01)


def main_has_no_event_file(pid, target):
    # Pinned O_PATH targets are expected. A readable FUSE file in the main
    # process would reintroduce a potentially blocking close on verdict/exit.
    for entry in Path(f'/proc/{pid}/fd').iterdir():
        try:
            if os.readlink(entry) != str(target):
                continue
            flags = next(line.split()[1] for line in Path(f'/proc/{pid}/fdinfo/{entry.name}').read_text().splitlines()
                         if line.startswith('flags:'))
            assert int(flags, 8) & os.O_PATH, (entry, flags)
        except FileNotFoundError:
            pass


class ReaderService(AuditedService):
    def events(self):
        assert self.process.poll() is not None
        return [json.loads(line) for line in contents(self.output).splitlines()]


def experiment(build, pidfd, blocked_at, combined):
    with tempfile.TemporaryDirectory(prefix='secmon-analysis-reader-') as tmp, ExitStack() as stack:
        root = Path(tmp); mountpoint = root / 'view'; mountpoint.mkdir()
        provider = stack.enter_context(DecoyView(build / 'secmon-decoyfs', mountpoint, allow_other=True))
        trap, victim = mountpoint / 'accounts.csv', root / 'victim'
        victim.write_bytes(b'original' + b'\0' * 8192)
        actor = stack.enter_context(DecoyActor(build / 'secmon-virtual-decoy-scenario', trap, victim))
        analyzer = build / ('secmon-analysis-fault-worker' if blocked_at == 'reply' else 'secmon-analyzer')
        marker = 'fuse-reply-fds' if blocked_at == 'reply' else 'SECMON_BLOCK'
        fields = (f'fanotify-file "{victim}"\nfanotify-event access\n'
                  f'fanotify-analyzer "{analyzer}"\nfanotify-marker "{marker}"\n'
                  'fanotify-timeout-ms 700\nfanotify-timeout-decision deny\n')
        if combined:
            fields += f'canary "{trap}"\ncanary-response 1 30000\n'
        monitor = ReaderService(build, root, trap, fields, combined, pidfd)
        stack.callback(monitor.close)
        control = monitor.control
        paused = False; local = None; worker = None
        def cleanup():
            if paused:
                os.kill(provider.process.pid, signal.SIGCONT)
            if worker is not None:
                try: os.kill(worker, signal.SIGCONT)
                except ProcessLookupError: pass
            if monitor.process.poll() is None:
                call(build / 'secmon', 'stop', control); monitor.process.wait(timeout=5)
            if local is not None and local.poll() is None:
                local.kill(); local.wait(timeout=5)
        stack.callback(cleanup)
        assert actor.request('r') == 0
        state = call(build / 'secmon', 'status', control)
        assert state['allowed'] == 1 and state['analyzer_online'], state
        worker = state['analyzer_pid']
        os.kill(worker, signal.SIGSTOP)
        wait_for(lambda: 'State:\tT' in Path(f'/proc/{worker}/status').read_text())
        if blocked_at == 'reader':
            local = subprocess.Popen(['cat', str(victim)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            wait_for(lambda: call(build / 'secmon', 'status', control)['pending'] == 1)
            os.kill(provider.process.pid, signal.SIGSTOP); paused = True
            actor.process.stdin.write('r\n'); actor.process.stdin.flush()
        else:
            actor.process.stdin.write('r\n'); actor.process.stdin.flush()
            wait_for(lambda: call(build / 'secmon', 'status', control)['pending'] == 1)
            # The event exists and its file is owned by the reader/scanner, not
            # by the main process. Pause FUSE before resuming the real scanner;
            # its fresh fstat (and eventual file cleanup) must remain isolated.
            if not combined: main_has_no_event_file(monitor.process.pid, trap)
            os.kill(provider.process.pid, signal.SIGSTOP); paused = True
            os.kill(worker, signal.SIGCONT)
        time.sleep(.08)
        begin = time.monotonic(); state = call(build / 'secmon', 'status', control)
        status_ms = (time.monotonic() - begin) * 1000
        assert status_ms < 500 and state['pending'] == (0 if blocked_at == 'reply' else 1), state
        wait_for(lambda: call(build / 'secmon', 'status', control)['pending'] == 0)
        state = call(build / 'secmon', 'status', control)
        assert state['denied'] == 1 and state['analyzer_failures'] == 1 and not state['analyzer_online'], state
        if not combined: main_has_no_event_file(monitor.process.pid, trap)
        if local is not None:
            output, error = local.communicate(timeout=2)
            assert local.returncode != 0 and output == b'', (output, error)
        begin = time.monotonic(); call(build / 'secmon', 'stop', control)
        stop_ms = (time.monotonic() - begin) * 1000
        assert stop_ms < 500
        monitor.process.wait(timeout=5); assert monitor.process.returncode == 0
        os.kill(provider.process.pid, signal.SIGCONT); paused = False
        result = int(actor.read())
        assert result in ((0, errno.EPERM, errno.EINTR) if blocked_at == 'reader' else (errno.EPERM,)), result
        permissions = [e for e in monitor.events() if e['event'] == 'fanotify_decision']
        assert len(permissions) == 2 and [e['reason'] for e in permissions] == ['analysis', 'analyzer_error' if blocked_at == 'reply' else 'timeout'], permissions
        expected_pid = local.pid if local is not None else actor.process.pid
        assert permissions[1]['requester_pid'] == expected_pid
        if pidfd:
            assert all(e['requester_process_inode'] > 0 for e in permissions)
        print(json.dumps({'pidfd': pidfd, 'combined': combined, 'blocked_at': blocked_at, 'status_ms': round(status_ms, 2),
                          'stop_ms': round(stop_ms, 2), 'fallback': 'analyzer_error' if blocked_at == 'reply' else 'timeout', 'main_owns_no_event_file': True if not combined else 'self-protection prevents inspection',
                          'unpublished_read_errno': result if blocked_at == 'reader' else None}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, default=Path('build'))
    args = parser.parse_args()
    if os.geteuid() != 0 or not __debug__: parser.error('run as root without Python optimization')
    for combined in (False, True):
        for pidfd in (False, True):
            for blocked_at in ('reader', 'scanner', 'reply'):
                experiment(args.build_dir.resolve(), pidfd, blocked_at, combined)
    print('PASS analysis reader/scanner FUSE isolation, deadlines, file ownership and bounded stop')


if __name__ == '__main__': main()
