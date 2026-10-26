#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Managed view readiness, progress, failure isolation and resource ownership."""
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
from decoy_harness import mounted
from management_harness import call
from permission_audit import contents
from virtual_decoy import DecoyActor
from writer_harness import WriterProcess


class ManagedRun:
    def __init__(self, build, root, combined=True, analysis=False, fault=None, invalid_policy=False, allow_other=True, capacity=False, ignore_sigchld=False):
        self.build, self.root = build, root
        self.view = root / 'view'; self.view.mkdir(mode=0o755)
        root.chmod(0o755)
        management = root / 'management'; management.mkdir(mode=0o700)
        self.control = management / 'control'; self.policy = root / 'policy'
        self.guard = root / 'guard'; self.guard.write_bytes(b'guarded')
        self.victim = root / 'victim'; self.victim.write_bytes(b'original' + b'\0' * 8192)
        self.trap = self.view / 'accounts.csv'
        fields = 'revision 1\n'
        if combined:
            fields += f'protect "{self.guard}"\n'
            if fault is None: fields += f'canary "{self.trap}"\ncanary-response 1 30000\n'
        if fault is None:
            fields += f'fanotify-file "{self.trap}"\nfanotify-event access\nfanotify-timeout-ms 700\n'
            fields += (f'fanotify-analyzer "{build / "secmon-analyzer"}"\nfanotify-marker "BLOCK"\n' if analysis
                       else 'fanotify-decision allow\n')
        if invalid_policy: fields += 'invalid-field value\n'
        self.policy.write_text(fields); self.policy.chmod(0o600)
        self.output, self.errors = tempfile.TemporaryFile(), tempfile.TemporaryFile()
        self.provider = build / ('secmon-decoyfs' if fault is None else 'secmon-decoy-fault-provider')
        args = [str(build / 'secmon'), '--policy', str(self.policy), '--control', str(self.control),
                '--decoy-provider', str(self.provider), '--decoy-mount', str(self.view),
                '--decoy-file', fault or 'accounts.csv', '--run-for', '30']
        if fault is None:
            args += ['--decoy-file', 'notes.txt', '--audit-permissions', '--requester-pidfd']
            if capacity:
                for i in range(62): args += ['--decoy-file', f'extra-{i}']
            if allow_other: args.append('--decoy-allow-other')
        self.file_count = 64 if capacity else 2 if fault is None else 1
        if not combined: args.append('--fanotify-only')
        self.started = time.monotonic()
        self.ignore_sigchld = ignore_sigchld
        self.process = subprocess.Popen(args, stdout=self.output, stderr=self.errors,
            preexec_fn=(lambda: signal.signal(signal.SIGCHLD, signal.SIG_IGN)) if ignore_sigchld else None)
        self.provider_pid = None

    def ready(self):
        until = time.monotonic() + 6
        while 'Service active;' not in contents(self.errors):
            assert self.process.poll() is None and time.monotonic() < until, contents(self.errors)
            time.sleep(.01)
        state = self.status(); self.provider_pid = state['decoy_provider_pid']
        if self.ignore_sigchld:
            ignored = next(line.split()[1] for line in Path(f'/proc/{self.process.pid}/status').read_text().splitlines()
                           if line.startswith('SigIgn:'))
            assert not int(ignored, 16) & (1 << (signal.SIGCHLD - 1)), ignored
        assert self.provider_pid > 0 and state['decoy_files'] == self.file_count, state
        return state

    def check(self, code='ok'):
        result = subprocess.run([str(self.build / 'secmon-policyctl'), '--socket', str(self.control),
                                 '--expect-revision', '1', '--require-ready', '--require-decoy'],
                                capture_output=True, text=True, timeout=3)
        assert result.returncode == (0 if code == 'ok' else 1), result
        reply = json.loads(result.stdout)
        assert reply['code'] == code and reply['status']['revision'] == 1, reply
        return reply['status']

    def status(self): return call(self.build / 'secmon', 'status', self.control)

    def wait_state(self, state):
        until = time.monotonic() + 4
        while True:
            reply = self.status()
            if reply['decoy_provider_state'] == state: return reply
            assert self.process.poll() is None and time.monotonic() < until, reply
            time.sleep(.02)

    def stop(self):
        begin = time.monotonic()
        if self.process.poll() is None:
            call(self.build / 'secmon', 'stop', self.control)
            self.process.wait(timeout=8)
        assert self.process.returncode == 0, contents(self.errors)
        return time.monotonic() - begin

    def close(self):
        try:
            if self.provider_pid is not None:
                try: os.kill(self.provider_pid, signal.SIGCONT)
                except (ProcessLookupError, PermissionError): pass
            if self.process.poll() is None: self.stop()
            # Abnormal provider death can leave a disconnected mount. The test
            # owns this unique temporary location; production never lazy-detaches
            # an unknown/replaced mount automatically.
            if mounted(self.view):
                subprocess.run(['fusermount3', '-uz', str(self.view)], check=True, capture_output=True, timeout=4)
        finally:
            self.output.close(); self.errors.close()


def normal(build, analysis, allow_other, capacity=False):
    with tempfile.TemporaryDirectory(prefix='secmon-managed-') as tmp, ExitStack() as stack:
        service = ManagedRun(build, Path(tmp), analysis=analysis, allow_other=allow_other, capacity=capacity, ignore_sigchld=not analysis and not capacity); stack.callback(service.close)
        state = service.ready(); pid = state['decoy_provider_pid']
        assert state['decoy_provider_state'] == 'responsive' and state['revision'] == 1
        service.check()
        actor = stack.enter_context(DecoyActor(build / 'secmon-virtual-decoy-scenario', service.trap, service.victim))
        assert len(list(service.view.iterdir())) == service.file_count
        assert actor.request('r') == 0
        reader = subprocess.run(['setpriv', '--reuid=65534', '--regid=65534', '--clear-groups',
                                 'cat', str(service.trap)], capture_output=True, timeout=5)
        if allow_other: assert reader.returncode == 0 and len(reader.stdout) == 4096, reader.stderr
        else: assert reader.returncode != 0 and not reader.stdout
        assert actor.request('c') == errno.EACCES and actor.request('w') == errno.EACCES
        state = service.status(); assert state['response_started'] == 1 and state['allowed'] == (3 if allow_other else 1), state
        try: os.kill(pid, signal.SIGSTOP)
        except PermissionError as error: assert error.errno == errno.EPERM
        else:
            os.kill(pid, signal.SIGCONT); raise AssertionError('managed provider was not protected')
        time.sleep(2.1)
        state = service.status()
        assert state['decoy_provider_state'] == state['reader_state'] == 'responsive', state
        elapsed = service.stop()
        assert not mounted(service.view) and not Path(f'/proc/{pid}').exists()
        assert list(service.view.iterdir()) == []
        rows = [json.loads(line) for line in contents(service.output).splitlines()]
        assert any(e['event'] == 'self_denied' and e['target_pid'] == pid for e in rows)
        assert len([e for e in rows if e['event'] == 'fanotify_decision']) == state['allowed']
        print(json.dumps({'analysis': analysis, 'allow_other': allow_other, 'files': service.file_count, 'inherited_sigchld_ignored': service.ignore_sigchld, 'ready_before_policy': True, 'provider_protected': True,
                          'canary_response': True, 'idle_progress': True, 'stop_ms': round(elapsed*1000, 2), 'unmounted': True}))


def private_analysis(build):
    with tempfile.TemporaryDirectory(prefix='secmon-managed-private-') as tmp, ExitStack() as stack:
        service = ManagedRun(build, Path(tmp), analysis=True, allow_other=False); stack.callback(service.close)
        service.ready()
        actor = stack.enter_context(DecoyActor(build / 'secmon-virtual-decoy-scenario', service.trap, service.victim))
        assert actor.request('r') == errno.EPERM
        state = service.status()
        assert state['last_scan_error'] == 'metadata_failed' and state['last_scan_errno'] == errno.EACCES, state
        assert state['analyzer_error'] == 1 and state['analyzer_failures'] == 0 and state['analyzer_online'], state
        assert state['decoy_provider_state'] == 'responsive' and state['response_started'] == 0
        service.stop()
    print('PASS private view denies dropped scanner metadata access through the configured error fallback')


def paused(build, stop_paused):
    with tempfile.TemporaryDirectory(prefix='secmon-managed-pause-') as tmp, ExitStack() as stack:
        service = ManagedRun(build, Path(tmp), combined=False); stack.callback(service.close)
        state = service.ready(); pid = state['decoy_provider_pid']
        os.kill(pid, signal.SIGSTOP)
        state = service.wait_state('unresponsive')
        assert state['revision'] == 1 and state['decoy_provider_progress_age_ms'] >= 2000
        assert state['decoy_provider_error'] == 'none'
        service.check('decoy_provider_unresponsive')
        begin = time.monotonic(); service.status(); latency = time.monotonic() - begin
        assert latency < .5
        if stop_paused:
            elapsed = service.stop(); assert elapsed < 3
            until = time.monotonic() + 2
            while Path(f'/proc/{pid}').exists():
                assert time.monotonic() < until
                time.sleep(.01)
            print(json.dumps({'paused_stop_ms': round(elapsed*1000, 2), 'status_ms': round(latency*1000, 2),
                              'residual_mount_requires_cleanup': mounted(service.view)}))
        else:
            os.kill(pid, signal.SIGCONT)
            assert service.wait_state('responsive')['decoy_provider_pid'] == pid
            os.kill(pid, signal.SIGKILL)
            state = service.wait_state('offline')
            assert state['revision'] == 1 and state['decoy_provider_error'] == 'disconnected', state
            assert service.process.poll() is None
            service.check('decoy_provider_offline')
            service.stop()
            print('PASS managed provider pause/recovery and real death stay visible without implicit remount')


def startup_faults(build):
    for mode in ('no-ready', 'bad-ready', 'ready-fds', 'exit-before-ready'):
        with tempfile.TemporaryDirectory(prefix='secmon-managed-startup-') as tmp:
            service = ManagedRun(build, Path(tmp), fault=mode)
            try:
                service.process.wait(timeout=4)
                assert service.process.returncode == 1 and 'Service active;' not in contents(service.errors), contents(service.errors)
                assert time.monotonic() - service.started < 3.5 and not mounted(service.view)
            finally: service.close()
    # Successful FUSE startup followed by rejected policy must also unmount.
    with tempfile.TemporaryDirectory(prefix='secmon-managed-rollback-') as tmp:
        service = ManagedRun(build, Path(tmp), invalid_policy=True)
        try:
            service.process.wait(timeout=4)
            assert service.process.returncode == 1 and not mounted(service.view), contents(service.errors)
        finally: service.close()
    print('PASS startup timeout/protocol/FD/disconnect failures and real-view policy rollback')


def peer_failure(build):
    for mode, expected in (('exit-on-probe', 'disconnected'), ('wrong-progress', 'protocol'), ('progress-fds', 'protocol')):
        with tempfile.TemporaryDirectory(prefix='secmon-managed-peer-') as tmp, ExitStack() as stack:
            root = Path(tmp); guard = root / 'guard'; guard.write_bytes(b'guarded')
            writer = stack.enter_context(WriterProcess(build / 'secmon-writer-scenario', guard))
            service = ManagedRun(build, root, fault=mode); stack.callback(service.close)
            service.ready()
            state = service.wait_state('offline')
            assert state['decoy_provider_error'] == expected and state['revision'] == 1, state
            assert writer.request('w') == errno.EACCES
            assert service.status()['self_protected']
            service.check('decoy_provider_offline')
            service.stop()
    print('PASS injected provider protocol failures preserve the independent BPF file policy')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, default=Path('build'))
    args = parser.parse_args()
    if os.geteuid() != 0 or not __debug__: parser.error('run as root without Python optimization')
    build = args.build_dir.resolve()
    normal(build, False, False)
    normal(build, True, True)
    normal(build, False, True, capacity=True)
    private_analysis(build)
    paused(build, False); paused(build, True)
    startup_faults(build); peer_failure(build)
    print('PASS explicit managed virtual view lifecycle and bounded control progress')


if __name__ == '__main__': main()
