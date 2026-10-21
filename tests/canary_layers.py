#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Backups stay harmless; BPF response dominates grants while fanotify holds an open."""
import argparse
from contextlib import ExitStack
import errno
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import shlex
import time
from canary_response import ResponseProcess
from management_harness import call
from monitor_harness import MonitorRun


def experiment(build, vault=False):
    with tempfile.TemporaryDirectory(prefix='secmon-canary-layers-') as tmp, ExitStack() as stack:
        root = Path(tmp)
        program = root / 'client'
        shutil.copyfile(build / 'secmon-response-scenario', program)
        program.chmod(0o755)
        trap, victim, policy = [root / name for name in ('trap', 'victim', 'policy')]
        original = b'original' + b'\0' * 8192
        for path in (trap, victim):
            path.write_bytes(original)
        actor = stack.enter_context(ResponseProcess(program, trap, victim))
        outsider = stack.enter_context(ResponseProcess(program, trap, victim))
        management = root / 'management'
        management.mkdir(mode=0o700)
        control = management / 'control'
        issued = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        def publish(revision, epoch):
            text = f'revision {revision}\ncanary "{trap}"\ncanary-response {epoch} 10000\n'
            if vault:
                text += f'vault "{victim}"\nvault-session 1 "{program}" 0 "{victim}" read-write 30000 {boot} {issued}\n'
            else:
                text += f'protect "{victim}"\nallow-writer "{program}" 0 "{victim}" all\n'
            if not vault: text += f'fanotify-file "{victim}"\nfanotify-decision allow\nfanotify-delay-ms 1500\nfanotify-timeout-ms 3000\n'
            stage = root / 'stage'
            stage.write_text(text); stage.chmod(0o600); stage.replace(policy)
        publish(1, 1)
        # MonitorRun prepends bpf-only. A wrapper selects the actual combined entrypoint.
        wrapper = root / 'service-wrapper'
        wrapper.write_text('#!/bin/sh\nshift\nexec ' + shlex.quote(str(build / 'secmon')) + ' "$@"\n')
        wrapper.chmod(0o700)
        monitor = stack.enter_context(MonitorRun(build / 'secmon' if vault else wrapper,
            ['--policy', str(policy), '--control', str(control)] +
            ([] if vault else ['--audit-permissions', '--requester-pidfd'])))
        def cleanup():
            if monitor.process.poll() is None:
                call(build / 'secmon', 'stop', control)
                monitor.process.wait(timeout=5)
        stack.callback(cleanup)
        # Ordinary reading/indexing/backup does not qualify as a canary violation.
        subprocess.run(['sha256sum', str(trap)], capture_output=True, check=True, timeout=5)
        backup = root / 'copy'
        subprocess.run(['cp', str(trap), str(backup)], capture_output=True, check=True, timeout=5)
        subprocess.run(['tar', '-cf', str(root / 'archive.tar'), '-C', str(root), 'trap'],
                       capture_output=True, check=True, timeout=5)
        assert backup.read_bytes() == original
        assert call(build / 'secmon', 'status', control)['response_started'] == 0
        assert actor.request('w') == outsider.request('w') == 0
        if not vault:
            assert actor.request('g') == 0
            until = time.monotonic() + 2
            while True:
                state = call(build / 'secmon', 'status', control)
                if state['pending'] == 1:
                    break
                assert time.monotonic() < until, state
        assert actor.request('c') == errno.EACCES
        assert actor.request('w') == errno.EACCES
        if not vault:
            assert actor.request('v') == 0  # Already-checked open is not retroactively cancelled.
        assert actor.request('W') == errno.EACCES
        assert actor.request('h') == 0
        assert outsider.request('w') == 0
        state = call(build / 'secmon', 'status', control)
        assert state['response_started'] == 1 and state['response_failed'] == 0
        if not vault:
            assert state['allowed'] == 1 and state['denied'] == 0 and state['pending'] == 0, state
        publish(2, 2)
        call(build / 'secmon', 'reload', control)
        assert actor.request('w') == actor.request('W') == 0
        cleanup()
        events = monitor.events()
        permissions = [event for event in events if event['event'] == 'fanotify_decision']
        assert len(permissions) == (0 if vault else 1)
        if not vault: assert permissions[0]['decision'] == 'allow'
        hits = [event for event in events if event.get('response_started')]
        assert len(hits) == 1
        if not vault: assert hits[0]['process_inode'] == permissions[0]['requester_process_inode']
        assert 'audit_invalid=0' in monitor.diagnostics()
        print(json.dumps({'vault': vault, 'normal_backup': True, 'response_overrides_grant': True,
                          'pending_open_allowed': not vault, 'later_write_denied': True}))



def vault_conflict(build):
    with tempfile.TemporaryDirectory(prefix='secmon-vault-fan-conflict-') as tmp, ExitStack() as stack:
        root = Path(tmp)
        first, second, alias, policy = [root / name for name in ('first', 'second', 'alias', 'policy')]
        first.write_bytes(b'data'); second.write_bytes(b'data'); os.link(first, alias)
        management = root / 'management'; management.mkdir(mode=0o700)
        control = management / 'control'
        def publish(revision, vault=None, fan=alias):
            text = f'revision {revision}\nfanotify-file "{fan}"\nfanotify-decision allow\n'
            if vault: text += f'vault "{vault}"\n'
            stage = root / 'stage'; stage.write_text(text); stage.chmod(0o600); stage.replace(policy)
        publish(1, vault=first)
        failed = subprocess.run([str(build / 'secmon'), '--policy', str(policy), '--run-for', '1'],
                                capture_output=True, text=True, timeout=5)
        assert failed.returncode and 'Vault inode cannot be a fanotify target' in failed.stderr
        publish(1)
        wrapper = root / 'service-wrapper'
        wrapper.write_text('#!/bin/sh\nshift\nexec ' + shlex.quote(str(build / 'secmon')) + ' "$@"\n')
        wrapper.chmod(0o700)
        monitor = stack.enter_context(MonitorRun(wrapper, ['--policy', str(policy), '--control', str(control)]))
        def cleanup():
            if monitor.process.poll() is None:
                call(build / 'secmon', 'stop', control); monitor.process.wait(timeout=5)
        stack.callback(cleanup)
        for revision, vault, fan in ((2, first, alias), (3, second, second)):
            publish(revision, vault, fan)
            reply = call(build / 'secmon', 'reload', control, 'prepare_failed')
            assert reply['revision'] == 1 and reply['vault_paths'] == 0 and reply['fanotify_targets'] == 1
            assert first.read_bytes() == b'data' and second.read_bytes() == b'data'
        cleanup()
    print('PASS vault/fanotify inode conflict rejected at startup, alias reload and new-target handover; old state retained')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, default=Path('build'))
    args = parser.parse_args()
    assert os.geteuid() == 0 and __debug__
    for vault in (False, True):
        experiment(args.build_dir.resolve(), vault)
    vault_conflict(args.build_dir.resolve())
    print('PASS canary reads/backups, writer/vault precedence, fanotify waiting, shared process identity and subsequent write denial')


if __name__ == '__main__':
    main()
