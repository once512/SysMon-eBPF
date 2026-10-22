#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Held-FD xattr/ACL/ioctl policy, exact grants, canary and response coverage."""
import argparse
import array
import fcntl
from contextlib import ExitStack
import errno
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import time
from management_harness import call
from monitor_harness import MonitorRun
from writer_harness import WriterProcess

OPERATIONS = {'x': ('setxattr', 16), 'd': ('removexattr', 17), 'a': ('setacl', 18),
              'r': ('removeacl', 19), 'i': ('ioctl-write', 20), 's': ('ioctl-write', 20),
              'c': ('ioctl-write', 20), 'l': ('ioctl-write', 20)}
ACL = bytes.fromhex('0200000001000600ffffffff02000400feff000004000400ffffffff10000400ffffffff20000000ffffffff')

class MetadataProcess(WriterProcess):
    def __init__(self, binary, targets):
        self.lock = threading.Lock()
        self.process = subprocess.Popen([str(binary), *map(str, targets)], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        try:
            assert self.read() == 'ready'
        except BaseException:
            self.close()
            raise


def snapshot(path):
    # atime intentionally excluded; monitoring reads may update it.
    state = path.stat()
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        flags = array.array('l', [0])
        fcntl.ioctl(fd, 0x80086601, flags, True)
        attributes = bytearray(28)
        fcntl.ioctl(fd, 0x801c581f, attributes, True)
    finally:
        os.close(fd)
    return (hashlib.sha256(path.read_bytes()).hexdigest(), state.st_size, state.st_mode,
            state.st_mtime_ns, flags[0],
            # nextents (offset 8) reflects allocation/writeback; padding is not
            # a settable attribute. Compare only the fields FSSETXATTR changes.
            bytes(attributes[:8] + attributes[12:20]),
            tuple((name, os.getxattr(path, name)) for name in sorted(os.listxattr(path))))


def experiment(build):
    with tempfile.TemporaryDirectory(prefix='secmon-metadata-') as temporary, ExitStack() as stack:
        root = Path(temporary)
        program, outsider_program = root / 'client', root / 'outsider'
        for p in (program, outsider_program):
            shutil.copyfile(build / 'secmon-metadata-scenario', p); p.chmod(0o755)
        targets = [root / n for n in ('target', 'victim', 'donor')]
        for p in targets:
            p.write_bytes(b'A' * 8192)
            os.setxattr(p, 'user.secmon', b'original')
            os.setxattr(p, 'system.posix_acl_access', ACL)
        alias = root / 'alias'; os.link(targets[0], alias)
        actor = stack.enter_context(MetadataProcess(program, [alias, *targets[1:]]))
        outsider = stack.enter_context(MetadataProcess(outsider_program, targets))
        # Every claimed command must work on this filesystem before enforcement.
        for command in OPERATIONS:
            result = actor.request(command)
            assert result == 0, ('unsupported baseline', command, result)
            if command == 'd': assert actor.request('x') == 0
            if command == 'r': assert actor.request('a') == 0
        for command in 'vfbenpt':
            assert actor.request(command) == 0, ('alternate I/O baseline', command)
        targets[0].write_bytes(b'A' * 8192)
        for p in targets:
            os.setxattr(p, 'user.secmon', b'original')
            os.setxattr(p, 'system.posix_acl_access', ACL)
        policy, control = root / 'policy', root / 'control'
        revision = epoch = 0
        def publish(kind='protect', grant='', response=False, extra=''):
            nonlocal revision, epoch
            revision += 1
            rows = f'revision {revision}\n{kind} "{targets[0]}"\n'
            if grant:
                rows += f'allow-writer "{program}" 0 "{targets[0]}" {grant}\n'
            if response:
                epoch += 1; rows += f'canary-response {epoch} 10000\n'
            stage = root / 'stage'; stage.write_text(rows + extra); stage.chmod(0o600); stage.replace(policy)
        publish()
        monitor = stack.enter_context(MonitorRun(build / 'secmon', ['--policy', str(policy), '--control', str(control)]))
        def stop():
            if monitor.process.poll() is None:
                call(build / 'secmon', 'stop', control); monitor.process.wait(timeout=5)
        stack.callback(stop)
        def reload(**kwargs):
            publish(**kwargs); return call(build / 'secmon', 'reload', control)
        before = snapshot(targets[0])
        for command in [*OPERATIONS, *'vfbenpt']:
            assert actor.request(command) == errno.EACCES, ('protect', command)
        assert snapshot(targets[0]) == before
        assert actor.request('g') == actor.request('h') == 0
        assert actor.request('z') == errno.ENOTTY
        assert actor.request('u') == errno.EACCES
        # Legacy setattr grants do not gain metadata privileges.
        reload(grant='setattr')
        for command in OPERATIONS:
            assert actor.request(command) == errno.EACCES, ('legacy grant widened', command)
        # Each new grant is isolated from the other operation classes.
        for command, (name, _) in OPERATIONS.items():
            reload(grant=name)
            if command in ('c', 'l'):
                # Reflink also traverses the ordinary destination write hook.
                assert actor.request(command) == errno.EACCES
                reload(grant=name + ',write')
            result = actor.request(command)
            assert result == 0, ('scoped grant', command, name, result)
            assert outsider.request(command) == errno.EACCES, ('wrong executable', command)
            for other, (other_name, _) in OPERATIONS.items():
                if other_name != name:
                    assert actor.request(other) == errno.EACCES, ('grant leaked', name, other)
            # Restore removed values through a separately-authorized controller.
            if command in ('d', 'r'):
                reload(grant='all')
                assert actor.request('x' if command == 'd' else 'a') == 0
        reload(grant='setxattr', extra='writer-lease-ms 350\n')
        assert actor.request('x') == 0
        time.sleep(0.45)
        assert actor.request('x') == errno.EACCES
        assert actor.request('w1') == 0  # An expired grant is not a canary hit.
        reload(kind='vault')
        for command in OPERATIONS:
            assert actor.request(command) == errno.EACCES, ('vault', command)
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        issued = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        reload(kind='vault', extra=f'vault-session 1 "{program}" 0 "{targets[0]}" read-write 10000 {boot} {issued}\n')
        assert actor.request('w') == 0
        for command in OPERATIONS:
            assert actor.request(command) == errno.EACCES, ('session widened metadata', command)
        # Fresh epoch per operation proves the actual trigger, independent of
        # containment from an earlier operation.
        reload(kind='canary', response=True)
        assert actor.request('g') == actor.request('h') == 0
        assert actor.request('z') == errno.ENOTTY
        assert actor.request('u') == errno.EACCES
        assert call(build / 'secmon', 'status', control)['response_started'] == 0
        triggers = {**OPERATIONS, **{c: ('write', 2) for c in 'vfbenpt'}}
        for number, command in enumerate(triggers, 1):
            if number > 1: reload(kind='canary', response=True)
            before = snapshot(targets[0])
            assert actor.request(command) == errno.EACCES, ('canary', command)
            assert snapshot(targets[0]) == before
            state = call(build / 'secmon', 'status', control)
            assert state['response_started'] == number and not state['response_failed'], state
            for other in [*(c + '1' for c in OPERATIONS), *('w1', 'v1', 'f1', 'b1', 'n1', 'p1', 't1', 'g1', 'h1', 'u1', 'z1')]:
                assert actor.request(other) == errno.EACCES, ('response', command, other)
            assert outsider.request('w1') == 0
        stop(); monitor.stop(); events = monitor.events()
        starts = [e for e in events if e.get('canary_hit') and e['pid'] == actor.process.pid]
        assert len(starts) == len(triggers), starts
        assert [e['operation'] for e in starts] == [op for _, op in triggers.values()]
        for event in starts:
            assert bool(event['ioctl_command']) == (event['operation'] == 20), event
        assert all(not e.get('canary_hit') for e in events if e.get('operation') == 21)
        diagnostics = monitor.diagnostics()
        assert 'ringbuf_dropped=0' in diagnostics and 'baseline_update_failed=0' in diagnostics, diagnostics
        print(f'PASS held-FD xattrs/ACL/ioctl: {len(triggers)} independent triggers; scoped grants, vault and alternate I/O', flush=True)


def compat_experiment(build):
    with tempfile.TemporaryDirectory(prefix='secmon-compat-') as temporary, ExitStack() as stack:
        root = Path(temporary)
        program = root / 'client'
        shutil.copyfile(build / 'secmon-metadata-compat', program); program.chmod(0o755)
        trap, victim = root / 'trap', root / 'victim'
        for p in (trap, victim): p.write_bytes(b'A' * 8192)
        actor = stack.enter_context(MetadataProcess(program, [trap, victim]))
        for command in 'giwv': assert actor.request(command) == 0
        policy, control = root / 'policy', root / 'control'
        revision = 0
        def publish(kind='protect', grant='', epoch=0):
            nonlocal revision
            revision += 1
            rows = f'revision {revision}\n{kind} "{trap}"\n'
            if grant: rows += f'allow-writer "{program}" 0 "{trap}" {grant}\n'
            if epoch: rows += f'canary-response {epoch} 10000\n'
            stage = root / 'stage'; stage.write_text(rows); stage.chmod(0o600); stage.replace(policy)
        publish()
        monitor = stack.enter_context(MonitorRun(build / 'secmon', ['--policy', str(policy), '--control', str(control)]))
        def stop():
            if monitor.process.poll() is None:
                call(build / 'secmon', 'stop', control); monitor.process.wait(timeout=5)
        stack.callback(stop)
        def reload(**kwargs):
            publish(**kwargs); call(build / 'secmon', 'reload', control)
        assert actor.request('g') == actor.request('v') == 0
        for command in 'iwu': assert actor.request(command) == errno.EACCES
        reload(grant='setattr')
        assert actor.request('i') == errno.EACCES
        reload(grant='ioctl-write')
        assert actor.request('i') == 0
        assert actor.request('w') == errno.EACCES
        reload(kind='vault')
        assert actor.request('i') == errno.EACCES
        reload(kind='canary', epoch=1)
        assert actor.request('g') == 0
        assert actor.request('u') == errno.EACCES
        assert call(build / 'secmon', 'status', control)['response_started'] == 0
        assert actor.request('i') == errno.EACCES
        for command in 'gv': assert actor.request(command) == errno.EACCES
        assert call(build / 'secmon', 'status', control)['response_started'] == 1
        reload(kind='canary', epoch=2)
        assert actor.request('g') == actor.request('v') == 0
        stop(); monitor.stop()
        starts = [e for e in monitor.events() if e.get('canary_hit')]
        assert len(starts) == 1 and starts[0]['operation'] == 20, starts
        assert starts[0]['ioctl_command'] == 0x40046602, starts
        print('PASS actual i386 compat ioctl: existing FD, isolated grant, vault, canary trigger and release', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', default='build')
    args = parser.parse_args()
    assert os.geteuid() == 0
    experiment(Path(args.build_dir).resolve())
    compat_experiment(Path(args.build_dir).resolve())

if __name__ == '__main__': main()
