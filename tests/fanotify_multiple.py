#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fixed multi-target group startup, request snapshots and transactional reload."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import errno
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from management_harness import call
from permission_audit import AuditedService, begin_request, finish_request, request, contents
from writer_harness import WriterProcess
from fanotify_harness import GateRun, open_errno


def reject_start(build, root, paths, marker):
    policy = root / 'bad-policy'
    policy.write_text('revision 1\nfanotify-decision allow\n' + ''.join(f'fanotify-file "{p}"\n' for p in paths))
    policy.chmod(0o600)
    result = subprocess.run([str(build/'secmon'), '--fanotify-only', '--policy', str(policy), '--run-for', '1'],
                            capture_output=True, text=True, timeout=5)
    assert result.returncode != 0 and marker in result.stderr, (paths, result.stderr)
    # Failed construction must not leave an earlier mark blocking readers.
    for path in paths:
        if path.is_file() and not path.is_symlink():
            assert request(path)['errno'] == 0


def experiment(build, event, pidfd):
    with tempfile.TemporaryDirectory(prefix='secmon-multiple-') as temporary, ExitStack() as stack:
        root = Path(temporary)
        targets = [root/f'target-{i}' for i in range(3)]
        for target in targets:
            target.write_bytes(b'original')
        identities = {target.stat().st_ino: target.stat() for target in targets}
        # Keep the last marked file outside BPF modification protection so the
        # controller can hard-link/rename it for self-wait and mark-lifetime checks.
        writers = [stack.enter_context(WriterProcess(build/'secmon-writer-scenario', target)) for target in targets[:2]]
        fields = ''.join(f'protect "{target}"\n' for target in targets[:2])
        fields += ''.join(f'fanotify-file "{target}"\n' for target in targets[1:])
        fields += f'fanotify-event {event}\nfanotify-decision allow\n'
        service = AuditedService(build, root, targets[0], fields, combined=True, requester_pidfd=pidfd)
        stack.callback(service.close)
        assert service.initial['fanotify_targets'] == 3
        baseline = len(list(Path(f'/proc/{service.process.pid}/fd').iterdir()))

        def read_all(expected):
            with ThreadPoolExecutor(max_workers=3) as executor:
                rows = list(executor.map(lambda path: request(path, event), targets))
            assert [r['errno'] for r in rows] == [expected]*3, rows

        def unchanged(revision):
            assert service.status()['revision'] == revision
            assert all(writer.request('w') == errno.EACCES for writer in writers)
            assert len(list(Path(f'/proc/{service.process.pid}/fd').iterdir())) == baseline

        read_all(0)
        # Decision-only update retains all marks, switches every target together.
        deny_fields = fields.replace('decision allow', 'decision deny')
        service.publish(2, deny_fields)
        assert call(service.binary, 'reload', service.control)['revision'] == 2
        read_all(errno.EPERM)
        # Target-set changes cannot partially switch BPF or fanotify settings.
        service.publish(3, deny_fields.replace(f'fanotify-file "{targets[2]}"\n', '').replace('decision deny','decision allow').replace(f'protect "{targets[0]}"\n',''))
        assert call(service.binary, 'reload', service.control, 'restart_required')['revision'] == 2
        unchanged(2)
        read_all(errno.EPERM)
        # Valid fanotify settings + failed BPF preparation must preserve deny.
        service.publish(3, fields + f'protect "{root / "missing"}"\n')
        assert call(service.binary, 'reload', service.control, 'prepare_failed')['revision'] == 2
        unchanged(2)
        read_all(errno.EPERM)
        # Reload source hard-linked to a secondary/last mark must fail before
        # opening it for reading, and return promptly rather than self-waiting.
        service.policy.unlink()
        os.link(targets[-1], service.policy)
        assert call(service.binary, 'reload', service.control, 'invalid_policy')['revision'] == 2
        unchanged(2)
        read_all(errno.EPERM)
        service.publish(3, fields + 'fanotify-delay-ms 600\nfanotify-timeout-ms 2000\n')
        assert call(service.binary, 'reload', service.control)['revision'] == 3
        # Two targets pending simultaneously must retain their own snapshots.
        processes = [begin_request(target, event) for target in targets[:2]]
        try:
            service.wait_pending(2)
            service.publish(4, fields)
            assert call(service.binary, 'reload', service.control, 'busy')['revision'] == 3
            assert all(finish_request(p)['errno'] == 0 for p in processes)
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)
        assert call(service.binary, 'reload', service.control)['revision'] == 4
        read_all(0)
        # Rename keeps the inode mark; pathname replacement does not inherit it.
        renamed = root/'renamed'
        targets[-1].rename(renamed)
        targets[-1].write_bytes(b'unmarked replacement')
        service.publish(5, fields.replace('decision allow','decision deny'))
        assert call(service.binary, 'reload', service.control)['revision'] == 5
        assert request(renamed,event)['errno'] == errno.EPERM
        assert request(targets[-1],event)['errno'] == 0
        service.stop()
        records = [json.loads(line) for line in contents(service.output).splitlines()]
        permissions = [r for r in records if r['event']=='fanotify_decision']
        assert len(permissions) == 21, (len(permissions), permissions)
        assert sorted(r['request_id'] for r in permissions)==list(range(1,22))
        assert {r['inode'] for r in permissions}==set(identities)
        assert {r['inode'] for r in permissions if r['revision']==3}=={targets[i].stat().st_ino for i in (0,1)}
        for row in permissions:
            identity = identities[row['inode']]
            assert (row['major'],row['minor'])==(os.major(identity.st_dev),os.minor(identity.st_dev))
            assert row['instance_ns']==service.initial['instance_ns']
            assert row['decision']==('deny' if row['revision'] in (2,5) else 'allow')
            if pidfd:
                assert row['requester_reference']=='present' and row['requester_process_inode']>0
        diagnostics=contents(service.errors)
        for field in ('audit_dropped','audit_invalid','audit_queued','audit_errno','ringbuf_dropped'):
            values=re.findall(r'\b'+field+r'=(\d+)',diagnostics)
            assert values and int(values[-1])==0,(field,values)
        return dict(event=event,requester_pidfd=pidfd,permissions=len(permissions),passed=True)


def completion_reasons(build, event, mode):
    with tempfile.TemporaryDirectory(prefix='secmon-multiple-reasons-') as temporary, ExitStack() as stack:
        root=Path(temporary)
        targets=[root/'clean',root/'blocked']
        targets[0].write_bytes(b'clean content')
        targets[1].write_bytes(b'BLOCK content')
        fields=f'fanotify-file "{targets[1]}"\nfanotify-event {event}\n'
        if mode=='analysis':
            fields+=f'fanotify-analyzer "{build/"secmon-analyzer"}"\nfanotify-marker "BLOCK"\n'
        elif mode=='timeout':
            fields+='fanotify-decision allow\nfanotify-delay-ms 600\nfanotify-timeout-ms 150\n'
        else:
            fields+='fanotify-decision allow\nfanotify-delay-ms 3000\nfanotify-timeout-ms 5000\nfanotify-max-pending 1\n'
        service=AuditedService(build,root,targets[0],fields,requester_pidfd=True)
        stack.callback(service.close)
        processes=[]
        try:
            processes.append(begin_request(targets[0],event))
            if mode=='capacity-shutdown':
                service.wait_pending(1)
            processes.append(begin_request(targets[1],event))
            if mode=='capacity-shutdown':
                assert finish_request(processes[1])['errno']==errno.EPERM
                service.stop()
                assert finish_request(processes[0])['errno']==errno.EPERM
            else:
                results=[finish_request(p)['errno'] for p in processes]
                assert results==([0,errno.EPERM] if mode=='analysis' else [errno.EPERM]*2),results
                service.stop()
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)
        permissions=[json.loads(line) for line in contents(service.output).splitlines()]
        assert len(permissions)==2
        by_inode={row['inode']:row for row in permissions}
        assert set(by_inode)=={target.stat().st_ino for target in targets}
        expected_reasons=['analysis','analysis'] if mode=='analysis' else ['timeout','timeout'] if mode=='timeout' else ['shutdown','capacity']
        for target,reason in zip(targets,expected_reasons):
            row=by_inode[target.stat().st_ino]
            assert row['reason']==reason and row['revision']==1
            assert row['requester_reference']=='present' and row['requester_process_inode']>0
        print(json.dumps(dict(event=event,mode=mode,permissions=2,passed=True)),flush=True)


def exec_targets(build):
    with tempfile.TemporaryDirectory(prefix='secmon-multiple-exec-') as temporary, ExitStack() as stack:
        root=Path(temporary)
        targets=[root/'first',root/'second']
        for target in targets:
            shutil.copy2('/usr/bin/true',target)
        fields=f'fanotify-file "{targets[1]}"\nfanotify-event exec\nfanotify-decision deny\n'
        service=AuditedService(build,root,targets[0],fields,requester_pidfd=True)
        stack.callback(service.close)
        assert [request(target,'exec')['errno'] for target in targets]==[errno.EPERM]*2
        service.publish(2,fields.replace('decision deny','decision allow'))
        assert call(service.binary,'reload',service.control)['revision']==2
        assert [request(target,'exec')['errno'] for target in targets]==[0]*2
        service.stop()
        permissions=[json.loads(line) for line in contents(service.output).splitlines()]
        assert len(permissions)==4
        assert {row['inode'] for row in permissions}=={target.stat().st_ino for target in targets}
        assert all(row['permission_event']=='exec' and row['requester_process_inode']>0 for row in permissions)
        print(json.dumps(dict(event='exec',permissions=4,passed=True)),flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir',type=Path,default=Path('build'))
    args=parser.parse_args()
    if os.geteuid()!=0 or __debug__ is False:
        parser.error('run as root without Python optimization')
    build=args.build_dir.resolve()
    base=len(os.listdir('/proc/self/fd'))
    with tempfile.TemporaryDirectory(prefix='secmon-target-errors-') as temporary:
        root=Path(temporary)
        first,second=root/'first',root/'second'
        first.write_bytes(b'first')
        second.write_bytes(b'second')
        hard,symbolic=root/'hard',root/'symbolic'
        os.link(first,hard)
        symbolic.symlink_to(second)
        reject_start(build,root,[first,hard],'Duplicate fanotify inode')
        reject_start(build,root,[first,symbolic],'regular file')
        reject_start(build,root,[first,root],'regular file')
        reject_start(build,root,[first,root/'missing'],'pin fanotify target')
        reject_start(build,root,[first,Path('/proc/self/status')],'fanotify_mark permission event')
        # The source is itself a secondary marked target.
        reject_start(build,root,[first,root/'bad-policy'],'policy file cannot be a marked inode')
        gate=GateRun(build/'secmon',first,'deny',['--file',str(second)])
        try:
            assert open_errno(first)==errno.EPERM and open_errno(second)==errno.EPERM
        finally:
            gate.finish()
    reports=[]
    for pidfd in (False,True):
        for event in ('open','access'):
            reports.append(experiment(build,event,pidfd))
            assert len(os.listdir('/proc/self/fd'))==base
            assert not Path('/proc/self/task',str(os.getpid()),'children').read_text().strip()
            print(json.dumps(reports[-1]),flush=True)
    for event in ('open','access'):
        for mode in ('analysis','timeout','capacity-shutdown'):
            completion_reasons(build,event,mode)
            assert len(os.listdir('/proc/self/fd'))==base
            assert not Path('/proc/self/task',str(os.getpid()),'children').read_text().strip()
    exec_targets(build)
    assert len(os.listdir('/proc/self/fd'))==base
    print(json.dumps(dict(passed=True,variants=4,controller_base_fds=base,
                          controller_final_fds=len(os.listdir('/proc/self/fd')))),flush=True)


if __name__=='__main__':
    main()
