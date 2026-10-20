#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real audit -> CLI grouping/rule evaluation, with independent pidfds and benign controls."""
import argparse
from collections import Counter
from contextlib import ExitStack
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import selectors
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

from management_harness import call
from permission_audit import AuditedService, contents
from writer_harness import WriterProcess

TOOLS = Path(__file__).resolve().parents[1] / 'tools'
sys.path.insert(0, str(TOOLS))
from evidence import Grouper, consume

GATE = """import os,sys
print('ready',flush=True)
assert sys.stdin.readline().strip() == 'go'
os.execv(sys.argv[1],sys.argv[1:])
"""


def reference(stack, pid):
    fd = os.pidfd_open(pid)
    stack.callback(os.close, fd)
    return os.fstat(fd).st_ino


def external(stack, argv, expected_code=0):
    """Open a real pidfd before exec; stdout contents are checked independently."""
    process = subprocess.Popen([sys.executable, '-B', '-c', GATE, *map(str, argv)],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            assert selector.select(5), 'external tool ready deadline'
        assert process.stdout.readline() == b'ready\n'
        cookie = reference(stack, process.pid)
        output, error = process.communicate(b'go\n', timeout=10)
        assert process.returncode == expected_code, (argv, process.returncode, error)
        return cookie, output
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()


def evaluate(raw, machine, boot, capture, rule_history=32):
    args = dict(rule_window_ms=1000, rule_history=rule_history)
    result = list(consume(io.BytesIO(raw), Grouper(machine, boot, capture, **args)))
    command = [sys.executable, '-B', str(TOOLS / 'evidence.py'), '--machine-id', machine,
               '--boot-id', boot, '--capture-id', capture, '--rule-window-ms', '1000',
               '--rule-history', str(rule_history)]
    cli = subprocess.run(command, input=raw, capture_output=True, timeout=10, check=True)
    assert [json.loads(line) for line in cli.stdout.splitlines()] == json.loads(json.dumps(result))
    summary = result[-1]
    assert summary['invalid'] == 0 and summary['capacity_evictions'] == 0
    assert all(row['classification'] == 'undetermined' for row in result)
    # Real dual-backend output can be delivered in either order. Neither an exact
    # sample representative nor LRU emission order is a cross-order guarantee.
    reversed_result = list(consume(io.BytesIO(b''.join(raw.splitlines(keepends=True)[::-1])),
                                   Grouper(machine, boot, capture, **args)))
    def facts(rows):
        return sorted((r['process_inode'], tuple(r['target'].values()), r['permission_allow'],
                       r['permission_deny'], r['mutation_denied'], r['behavior']['matches'])
                      for r in rows[:-1])
    assert facts(result) == facts(reversed_result)
    assert reversed_result[-1]['invalid'] == 0
    return result, cli.stdout


def experiment(build, event, pidfd, artifact, corpus_files=256, payload_bytes=2048, protected_bytes=10040,
               mutation_attempts=1, benign_edit=False):
    with tempfile.TemporaryDirectory(prefix='secmon-behavior-') as temporary, ExitStack() as stack:
        root = Path(temporary)
        target, other = root / 'decoy', root / 'other'
        pattern = bytes(range(251))
        data = (pattern * (protected_bytes // len(pattern) + 1))[:protected_bytes]
        target.write_bytes(data)
        other.write_bytes(b'other object\n')
        identity = target.stat()
        hard, symbolic = root / 'hard', root / 'symbolic'
        os.link(target, hard)
        symbolic.symlink_to(target)
        corpus = root / 'corpus'
        corpus.mkdir()
        corpus_expected = {}
        for directory in range((corpus_files + 15) // 16):
            folder = corpus / f'dir-{directory:02}'
            folder.mkdir()
            for number in range(min(16, corpus_files - directory * 16)):
                relative = f'{folder.name}/file-{number:02}'
                block = hashlib.sha256(relative.encode()).digest()
                payload = (block * (payload_bytes // len(block) + 1))[:payload_bytes]
                (corpus / relative).write_bytes(payload)
                corpus_expected[relative] = payload
        os.link(target, corpus / 'decoy-hard')
        (corpus / 'decoy-symbolic').symlink_to(target)
        editor_program = root / 'editor'
        shutil.copy2(build / 'secmon-writer-scenario', editor_program)
        actors, cookies = {}, {}
        cross_object = root / 'cross-object'
        cross_object.symlink_to(other)
        for role in ('reader', 'authorized', 'candidate', 'maintenance', 'write-only', 'other-object', 'expired'):
            binary = editor_program if role in ('authorized', 'maintenance') else build / 'secmon-writer-scenario'
            actors[role] = stack.enter_context(WriterProcess(binary, cross_object if role == 'other-object' else target))
            cookies[role] = reference(stack, actors[role].process.pid)
        cross_object.unlink()
        cross_object.symlink_to(target)
        fields = (f'protect "{target}"\nprotect "{other}"\n'
                  f'fanotify-event {event}\nfanotify-decision allow\n'
                  f'allow-writer "{editor_program}" 0 "{target}" write,rename')
        service = AuditedService(build, root, target, fields, combined=True, requester_pidfd=pidfd)
        stack.callback(service.close)
        cases = []

        def act(role, command, expected):
            begin = time.monotonic_ns()
            actual = actors[role].request(command)
            assert actual == expected, (role, command, actual)
            cases.append(dict(role=role, command=command, errno=actual,
                              begin_ns=begin, end_ns=time.monotonic_ns(), process_inode=cookies[role]))

        act('reader', 'r', 0)
        act('authorized', 'r', 0)
        act('authorized', 'w', 0)
        for _ in range(mutation_attempts):
            act('candidate', 'r', 0)
            act('candidate', 'w', errno.EACCES)
        act('maintenance', 'r', 0)
        # Same observational pattern can be a benign application using stale authorization.
        service.publish(2, fields.replace(' write,rename', ' rename'))
        assert call(service.binary, 'reload', service.control)['revision'] == 2
        act('maintenance', 'w', errno.EACCES)
        act('write-only', 'w', errno.EACCES)
        act('expired', 'r', 0)
        time.sleep(1.1)
        act('expired', 'w', errno.EACCES)
        # A read of another marked object cannot explain a write denial on decoy.
        act('other-object', 'r', 0)
        act('other-object', 'w', errno.EACCES)

        expected_data = b'W' + data[1:]
        corpus_expected.update({'decoy-hard': expected_data, 'decoy-symbolic': expected_data})
        tools = []
        def tool(role, argv, expected_output=None, expected_code=0):
            cookie, output = external(stack, argv, expected_code)
            if expected_output is not None:
                assert output == expected_output, (role, output[:100])
            tools.append(dict(role=role, process_inode=cookie, argv=list(map(str, argv)),
                              exit_code=expected_code,
                              output_sha256=hashlib.sha256(output).hexdigest()))

        tool('cat', ['/usr/bin/cat', hard], expected_data)
        indexed_paths = [corpus / name for name in sorted(corpus_expected)]
        expected_index = ''.join(f'{hashlib.sha256(corpus_expected[str(path.relative_to(corpus))]).hexdigest()}  {path}\n'
                                 for path in indexed_paths).encode()
        tool('index-sha256sum', ['/usr/bin/sha256sum', *indexed_paths], expected_index)
        copy = root / 'copy'
        tool('backup-cp', ['/usr/bin/cp', '-RL', '--reflink=never', corpus, copy], b'')
        for relative, payload in corpus_expected.items():
            assert (copy / relative).read_bytes() == payload
        archive = root / 'backup.tar'
        tool('backup-tar', ['/usr/bin/tar', '--dereference', '--hard-dereference', '-cf', archive,
                            '-C', corpus, '.'], b'')
        if benign_edit:
            # GNU sed reads successfully, writes a new temporary inode, then
            # attempts to replace the protected destination: a benign rule match.
            tool('benign-sed-inplace', ['/usr/bin/sed', '-i', '1s/^/EDIT:/', hard], b'', expected_code=4)

        # Rename retains the protected object; replacement pathname is a distinct object.
        act('authorized', 'n', 0)
        replacement = b'unmarked replacement\n'
        target.write_bytes(replacement)
        assert target.stat().st_ino != identity.st_ino
        tool('renamed-cat', ['/usr/bin/cat', Path(str(target) + '.alias')], expected_data)
        tool('replacement-cat', ['/usr/bin/cat', symbolic], replacement)
        status = service.status()
        assert status['revision'] == 2
        service.stop()
        raw = contents(service.output).encode()
        diagnostics = contents(service.errors)
        for field in ('audit_dropped', 'audit_invalid', 'audit_queued', 'audit_errno',
                      'ringbuf_dropped', 'baseline_update_failed'):
            values = re.findall(r'\b' + field + r'=(\d+)', diagnostics)
            assert values and int(values[-1]) == 0, (field, values)
        with tarfile.open(archive) as backup:
            archived = {str(Path(member.name)): backup.extractfile(member).read()
                        for member in backup.getmembers() if member.isfile()}
            assert archived == corpus_expected
        assert hard.read_bytes() == expected_data
        machine = Path('/etc/machine-id').read_text().strip()
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        capture = f'behavior-{event}-{int(pidfd)}-{service.initial["instance_ns"]}'
        # The capture baseline retains this workload's whole candidate history;
        # lower capacities and delivery loss are measured separately by the evaluator.
        result, cli_output = evaluate(raw, machine, boot, capture, max(32, mutation_attempts))
        summary = result[-1]
        if protected_bytes == 10040 and mutation_attempts <= 32:
            assert summary['rule_history_evictions'] == 0
        groups = result[:-1]
        expected_key = dict(major=os.major(identity.st_dev), minor=os.minor(identity.st_dev), inode=identity.st_ino)
        by_key = {(r['process_inode'], r['target']['inode']): r for r in groups}
        records = [json.loads(line) for line in raw.splitlines()]
        permissions = [r for r in records if r['event'] == 'fanotify_decision']
        denials = [r for r in records if r['event'] == 'file_denied']
        assert len(denials) == mutation_attempts + 4 + int(benign_edit), denials
        expected_counts = {
            cookies[role]: mutation_attempts if role == 'candidate' else 1
            for role in ('candidate', 'maintenance', 'write-only', 'expired', 'other-object')}
        expected_denials = {cookies[role]: other.stat().st_ino if role == 'other-object' else identity.st_ino
                            for role in ('candidate', 'maintenance', 'write-only', 'expired', 'other-object')}
        sed_cookie = next((t['process_inode'] for t in tools if t['role'] == 'benign-sed-inplace'), None)
        if benign_edit:
            expected_counts[sed_cookie] = 1
            expected_denials[sed_cookie] = identity.st_ino
        assert Counter(r['process_inode'] for r in denials) == Counter(expected_counts)
        assert {r['process_inode']: r['ino'] for r in denials} == expected_denials
        assert all(r['operation'] == (5 if r['process_inode'] == sed_cookie else 2) and
                   r['errno'] == errno.EACCES for r in denials)
        assert len(permissions) > 0
        assert sorted(r['request_id'] for r in permissions) == list(range(1, len(permissions) + 1))
        assert all(r['decision'] == 'allow' for r in permissions)
        for row in permissions:
            assert row['instance_ns'] == service.initial['instance_ns']
            assert row['listener_pid'] == service.process.pid
            assert (row['major'], row['minor'], row['inode']) == tuple(expected_key.values())
            if pidfd:
                assert row['requester_reference'] == 'present' and row['requester_identity_errno'] == 0
                assert row['requester_process_inode'] in {*cookies.values(), *(r['process_inode'] for r in tools)}
        assert summary['grouped'] + summary['unattributed'] == len(permissions) + len(denials)
        assert summary['unattributed'] == (0 if pidfd else len(permissions))
        expected_matches = {'candidate': mutation_attempts, 'maintenance': 1}
        if benign_edit:
            expected_matches['benign-sed-inplace'] = 1
        for role, cookie in cookies.items():
            inode = identity.st_ino
            group = by_key.get((cookie, inode))
            count = group['behavior']['matches'] if group else 0
            assert count == (expected_matches.get(role, 0) if pidfd else 0), (role, group)
        assert summary['rule_matches'] == (mutation_attempts + 1 + int(benign_edit) if pidfd else 0)
        cross_denial = by_key[(cookies['other-object'], other.stat().st_ino)]
        assert cross_denial['mutation_denied'] == 1 and cross_denial['behavior']['matches'] == 0
        for actor in tools:
            observed = [r for r in groups if r['process_inode'] == actor['process_inode']]
            if actor['role'] == 'benign-sed-inplace':
                assert len(observed) == 1 and observed[0]['mutation_denied'] == 1
                assert observed[0]['behavior']['matches'] == int(pidfd)
                assert (observed[0]['permission_allow'] > 0) == pidfd
                assert observed[0]['target'] == expected_key
                continue
            assert all(r['behavior']['matches'] == 0 and r['mutation_denied'] == 0 for r in observed)
            if actor['role'] == 'replacement-cat' or not pidfd:
                assert not observed, (actor, observed)
            else:
                assert len(observed) == 1 and observed[0]['permission_allow'] > 0, (actor, observed)
                assert observed[0]['target'] == expected_key
        report = dict(event=event, requester_pidfd=pidfd, capture=capture, source=result[-1]['source'],
                      scenarios=cases, tools=tools, summary=summary,
                      matched_roles=expected_matches if pidfd else {},
                      interpretation='controlled observations; benign matching counterexamples are test declarations',
                      permissions=len(permissions), denials=len(denials),
                      corpus_files=len(corpus_expected), corpus_bytes=sum(map(len, corpus_expected.values())),
                      protected_bytes=protected_bytes,
                      mutation_attempts=mutation_attempts,
                      benign_matching_counterexamples=(1 + int(benign_edit)) if pidfd else 0,
                      diagnostics=diagnostics)
        report['environment'] = dict(kernel=platform.release(), architecture=platform.machine(),
                                     python=sys.version, executable_sha256={
                                         str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                                         for path in [build / 'secmon', build / 'secmon-writer-scenario',
                                                      TOOLS / 'evidence.py', TOOLS / 'behavior.py',
                                                      Path(__file__).resolve(),
                                                      *[Path('/usr/bin') / name for name in
                                                        ('cat', 'sha256sum', 'cp', 'tar', *(['sed'] if benign_edit else []))]]})
        report['audit_sha256'] = hashlib.sha256(raw).hexdigest()
        report['evidence_sha256'] = hashlib.sha256(cli_output).hexdigest()
        if artifact:
            artifact.mkdir(parents=True, exist_ok=False)
            (artifact / 'audit.jsonl').write_bytes(raw)
            (artifact / 'evidence.jsonl').write_bytes(cli_output)
            (artifact / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', default='build')
    parser.add_argument('--artifact-dir', type=Path)
    parser.add_argument('--duration', type=int, default=0, help='repeat complete four-variant cycles, 0..3600 seconds')
    parser.add_argument('--corpus-files', type=int, default=256, help='ordinary files, 1..16384 (plus two decoy aliases)')
    parser.add_argument('--payload-bytes', type=int, default=2048, help='bytes per ordinary file, 1..65536')
    parser.add_argument('--protected-bytes', type=int, default=10040, help='protected file size, 1..16777216')
    parser.add_argument('--mutation-attempts', type=int, default=1, help='controlled read/denied-write pairs, 1..128')
    parser.add_argument('--benign-edit', action='store_true', help='include GNU sed inplace-save denial counterexample')
    args = parser.parse_args()
    if os.geteuid() != 0 or sys.flags.optimize or os.environ.get('PYTHONOPTIMIZE'):
        parser.error('run as root without Python optimization')
    if not 0 <= args.duration <= 3600:
        parser.error('duration must be 0..3600')
    if not 1 <= args.mutation_attempts <= 128:
        parser.error('mutation-attempts must be 1..128')
    if not 1 <= args.corpus_files <= 16384 or not 1 <= args.payload_bytes <= 65536:
        parser.error('corpus-files must be 1..16384; payload-bytes must be 1..65536')
    if args.corpus_files * args.payload_bytes > 128 * 1024 * 1024 or not 1 <= args.protected_bytes <= 16 * 1024 * 1024:
        parser.error('ordinary corpus must be <=128 MiB; protected-bytes must be 1..16777216')
    assert os.readlink('/proc/self/ns/pid') == os.readlink('/proc/1/ns/pid')
    for program in ('cat', 'sha256sum', 'cp', 'tar', *(['sed'] if args.benign_edit else [])):
        assert Path('/usr/bin', program).is_file(), program
    start, cycle, reports = time.monotonic(), 0, []
    base_fds = len(os.listdir('/proc/self/fd'))
    while True:
        cycle += 1
        for pidfd in (False, True):
            for event in ('open', 'access'):
                artifact = args.artifact_dir / f'cycle-{cycle}-{event}-pidfd-{int(pidfd)}' if args.artifact_dir else None
                report = experiment(Path(args.build_dir).resolve(), event, pidfd, artifact,
                                    args.corpus_files, args.payload_bytes, args.protected_bytes,
                                    args.mutation_attempts, args.benign_edit)
                assert len(os.listdir('/proc/self/fd')) == base_fds, 'controller FD leak'
                assert not Path('/proc/self/task', str(os.getpid()), 'children').read_text().strip(), 'unreaped child'
                reports.append(dict(event=event, requester_pidfd=pidfd, cycle=cycle,
                                    corpus_files=report['corpus_files'], protected_bytes=report['protected_bytes'],
                                    **{k: report['summary'][k] for k in ('grouped', 'unattributed', 'rule_matches', 'rule_history_evictions')}))
                print(json.dumps(dict(experiment='behavior-workloads', **reports[-1], passed=True)), flush=True)
        if time.monotonic() - start >= args.duration:
            break
    print(json.dumps(dict(passed=True, cycles=cycle, variants=len(reports),
                          controller_base_fds=base_fds, controller_final_fds=len(os.listdir('/proc/self/fd')),
                          seconds=round(time.monotonic() - start, 3))), flush=True)


if __name__ == '__main__':
    main()
