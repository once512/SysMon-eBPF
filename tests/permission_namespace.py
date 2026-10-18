#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""An inner fanotify listener sees its local TGIDs and zero for invisible outer actors."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from permission_audit import contents, request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', default='build')
    args = parser.parse_args()
    if os.geteuid() != 0 or sys.flags.optimize:
        parser.error('run as root without Python optimization')
    build = Path(args.build_dir).resolve()
    for combined in (False, True):
        with tempfile.TemporaryDirectory(prefix='secmon-permission-namespace-') as temporary:
            root = Path(temporary)
            target, policy, control = (root / name for name in ('target', 'policy', 'control'))
            target.write_bytes(b'fixture')
            policy.write_text(f'revision 1\nfanotify-file "{target}"\nfanotify-decision allow\n')
            policy.chmod(0o600)
            namespace_call = None
            with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
                metadata = root / 'namespace.json'
                launcher = ('import json,pathlib,subprocess,sys; child=subprocess.Popen(sys.argv[2:]); '
                            'pathlib.Path(sys.argv[1]).write_text(json.dumps({"listener_pid":child.pid})); '
                            'sys.exit(child.wait())')
                process = subprocess.Popen(['unshare', '--mount', '--pid', '--fork', '--mount-proc',
                                            '--propagation', 'private', '--kill-child=KILL', '--', sys.executable, '-B', '-c', launcher,
                                            str(metadata), str(build / 'secmon'),
                                            *([] if combined else ['--fanotify-only']), '--audit-permissions', '--policy', str(policy),
                                            '--control', str(control), '--run-for', '30'], stdout=output, stderr=errors)
                try:
                    deadline = time.monotonic() + 10
                    while 'Service active;' not in contents(errors):
                        assert process.poll() is None and time.monotonic() < deadline, contents(errors)
                        time.sleep(0.01)
                    children = Path(f'/proc/{process.pid}/task/{process.pid}/children').read_text().split()
                    assert len(children) == 1
                    holder_host_pid = int(children[0])
                    listener_local_pid = json.loads(metadata.read_text())['listener_pid']
                    # The namespace init remains unprotected; the service child retains self-protection.
                    namespace_inode = os.stat(f'/proc/{holder_host_pid}/ns/pid').st_ino
                    assert namespace_inode != os.stat('/proc/self/ns/pid').st_ino
                    def namespace_call(command):
                        reply = subprocess.run(['nsenter', '--target', str(holder_host_pid), '--pid', '--',
                                                str(build / 'secmon'), '--' + command, str(control)],
                                               capture_output=True, text=True, timeout=5)
                        assert reply.returncode == 0, (reply.stdout, reply.stderr)
                        result = json.loads(reply.stdout)
                        assert result['code'] == 'ok' and result['protocol_version'] == 3
                        return result
                    # The client intentionally rejects a reply PID in different coordinates.
                    outer = subprocess.run([str(build / 'secmon'), '--status', str(control)],
                                           capture_output=True, text=True, timeout=5)
                    assert outer.returncode != 0 and 'Management peer PID mismatch' in outer.stderr
                    status = namespace_call('status')
                    assert status['backend'] == ('combined' if combined else 'fanotify')
                    assert request(target)['errno'] == 0
                    # Enter only the PID namespace; namespace /proc membership is not used as identity proof.
                    code = 'import json,os,sys; fd=os.open(sys.argv[1],os.O_RDONLY); os.close(fd); print(json.dumps({"pid":os.getpid()}))'
                    result = subprocess.run(['nsenter', '--target', str(holder_host_pid), '--pid', '--',
                                             sys.executable, '-B', '-c', code, str(target)],
                                            capture_output=True, text=True, timeout=5, check=True)
                    inner_pid = json.loads(result.stdout)['pid']
                    assert inner_pid > 1
                    namespace_call('stop')
                    process.wait(timeout=5)
                    assert process.returncode == 0, contents(errors)
                    records = [json.loads(line) for line in contents(output).splitlines()]
                    events = [row for row in records if row['event'] == 'fanotify_decision']
                    assert len(events) == 2
                    assert [row['requester_pid'] for row in events] == [0, inner_pid], events
                    assert [row['request_id'] for row in events] == [1, 2]
                    for row in events:
                        assert row['requester_pid_kind'] == 'tgid'
                        assert row['listener_pid'] == listener_local_pid and row['pid_namespace_inode'] == namespace_inode
                        assert row['instance_ns'] == status['instance_ns']
                        assert row['decision'] == 'allow' and row['reason'] == 'policy'
                    for field in ('audit_dropped', 'audit_invalid', 'audit_queued', 'audit_errno'):
                        values = re.findall(r'\b' + field + r'=(\d+)', contents(errors))
                        assert values and int(values[-1]) == 0, (field, values)
                    assert not control.exists()
                finally:
                    if process.poll() is None:
                        try:
                            if control.exists() and namespace_call is not None:
                                namespace_call('stop')
                        finally:
                            process.wait(timeout=35)
        print(json.dumps(dict(experiment='permission-namespace', combined=combined,
                              outer_pid=0, local_pid=inner_pid, passed=True)), flush=True)


if __name__ == '__main__':
    main()
