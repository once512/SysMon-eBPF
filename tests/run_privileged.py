#!/usr/bin/env python3
# 按顺序运行权限专题并在首个失败时停止；需保留 Python 断言，不要使用 -O 把验证条件优化掉。
# SPDX-License-Identifier: MIT
"""Run the temporary privileged experiments sequentially with one sudo session."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

TESTS = (
    ('audit-file', 'integration.py'),
    ('self-protection', 'self_protection.py'),
    ('fanotify-open', 'fanotify.py'),
    ('fanotify-deferred', 'fanotify_deferred.py'),
    ('fanotify-events', 'fanotify_events.py'),
    ('reader-health', 'fanotify_reader_health.py'),
    ('fanotify-analysis', 'fanotify_analysis.py'),
    ('analysis-faults', 'fanotify_analysis_faults.py'),
    ('policy-layers', 'policy_composition.py'),
    ('policy-reload', 'policy_reload.py'),
    ('writer-identity', 'writer_identity.py'),
    ('writer-lease', 'writer_lease.py'),
    ('file-metadata', 'file_metadata.py'),
    ('metadata-identity', 'metadata_identity.py'),
    ('virtual-reader', 'fanotify_reader_pause.py'),
    ('virtual-analysis-reader', 'fanotify_analysis_reader.py'),
    ('virtual-preparation', 'bounded_preparation.py'),
    ('virtual-view', 'decoy_view.py'),
    ('virtual-response', 'virtual_decoy.py'),
    ('virtual-lifecycle', 'virtual_decoy_lifecycle.py'),
    ('virtual-fanotify', 'virtual_decoy_fanotify.py'),
    ('canary-response', 'canary_response.py'),
    ('canary-capacity', 'canary_capacity.py'),
    ('canary-backpressure', 'canary_backpressure.py'),
    ('canary-namespace', 'canary_namespace.py'),
    ('canary-layers', 'canary_layers.py'),
    ('vault-sessions', 'vault_sessions.py'),
    ('vault-capacity', 'vault_capacity.py'),
    ('vault-restart', 'vault_restart.py'),
    ('vault-history', 'vault_history.py'),
    ('vault-applications', 'vault_applications.py'),
    ('vault-time-namespace', 'vault_time_namespace.py'),
    ('lease-time-namespace', 'lease_time_namespace.py'),
    ('writer-scope', 'writer_scope.py'),
    ('writer-matrix', 'writer_matrix.py'),
    ('writer-capacity', 'writer_capacity.py'),
    ('writer-layers', 'writer_layers.py'),
    ('fanotify-policy', 'fanotify_policy.py'),
    ('fanotify-multiple', 'fanotify_multiple.py'),
    ('fanotify-handover', 'fanotify_handover.py'),
    ('subscription-lifecycle', 'subscription_live.py'),
    ('management-live', 'management_live.py'),
    ('management-faults', 'management_faults.py'),
    ('control-loop', 'control_loop.py'),
    ('namespace-policy', 'namespace_policy.py'),
    ('pid-namespace', 'pid_namespace.py'),
    ('policy-consistency', 'policy_consistency.py'),
    ('unified-service', 'unified_service.py'),
    ('audit-backpressure', 'audit_backpressure.py'),
    ('permission-audit', 'permission_audit.py'),
    ('decoy-evidence', 'decoy_evidence.py'),
    ('decoy-workloads', 'decoy_workloads.py'),
    ('behavior-workloads', 'behavior_workloads.py'),
    ('behavior-applications', 'behavior_applications.py'),
    ('behavior-chains', 'behavior_chains.py'),
    ('behavior-identity', 'behavior_identity.py'),
    ('identity-threads', 'identity_threads.py'),
    ('permission-namespace', 'permission_namespace.py'),
    ('requester-pidfd', 'requester_pidfd.py'),
    ('requester-lifecycle', 'requester_lifecycle.py'),
    ('permission-audit-backpressure', 'permission_audit_backpressure.py'),
    ('shutdown-order', 'shutdown_order.py'),
    ('diagnostic-backpressure', 'diagnostic_backpressure.py'),
    ('baseline-lifecycle', 'baseline_lifecycle.py'),
    ('credential-transitions', 'credential_transitions.py'),
    ('userns-credentials', 'userns_credentials.py'),
    ('baseline-mismatch', 'baseline_mismatch.py'),
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', default='build')
    parser.add_argument('--soak-duration', type=int, default=0,
                        help='add both policy/timeout workloads, 0 disables (default)')
    parser.add_argument('--analysis-soak-duration', type=int, default=0)
    parser.add_argument('--management-soak-duration', type=int, default=0)
    parser.add_argument('--combined-soak-duration', type=int, default=0, help='add same-process scoped-writer static/analysis management loads')
    parser.add_argument('--permission-audit-soak-duration', type=int, default=0, help='add combined permission-audit record accounting loads')
    parser.add_argument('--requester-pidfd-soak-duration', type=int, default=0, help='add three combined pidfd identity/accounting loads')
    parser.add_argument('--requester-identity-soak-duration', type=int, default=0, help='repeat all pidfd thread/namespace variants')
    parser.add_argument('--writer-soak-duration', type=int, default=0)
    parser.add_argument('--only', choices=[name for name, _ in TESTS], nargs='+')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run with sudo; tests temporarily load BPF and fanotify policies')
    if sys.flags.optimize or os.environ.get('PYTHONOPTIMIZE'):
        parser.error('run without Python optimization; test assertions must remain enabled')
    if not 0 <= args.soak_duration <= 1800 or not 0 <= args.analysis_soak_duration <= 1800 or not 0 <= args.management_soak_duration <= 1800:
        parser.error('soak-duration must be 0..1800 seconds')
    if not (args.combined_soak_duration == 0 or 5 <= args.combined_soak_duration <= 1800):
        parser.error('combined-soak-duration must be 0 or 5..1800 seconds')
    if not (args.permission_audit_soak_duration == 0 or 5 <= args.permission_audit_soak_duration <= 1800):
        parser.error('permission-audit-soak-duration must be 0 or 5..1800 seconds')
    if not (args.writer_soak_duration == 0 or 5 <= args.writer_soak_duration <= 1800):
        parser.error('writer-soak-duration must be 0 or 5..1800 seconds')
    if not (args.requester_pidfd_soak_duration == 0 or 5 <= args.requester_pidfd_soak_duration <= 1800):
        parser.error('requester-pidfd-soak-duration must be 0 or 5..1800 seconds')
    if not (args.requester_identity_soak_duration == 0 or 5 <= args.requester_identity_soak_duration <= 1200):
        parser.error('requester-identity-soak-duration must be 0 or 5..1200 seconds')
    root = Path(__file__).resolve().parent
    build = Path(args.build_dir).resolve()
    commands = [(name, [sys.executable, str(root / script), '--build-dir', str(build)])
                for name, script in TESTS if args.only is None or name in args.only]
    if not (build / 'secmon-decoyfs').exists():
        if args.only and any(name.startswith('virtual-') for name in args.only):
            parser.error('virtual topics require SECMON_BUILD_DECOYFS=ON')
        commands = [(name, command) for name, command in commands if not name.startswith('virtual-')]
    commands += [(name + '-pidfd', [sys.executable, str(root / script), '--build-dir', str(build), '--requester-pidfd'])
                 for name, script in (('identity-threads', 'identity_threads.py'), ('permission-namespace', 'permission_namespace.py'),
                                      ('permission-audit-backpressure', 'permission_audit_backpressure.py'))
                 if args.only is None or name in args.only]
    if args.soak_duration:
        commands += [(f'soak-{mode}', [sys.executable, str(root / 'fanotify_soak.py'),
                      '--build-dir', str(build), '--duration', str(args.soak_duration), '--mode', mode])
                     for mode in ('policy', 'timeout')]
    if args.analysis_soak_duration:
        commands += [(f'analysis-soak-{event}', [sys.executable, str(root / 'fanotify_soak.py'),
                      '--build-dir', str(build), '--duration', str(args.analysis_soak_duration),
                      '--backend', 'analysis', '--event', event]) for event in ('open', 'access')]
    if args.management_soak_duration:
        if args.management_soak_duration < 5:
            parser.error('management-soak-duration must be 0 or 5..1800 seconds')
        commands += [(f'management-soak-{backend}-{event}', [sys.executable, str(root / 'management_soak.py'),
                      '--build-dir', str(build), '--duration', str(args.management_soak_duration),
                      '--backend', backend, '--event', event])
                     for backend, event in (('static', 'open'), ('analysis', 'open'), ('analysis', 'access'))]
    if args.combined_soak_duration:
        commands += [(f'combined-soak-{backend}-{event}', [sys.executable, str(root / 'management_soak.py'),
                      '--build-dir', str(build), '--duration', str(args.combined_soak_duration), '--combined', '--verify-audit-output',
                      '--backend', backend, '--event', event])
                     for backend, event in (('static', 'open'), ('analysis', 'open'), ('analysis', 'access'))]
    if args.permission_audit_soak_duration:
        commands += [(f'permission-audit-soak-{backend}-{event}', [sys.executable, str(root / 'management_soak.py'),
                      '--build-dir', str(build), '--duration', str(args.permission_audit_soak_duration),
                      '--combined', '--verify-audit-output', '--audit-permissions', '--backend', backend, '--event', event])
                     for backend, event in (('static', 'open'), ('analysis', 'open'), ('analysis', 'access'))]
    if args.requester_identity_soak_duration:
        commands.append(('requester-identity-soak', [sys.executable, str(root / 'identity_threads.py'),
                         '--build-dir', str(build), '--duration', str(args.requester_identity_soak_duration), '--requester-pidfd']))
    if args.requester_pidfd_soak_duration:
        commands += [(f'requester-pidfd-soak-{backend}-{event}', [sys.executable, str(root / 'management_soak.py'),
                      '--build-dir', str(build), '--duration', str(args.requester_pidfd_soak_duration),
                      '--combined', '--verify-audit-output', '--audit-permissions', '--requester-pidfd', '--backend', backend, '--event', event])
                     for backend, event in (('static', 'open'), ('analysis', 'open'), ('analysis', 'access'))]
    if args.writer_soak_duration:
        commands.append(('writer-soak', [sys.executable, str(root / 'writer_soak.py'),
                         '--build-dir', str(build), '--duration', str(args.writer_soak_duration)]))
    results = []
    for name, command in commands:
        print(f'RUN {name}', flush=True)
        started = time.monotonic()
        result = subprocess.run(command)
        results.append({'test': name, 'passed': result.returncode == 0,
                        'seconds': round(time.monotonic() - started, 3)})
        if result.returncode:
            print(json.dumps({'passed': False, 'results': results}), flush=True)
            return 1
    print(json.dumps({'passed': True, 'results': results}), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
