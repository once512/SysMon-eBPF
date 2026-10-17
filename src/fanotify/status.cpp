// SPDX-License-Identifier: MIT
#include "status.h"
management::Reply fanotify_status(const PolicyRuntime &runtime, const FanotifyOptions &options,
                                 const PermissionGate &gate)
{
    auto reply = runtime.snapshot(management::Backend::fanotify);
    const auto &stats = gate.stats();
    reply.allowed = stats.allowed;
    reply.denied = stats.denied;
    reply.analysis_errors = stats.analyzer_error;
    reply.analysis_failures = stats.analyzer_failures;
    reply.overflow = stats.overflow;
    reply.pending = gate.pending_count();
    reply.peak_pending = stats.peak_pending;
    reply.event = options.event == PermissionEvent::open ? 1 : (options.event == PermissionEvent::access ? 2 : 3);
    reply.mode = options.decision.external ? 3 : (options.decision.allow ? 1 : 2);
    reply.delay_ms = options.decision.delay.count();
    reply.timeout_ms = options.decision.timeout.count();
    reply.max_pending = options.decision.max_pending;
    reply.fallbacks = (options.decision.timeout_allow ? 1U : 0U) |
        (options.decision.overload_allow ? 2U : 0U) | (options.decision.analyzer_error_allow ? 4U : 0U);
    if (options.decision.external) {
        reply.flags |= management::analyzer;
        if (gate.analyzer_online()) reply.flags |= management::analyzer_online;
        reply.worker_pid = gate.analyzer_pid();
        reply.scan_limit = options.analyzer.scan_limit;
    }
    return reply;
}
