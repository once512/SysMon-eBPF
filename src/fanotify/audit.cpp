// SPDX-License-Identifier: MIT
#include "audit.h"
#include <sstream>
#include <stdexcept>
namespace {
const char *reason_name(DecisionReason reason)
{
    switch (reason) {
    case DecisionReason::policy: return "policy";
    case DecisionReason::timeout: return "timeout";
    case DecisionReason::capacity: return "capacity";
    case DecisionReason::shutdown: return "shutdown";
    case DecisionReason::analysis: return "analysis";
    case DecisionReason::analyzer_error: return "analyzer_error";
    }
    throw std::invalid_argument("Invalid permission decision reason");
}
}
std::string format_permission_decision(const PermissionAuditIdentity &identity, const PermissionRequest &request,
                                       Verdict verdict, PendingDecisions::Clock::time_point responded)
{
    using namespace std::chrono;
    if (!identity.pid_namespace_inode || !request.id || !identity.instance_ns || identity.listener_pid <= 0 || responded < request.received ||
        request.received.time_since_epoch() < PendingDecisions::Clock::duration::zero() ||
        !analysis::valid_scan_error(verdict.scan_error, verdict.scan_errno) ||
        (verdict.scan_error != analysis::ScanError::none && verdict.reason != DecisionReason::analyzer_error))
        throw std::invalid_argument("Invalid permission audit context");
    const auto *reason = reason_name(verdict.reason);
    const auto *event = permission_name(identity.event);
    std::ostringstream out;
    // permission reply 表示已向内核成功写回，不宣称原系统调用最终成功。
    out << "{\"event\":\"fanotify_decision\",\"listener_pid\":" << identity.listener_pid
        << ",\"instance_ns\":" << identity.instance_ns << ",\"request_id\":" << request.id
        << ",\"requester_pid\":" << request.requester_pid
        << ",\"requester_pid_kind\":\"tgid\",\"pid_namespace_inode\":" << identity.pid_namespace_inode
        << ",\"revision\":" << request.revision
        << ",\"major\":" << identity.major << ",\"minor\":" << identity.minor << ",\"inode\":" << identity.inode
        << ",\"permission_event\":\"" << event << "\",\"decision\":\"" << (verdict.allow ? "allow" : "deny")
        << "\",\"reason\":\"" << reason << "\",\"scan_error\":\"" << analysis::scan_error_name(verdict.scan_error)
        << "\",\"scan_errno\":" << verdict.scan_errno
        << ",\"received_ns\":" << duration_cast<nanoseconds>(request.received.time_since_epoch()).count()
        << ",\"responded_ns\":" << duration_cast<nanoseconds>(responded.time_since_epoch()).count()
        << ",\"latency_us\":" << duration_cast<microseconds>(responded - request.received).count() << "}\n";
    return out.str();
}
