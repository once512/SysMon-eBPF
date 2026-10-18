// SPDX-License-Identifier: MIT
// 同一线程中 prepare 与 commit 之间不消费事件，故空闲验证不会在提交前被本线程改变。
#include "monitor.h"
#include "policy.h"
#include "status.h"
#include "stats.h"
#include <iostream>
#include <type_traits>
static_assert(std::is_nothrow_move_assignable_v<FanotifyOptions>);
static_assert(std::is_nothrow_move_constructible_v<FanotifyOptions>);
FanotifyMonitor::FanotifyMonitor(FanotifyOptions options, const std::string &policy_path, AuditSink *audit,
                                 std::uint64_t instance_ns, std::uint64_t revision)
    : options_(std::move(options)), gate_(options_.path, options_.decision, options_.event, options_.analyzer, policy_path, audit, instance_ns, revision)
{
    std::cerr << "Fanotify active; decision=" << (options_.decision.external ? "analysis" : (options_.decision.allow ? "allow" : "deny"))
              << " analyzer_pid=" << gate_.analyzer_pid() << " event=" << permission_name(options_.event) << '\n';
}
FanotifyOptions FanotifyMonitor::prepare(const PolicyConfig &candidate) const
{
    if (!candidate.fanotify)
        throw management::Error(management::Code::restart_required, "Disabling fanotify requires restart");
    auto next = options_;
    apply_fanotify_policy(candidate, next);
    if (!same_fanotify_backend(options_, next))
        throw management::Error(management::Code::restart_required, "Changing fanotify target, event or analyzer requires restart");
    gate_.validate_reconfigure(next.decision);
    return next;
}
void FanotifyMonitor::commit(FanotifyOptions candidate, std::uint64_t revision) noexcept
{
    gate_.commit_reconfigure(candidate.decision, revision);
    options_ = std::move(candidate);
}
void FanotifyMonitor::snapshot(management::Reply &reply) const { fill_fanotify_status(reply, options_, gate_); }
void FanotifyMonitor::report(std::ostream &out) const { write_gate_stats(out, options_.event, gate_.stats()); }
