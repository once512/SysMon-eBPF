// SPDX-License-Identifier: MIT
// 同一线程中 prepare 与 commit 之间不消费事件，故空闲验证不会在提交前被本线程改变。
#include "monitor.h"
#include "policy.h"
#include "status.h"
#include "stats.h"
#include <iostream>
#include <type_traits>
#include <algorithm>
#include "audit_sink.h"
#include <unistd.h>
#include <limits>
static_assert(std::is_nothrow_move_assignable_v<FanotifyOptions>);
static_assert(std::is_nothrow_move_constructible_v<FanotifyOptions>);
static_assert(std::is_nothrow_move_constructible_v<FanotifyMonitor::Prepared>);
namespace {
void accumulate(GateStats &total, const GateStats &part) noexcept
{
    total.allowed += part.allowed;
    total.denied += part.denied;
    total.overflow += part.overflow;
    total.timed_out += part.timed_out;
    total.overloaded += part.overloaded;
    total.shutdown_denied += part.shutdown_denied;
    total.analyzed += part.analyzed;
    total.analysis_denied += part.analysis_denied;
    total.analyzer_error += part.analyzer_error;
    total.analyzer_failures += part.analyzer_failures;
    total.backend_error_requests += part.backend_error_requests;
    for (std::size_t i = 0; i < total.scan_errors.size(); ++i)
        total.scan_errors[i] += part.scan_errors[i];
    if (part.last_scan_error != analysis::ScanError::none) {
        total.last_scan_error = part.last_scan_error;
        total.last_scan_errno = part.last_scan_errno;
    }
    total.peak_pending = std::max(total.peak_pending, part.peak_pending);
    total.target_updates += part.target_updates;
}
}
FanotifyMonitor::FanotifyMonitor(FanotifyOptions options, const std::string &policy_path, AuditSink *audit,
                                 std::uint64_t instance_ns, std::uint64_t revision, bool requester_pidfd)
    : policy_path_(policy_path), audit_(audit), instance_ns_(instance_ns), revision_(revision), requester_pidfd_(requester_pidfd),
      options_(std::move(options)), gate_(std::make_unique<PermissionGate>(options_.paths, options_.decision,
          options_.event, options_.analyzer, policy_path_, audit_, instance_ns_, revision, requester_pidfd_, &request_sequence_))
{
    std::cerr << "Fanotify active; decision=" << (options_.decision.external ? "analysis" : (options_.decision.allow ? "allow" : "deny"))
              << " analyzer_pid=" << gate_->analyzer_pid() << " event=" << permission_name(options_.event)
              << " targets=" << gate_->target_count() << '\n';
}
FanotifyOptions FanotifyMonitor::checked_options(const PolicyConfig &candidate) const
{
    if (!candidate.fanotify)
        throw management::Error(management::Code::restart_required, "Disabling fanotify requires restart");
    auto next = options_;
    apply_fanotify_policy(candidate, next);
    if (!same_fanotify_backend(options_, next))
        throw management::Error(management::Code::restart_required, "Changing fanotify event or analyzer requires restart");
    if (next.rebind_epoch < options_.rebind_epoch)
        throw management::Error(management::Code::invalid_policy, "Fanotify rebind epoch cannot decrease or be omitted after activation");
    gate_->validate_reconfigure(next.decision);
    if (next.paths != options_.paths || next.rebind_epoch > options_.rebind_epoch) {
        // Group closure releases kernel-unread permissions under prior allow.
        // Explicit re-pinning never relaxes this existing handover condition.
        if (options_.decision.external || !options_.decision.allow || options_.decision.delay.count())
            throw management::Error(management::Code::restart_required,
                "Target handover/rebind requires the old gate to use immediate static allow");
        if (subscription_generation_ == std::numeric_limits<std::uint64_t>::max())
            throw std::runtime_error("Subscription generation exhausted");
    }
    return next;
}
FanotifyMonitor::Prepared FanotifyMonitor::prepare(const PolicyConfig &candidate)
{
    Prepared prepared{checked_options(candidate), {}};
    const bool rebind = prepared.options.rebind_epoch > options_.rebind_epoch;
    if (prepared.options.paths != options_.paths || rebind) {
        std::vector<std::pair<std::string, int>> retained;
        retained.reserve(options_.paths.size());
        for (std::size_t i = 0; !rebind && i < options_.paths.size(); ++i)
            retained.emplace_back(options_.paths[i], gate_->target_fds()[i]);
        for (const auto &path : prepared.options.paths)
            if (!rebind) prepared.retained_targets += std::find(options_.paths.begin(), options_.paths.end(), path) != options_.paths.end();
        prepared.replacement = std::make_unique<PermissionGate>(prepared.options.paths, prepared.options.decision,
            prepared.options.event, prepared.options.analyzer, policy_path_, audit_, instance_ns_, candidate.revision,
            requester_pidfd_, &request_sequence_, retained, subscription_generation_ + 1);
    }
    return prepared;
}
void FanotifyMonitor::commit(Prepared candidate, std::uint64_t revision) noexcept
{
    if (candidate.replacement) {
        const auto old_count = gate_->target_count();
        accumulate(history_, gate_->stats());
        ++history_.target_updates;
        const auto previous_generation = subscription_generation_++;
        // All failure-prone preparation, including BPF installation, is done.
        // The old queue is empty; its unread kernel requests retain prior allow
        // semantics. The new group was marked before this old group is closed.
        gate_ = std::move(candidate.replacement);
        if (audit_) {
            try {
                const auto timestamp = std::chrono::duration_cast<std::chrono::nanoseconds>(
                    PendingDecisions::Clock::now().time_since_epoch()).count();
                audit_->enqueue("{\"event\":\"fanotify_target_handover\",\"listener_pid\":" + std::to_string(getpid()) +
                    ",\"instance_ns\":" + std::to_string(instance_ns_) +
                    ",\"pid_namespace_inode\":" + std::to_string(gate_->pid_namespace_inode()) +
                    ",\"from_generation\":" + std::to_string(previous_generation) +
                    ",\"to_generation\":" + std::to_string(subscription_generation_) +
                    ",\"from_revision\":" + std::to_string(revision_) +
                    ",\"to_revision\":" + std::to_string(revision) + ",\"old_targets\":" + std::to_string(old_count) +
                    ",\"new_targets\":" + std::to_string(gate_->target_count()) +
                    ",\"retained_targets\":" + std::to_string(candidate.retained_targets) +
                    ",\"from_rebind_epoch\":" + std::to_string(options_.rebind_epoch) +
                    ",\"to_rebind_epoch\":" + std::to_string(candidate.options.rebind_epoch) +
                    ",\"next_request_id\":" + std::to_string(request_sequence_) + ",\"timestamp_ns\":" + std::to_string(timestamp) +
                    ",\"kernel_unread\":\"released_under_prior_allow\",\"individual_audit_complete\":false}\n");
            } catch (...) { audit_->note_drop(); }
        }
    }
    gate_->commit_reconfigure(candidate.options.decision, revision);
    options_ = std::move(candidate.options);
    revision_ = revision;
}
GateStats FanotifyMonitor::combined_stats() const
{
    auto stats = history_;
    accumulate(stats, gate_->stats());
    return stats;
}
void FanotifyMonitor::snapshot(management::Reply &reply) const { fill_fanotify_status(reply, options_, *gate_, combined_stats()); }
void FanotifyMonitor::report(std::ostream &out) const { write_gate_stats(out, options_.event, combined_stats()); }
