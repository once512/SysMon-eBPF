// SPDX-License-Identifier: MIT
// fanotify 模块对象：准备独立候选资源，在允许的旧裁决下无异常切换固定目标集合。
#pragma once
#include "gate.h"
#include <iosfwd>
#include "options.h"
#include "policy_config.h"
#include "management/protocol.h"
class FanotifyMonitor {
    std::uint64_t request_sequence_ = 1; // Outlives all gates; never reset on handover.
    std::string policy_path_;
    AuditSink *audit_;
    std::uint64_t instance_ns_;
    std::uint64_t revision_;
    bool requester_pidfd_;
    FanotifyOptions options_;
    std::unique_ptr<PermissionGate> gate_;
    GateStats history_;
    GateStats combined_stats() const;
public:
    struct Prepared {
        FanotifyOptions options;
        std::unique_ptr<PermissionGate> replacement;
        std::size_t retained_targets = 0;
    };
    FanotifyMonitor(FanotifyOptions options, const std::string &policy_path, AuditSink *audit,
                    std::uint64_t instance_ns, std::uint64_t revision, bool requester_pidfd = false);
    FanotifyMonitor(const FanotifyMonitor &) = delete;
    FanotifyMonitor &operator=(const FanotifyMonitor &) = delete;
    FanotifyMonitor(FanotifyMonitor &&) = delete;
    FanotifyMonitor &operator=(FanotifyMonitor &&) = delete;
    Prepared prepare(const PolicyConfig &candidate);
    void commit(Prepared candidate, std::uint64_t revision) noexcept;
    void poll_once(int timeout_ms) { gate_->poll_once(timeout_ms); }
    const std::vector<int> &target_fds() const { return gate_->target_fds(); }
    void snapshot(management::Reply &reply) const;
    void shutdown() { gate_->shutdown(); }
    void report(std::ostream &out) const;
};
