// SPDX-License-Identifier: MIT
// 权限门负责 group、目标 inode 和事件 FD 生命周期，并协调有界队列与可选的独立分析器。
// 成员按声明的逆序析构：group 先于 target 和 analyzer 释放，避免监听器关闭后仍等待分析清理。
#pragma once
#include "decisions.h"
#include "gate_stats.h"
#include "event_kind.h"
#include "analysis/client.h"
#include <memory>
#include <cstdint>
#include <string>

// A single inode mark with bounded decisions and an optional external scanner.
class PermissionGate {
    std::unique_ptr<AnalysisClient> analyzer_; // Destroy only after group closure.
    OwnedFd target_; // Pin before marking; release after the fanotify group.
    OwnedFd group_;
    std::uint64_t mask_;
    GateStats stats_;
    PendingDecisions pending_;
    void respond(int fd, Verdict verdict);
    void service_analysis();
public:
    PermissionGate(const std::string &path, DecisionConfig config,
                   PermissionEvent event = PermissionEvent::open,
                   const AnalyzerConfig &analyzer = {}, const std::string &policy_path = {});
    PermissionGate(const PermissionGate &) = delete;
    PermissionGate &operator=(const PermissionGate &) = delete;
    PermissionGate(PermissionGate &&) = delete; // The reply callback captures this.
    PermissionGate &operator=(PermissionGate &&) = delete;
    // Process at most one incoming event. False means poll timed out or was interrupted.
    bool poll_once(int timeout_ms);
    void reconfigure(DecisionConfig config);
    void shutdown() { pending_.shutdown(); if (analyzer_) analyzer_->stop(); }
    int target_fd() const { return target_.get(); } // Borrowed; never close or read.
    pid_t analyzer_pid() const { return analyzer_ ? analyzer_->pid() : -1; }
    bool analyzer_online() const { return analyzer_ && analyzer_->online(); }
    std::size_t pending_count() const { return pending_.size(); }
    const GateStats &stats() const { return stats_; }
};
