// SPDX-License-Identifier: MIT
#pragma once
#include "decisions.h"
#include "event_kind.h"
#include "analysis/client.h"
#include <memory>
#include <cstdint>
#include <string>

struct GateStats {
    std::uint64_t allowed = 0;
    std::uint64_t denied = 0;
    std::uint64_t overflow = 0;
    std::uint64_t timed_out = 0;
    std::uint64_t overloaded = 0;
    std::uint64_t shutdown_denied = 0;
    std::uint64_t analyzed = 0;
    std::uint64_t analysis_denied = 0;
    std::uint64_t analyzer_error = 0;
    std::uint64_t analyzer_failures = 0;
    std::size_t peak_pending = 0;
};

// A single inode mark with bounded deferred decisions; no content scanning.
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
                   const AnalyzerConfig &analyzer = {});
    PermissionGate(const PermissionGate &) = delete;
    PermissionGate &operator=(const PermissionGate &) = delete;
    PermissionGate(PermissionGate &&) = delete; // The reply callback captures this.
    PermissionGate &operator=(PermissionGate &&) = delete;
    // Process at most one incoming event. False means poll timed out or was interrupted.
    bool poll_once(int timeout_ms);
    void shutdown() { pending_.shutdown(); if (analyzer_) analyzer_->stop(); }
    pid_t analyzer_pid() const { return analyzer_ ? analyzer_->pid() : -1; }
    const GateStats &stats() const { return stats_; }
};
