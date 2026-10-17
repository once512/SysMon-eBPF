// SPDX-License-Identifier: MIT
#pragma once
#include "decisions.h"
#include <cstdint>
#include <string>

struct GateStats {
    std::uint64_t allowed = 0;
    std::uint64_t denied = 0;
    std::uint64_t overflow = 0;
    std::uint64_t timed_out = 0;
    std::uint64_t overloaded = 0;
    std::uint64_t shutdown_denied = 0;
    std::size_t peak_pending = 0;
};

// A single inode mark with bounded deferred decisions; no content scanning.
class PermissionGate {
    OwnedFd target_; // Pin before marking; release after the fanotify group.
    OwnedFd group_;
    GateStats stats_;
    PendingDecisions pending_;
    void respond(int fd, Verdict verdict);
public:
    PermissionGate(const std::string &path, DecisionConfig config);
    PermissionGate(const PermissionGate &) = delete;
    PermissionGate &operator=(const PermissionGate &) = delete;
    PermissionGate(PermissionGate &&) = delete; // The reply callback captures this.
    PermissionGate &operator=(PermissionGate &&) = delete;
    // Process at most one incoming event. False means poll timed out or was interrupted.
    bool poll_once(int timeout_ms);
    void shutdown() { pending_.shutdown(); }
    const GateStats &stats() const { return stats_; }
};
