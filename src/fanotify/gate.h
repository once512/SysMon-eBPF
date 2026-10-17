// SPDX-License-Identifier: MIT
#pragma once
#include "owned_fd.h"
#include <cstdint>
#include <string>

struct GateStats {
    std::uint64_t allowed = 0;
    std::uint64_t denied = 0;
    std::uint64_t overflow = 0;
};

// A single inode mark with an immediate static decision; no content scanning.
class PermissionGate {
    OwnedFd target_; // Pin before marking; release after the fanotify group.
    OwnedFd group_;
    bool allow_;
    GateStats stats_;
public:
    PermissionGate(const std::string &path, bool allow);
    // Process at most one event. False means poll timed out or was interrupted.
    bool poll_once(int timeout_ms);
    const GateStats &stats() const { return stats_; }
};
