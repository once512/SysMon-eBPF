// SPDX-License-Identifier: MIT
#pragma once
#include "owned_fd.h"
#include <chrono>
#include <cstddef>
#include <deque>
#include <functional>

struct DecisionConfig {
    bool allow = false;
    std::chrono::milliseconds delay{0};
    std::chrono::milliseconds timeout{250};
    std::size_t max_pending = 64;
    bool timeout_allow = false;
    bool overload_allow = false;
};
enum class DecisionReason { policy, timeout, capacity, shutdown };
struct Verdict {
    bool allow;
    DecisionReason reason;
};

// Owns only events already delivered by the kernel, never the kernel queue.
// The delay simulates deferred analysis; no file content is opened or read.
class PendingDecisions {
public:
    using Clock = std::chrono::steady_clock;
    using Reply = std::function<void(int, Verdict)>;
private:
    struct Request {
        OwnedFd fd;
        Clock::time_point received;
    };
    DecisionConfig config_;
    Reply reply_;
    std::deque<Request> pending_;
public:
    PendingDecisions(DecisionConfig config, Reply reply);
    PendingDecisions(const PendingDecisions &) = delete;
    PendingDecisions &operator=(const PendingDecisions &) = delete;
    void submit(OwnedFd fd, Clock::time_point now);
    void process_due(Clock::time_point now);
    // Reply deny to delivered requests before a graceful group shutdown.
    void shutdown();
    int poll_timeout(int maximum_ms, Clock::time_point now) const;
    std::size_t size() const { return pending_.size(); }
};
