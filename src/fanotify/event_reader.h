// SPDX-License-Identifier: MIT
#pragma once
#include "metadata.h"
#include "decisions.h"
#include "owned_fd.h"
#include <array>
#include <chrono>
#include <map>
#include <memory>
// Keep real event FDs in an isolated reader and use local eventfd handles
// in PendingDecisions. Analysis files travel directly to the worker. Kernel
// replies use the reader's original token; the main process never closes a file.
class EventReader {
    struct Token { std::uint64_t sequence; int kernel_fd; };
    struct Command { Token token; std::uint64_t request_id; };
    OwnedFd channel_;
    int slot_ = -1;
    bool pidfd_mode_;
    std::uint64_t next_sequence_ = 1;
    std::map<int, Token> tokens_;
    std::array<Command, 4099> commands_{};
    std::size_t command_head_ = 0, command_count_ = 0;
    using Clock = std::chrono::steady_clock;
    Clock::time_point last_progress_ = Clock::now(), next_probe_ = last_progress_;
    std::uint64_t probe_id_ = 0;
    bool probe_pending_ = false;
public:
    struct Event { PermissionMetadata metadata; PermissionObject object; std::uint64_t dispatch_error = 0; bool progress = false; };
    EventReader(int group, bool pidfd_mode, int analyzer_channel = -1);
    ~EventReader();
    EventReader(const EventReader &) = delete;
    EventReader &operator=(const EventReader &) = delete;
    int fd() const { return channel_.get(); }
    pid_t pid() const;
    std::uint64_t progress_age_ms() const;
    void flush();
    std::optional<Event> receive();
    int kernel_fd(int handle) const;
    void release(int handle);
    void dispatch(int handle, std::uint64_t request_id);
    void stop() noexcept;
    static void reap() noexcept;
};
