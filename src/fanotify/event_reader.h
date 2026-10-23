// SPDX-License-Identifier: MIT
#pragma once
#include "metadata.h"
#include "decisions.h"
#include "owned_fd.h"
#include <array>
#include <map>
#include <memory>
// Static decisions need identity, not a readable event file in the main
// process. Keep real event FDs in an isolated reader and use local eventfd
// handles in PendingDecisions. Kernel replies use the reader's original token.
class EventReader {
    struct Token { std::uint64_t sequence; int kernel_fd; };
    OwnedFd channel_;
    int slot_ = -1;
    bool pidfd_mode_;
    std::uint64_t next_sequence_ = 1;
    std::map<int, Token> tokens_;
    std::array<Token, 4097> releases_{};
    std::size_t release_head_ = 0, release_count_ = 0;
public:
    struct Event { PermissionMetadata metadata; PermissionObject object; };
    EventReader(int group, bool pidfd_mode);
    ~EventReader();
    EventReader(const EventReader &) = delete;
    EventReader &operator=(const EventReader &) = delete;
    int fd() const { return channel_.get(); }
    void flush();
    std::optional<Event> receive();
    int kernel_fd(int handle) const;
    void release(int handle);
    void stop() noexcept;
    static void reap() noexcept;
};
