// SPDX-License-Identifier: MIT
#pragma once
#include "config.h"
#include "owned_fd.h"
#include "management/protocol.h"
#include <chrono>
class DecoyProvider {
    using Clock = std::chrono::steady_clock;
    OwnedFd channel_, process_;
    pid_t pid_ = -1;
    std::uint32_t files_ = 0;
    Clock::time_point progress_ = Clock::now(), next_probe_ = progress_;
    std::uint64_t sequence_ = 0;
    management::ProviderError error_ = management::ProviderError::none;
    bool pending_ = false, failed_ = false;
    void reap() noexcept;
    void fail() noexcept;
    void stop() noexcept;
public:
    explicit DecoyProvider(const DecoyConfig &config);
    ~DecoyProvider();
    DecoyProvider(const DecoyProvider &) = delete;
    DecoyProvider &operator=(const DecoyProvider &) = delete;
    void poll_once() noexcept;
    void snapshot(management::Reply &reply) const;
};
