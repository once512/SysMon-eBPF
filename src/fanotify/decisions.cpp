// SPDX-License-Identifier: MIT
#include "decisions.h"
#include <algorithm>
#include <stdexcept>
#include <utility>

PendingDecisions::PendingDecisions(DecisionConfig config, Reply reply)
    : config_(config), reply_(std::move(reply))
{
    if (config_.delay.count() < 0 || config_.timeout.count() <= 0 ||
        config_.max_pending == 0 || !reply_)
        throw std::invalid_argument("Invalid pending decision configuration");
}

void PendingDecisions::submit(OwnedFd fd, Clock::time_point now)
{
    if (fd.get() < 0) throw std::invalid_argument("Cannot submit an invalid event FD");
    process_due(now);
    if (pending_.size() >= config_.max_pending) {
        reply_(fd.get(), {config_.overload_allow, DecisionReason::capacity});
        return;
    }
    if (!next_id_) throw std::runtime_error("Analysis request ID exhausted");
    pending_.push_back({std::move(fd), next_id_++, now});
    process_due(now);
}

void PendingDecisions::process_due(Clock::time_point now)
{
    // All requests share the same delay/timeout, so FIFO is also due-time order.
    while (!pending_.empty()) {
        const auto received = pending_.front().received;
        // Expiration wins, including when a late wakeup passes both timestamps.
        if (now >= received + config_.timeout)
            reply_(pending_.front().fd.get(), {config_.timeout_allow, DecisionReason::timeout});
        else if (!config_.external && now >= received + config_.delay)
            reply_(pending_.front().fd.get(), {config_.allow, DecisionReason::policy});
        else break;
        pending_.pop_front(); // Close only after the reply succeeds.
    }
}

void PendingDecisions::shutdown()
{
    while (!pending_.empty()) {
        reply_(pending_.front().fd.get(), {false, DecisionReason::shutdown});
        pending_.pop_front();
    }
}

int PendingDecisions::poll_timeout(int maximum_ms, Clock::time_point now) const
{
    if (maximum_ms < 0) throw std::invalid_argument("Poll timeout must be bounded");
    if (pending_.empty()) return maximum_ms;
    const auto due = pending_.front().received + (config_.external ? config_.timeout : std::min(config_.delay, config_.timeout));
    if (due <= now) return 0;
    // Round up: a fractional millisecond must not cause a busy wait.
    const auto remaining = std::chrono::ceil<std::chrono::milliseconds>(due - now).count();
    return static_cast<int>(std::min<long long>(maximum_ms, remaining));
}

std::optional<PendingDecisions::ReadyRequest> PendingDecisions::next_request() const
{
    if (pending_.empty() || !config_.external) return std::nullopt;
    return ReadyRequest{pending_.front().id, pending_.front().fd.get()};
}
bool PendingDecisions::contains(std::uint64_t id) const
{
    return std::any_of(pending_.begin(), pending_.end(), [id](const auto &request) { return request.id == id; });
}
bool PendingDecisions::complete(std::uint64_t id, bool allow, bool error, Clock::time_point now)
{
    process_due(now);
    const auto found = std::find_if(pending_.begin(), pending_.end(),
                                   [id](const auto &request) { return request.id == id; });
    if (found == pending_.end()) return false;
    reply_(found->fd.get(), {error ? config_.analyzer_error_allow : allow,
                           error ? DecisionReason::analyzer_error : DecisionReason::analysis});
    pending_.erase(found);
    return true;
}
void PendingDecisions::fail_analysis()
{
    while (!pending_.empty()) {
        reply_(pending_.front().fd.get(), {config_.analyzer_error_allow, DecisionReason::analyzer_error});
        pending_.pop_front();
    }
}
