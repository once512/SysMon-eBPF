// SPDX-License-Identifier: MIT
// 裁决状态机使用 steady_clock 避免系统时间调整；超时从用户态接收事件起算，不是从系统调用开始。
// 回复成功后才移除并关闭 FD；发生异常时由对象所有权负责回收，正常关闭会显式拒绝已交付请求。
#include "decisions.h"
#include "management/protocol.h"
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

void PendingDecisions::reconfigure(DecisionConfig config)
{
    // 空队列才允许替换统一配置，否则同一批旧请求的裁决、截止时间和回退可能被重载悄悄改变。
    if (!pending_.empty()) throw management::Error(management::Code::busy, "Policy reload requires an empty delivered-request queue; retry later");
    if (config.delay.count() < 0 || config.timeout.count() <= 0 || !config.max_pending || config.external != config_.external)
        throw std::invalid_argument("Invalid decision reconfiguration");
    config_ = config;
}

void PendingDecisions::submit(OwnedFd fd, Clock::time_point now)
{
    if (fd.get() < 0) throw std::invalid_argument("Cannot submit an invalid event FD");
    // 先兑现已经到期的旧请求，再判断容量；已超时条目不应继续占据用户态 pending 预算。
    process_due(now);
    if (pending_.size() >= config_.max_pending) {
        reply_(fd.get(), {config_.overload_allow, DecisionReason::capacity});
        return;
    }
    if (!next_id_) throw std::runtime_error("Analysis request ID exhausted");
    // 接收时间与递增 ID 一起保存；ID 不复用，避免过期或重复响应错误地命中新请求。
    pending_.push_back({std::move(fd), next_id_++, now});
    process_due(now);
}

void PendingDecisions::process_due(Clock::time_point now)
{
    // All requests share the same delay/timeout, so FIFO is also due-time order.
    // 固定配置下每个请求使用相同延迟/超时，因此 FIFO 头也是最先到期者；忙时禁止重载维持这一前提。
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
    // poll 的等待上限要同时受下一裁决截止时间限制；向上取整到毫秒，避免不足 1ms 时反复空转。
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
