// SPDX-License-Identifier: MIT
// 只管理已经从内核读出的事件：持有事件 FD、接收时间与请求 ID，不代表内核队列的长度或容量。
// 静态延迟用于实验；外部模式把实际分析交给独立进程，本队列仍负责截止时间和回退。
#pragma once
#include "owned_fd.h"
#include "requester.h"
#include "analysis/protocol.h"
#include <chrono>
#include <cstddef>
#include <deque>
#include <functional>
#include <cstdint>
#include <optional>

struct DecisionConfig {
    bool allow = false;
    std::chrono::milliseconds delay{0};
    std::chrono::milliseconds timeout{250};
    std::size_t max_pending = 64;
    bool timeout_allow = false;
    bool overload_allow = false;
    bool external = false;
    bool analyzer_error_allow = false;
};
enum class DecisionReason { policy, timeout, capacity, shutdown, analysis, analyzer_error, reader_error };
struct Verdict {
    bool allow;
    DecisionReason reason;
    analysis::ScanError scan_error = analysis::ScanError::none;
    int scan_errno = 0;
};

// 身份和版本在接收时固定；不通过可能复用的 PID 在回复时重建主体。
struct PermissionObject {
    std::uint32_t major = 0, minor = 0;
    std::uint64_t inode = 0;
};
struct PermissionRequest {
    std::uint64_t id;
    std::uint64_t revision;
    std::int32_t requester_pid;
    std::chrono::steady_clock::time_point received;
    ProcessIdentity process{};
    PermissionObject object{};
};

// Owns only events already delivered by the kernel, never the kernel queue.
// The delay simulates deferred analysis; no file content is opened or read.
class PendingDecisions {
public:
    using Clock = std::chrono::steady_clock;
    using Reply = std::function<void(int, const PermissionRequest &, Verdict)>;
private:
    // Request 持有 FD、不可复用的请求号和接收时刻；
    // 数字 PID 不参与 fanotify 回复定位。
    struct Request {
        OwnedFd fd;
        ProcessReference process;
        PermissionRequest context;
    };
    DecisionConfig config_;
    Reply reply_;
    std::deque<Request> pending_;
    std::uint64_t local_next_id_ = 1;
    std::uint64_t *next_id_;
public:
    PendingDecisions(DecisionConfig config, Reply reply, std::uint64_t *request_sequence = nullptr);
    PendingDecisions(const PendingDecisions &) = delete;
    PendingDecisions &operator=(const PendingDecisions &) = delete;
    PendingDecisions(PendingDecisions &&) = delete;
    PendingDecisions &operator=(PendingDecisions &&) = delete;
    // Reject busy queues so already-delivered requests retain their original contract.
    void validate_reconfigure(DecisionConfig config) const;
    // 仅供协调器在验证后、同一事件循环内调用；纯值赋值，不再检查或分配。
    void commit_reconfigure(DecisionConfig config) noexcept { config_ = config; }
    void reconfigure(DecisionConfig config);
    void submit(OwnedFd fd, Clock::time_point now, std::int32_t requester_pid = 0, std::uint64_t revision = 0,
                ProcessReference process = {}, PermissionObject object = {});
    struct ReadyRequest { std::uint64_t id; int fd; };
    // 返回的是借用视图；
    // 调用者不得跨越队列完成/超时后继续把其中的裸 FD 当成有效请求。
    std::optional<ReadyRequest> next_request() const;
    bool contains(std::uint64_t id) const;
    bool complete(std::uint64_t id, bool allow, bool error, Clock::time_point now,
                  analysis::ScanError scan_error = analysis::ScanError::none, int scan_errno = 0);
    void fail_analysis();
    // An unavailable event transport never grants a delivered permission.
    void fail_reader();
    // No verdict is invented when an actual kernel write cannot be confirmed.
    std::size_t abandon() noexcept { const auto count=pending_.size(); pending_.clear(); return count; }
    void process_due(Clock::time_point now);
    // Reply deny to delivered requests before a graceful group shutdown.
    void shutdown();
    int poll_timeout(int maximum_ms, Clock::time_point now) const;
    std::size_t size() const { return pending_.size(); }
};
