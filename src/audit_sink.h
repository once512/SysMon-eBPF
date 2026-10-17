// SPDX-License-Identifier: MIT
// 审计出口拥有独立输出引用和 I/O 线程；生产者只尝试入队，绝不在策略事件循环等待输出 FD。
#pragma once
#include <secmon/audit_limits.h>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
struct AuditStats {
    std::uint64_t written = 0;
    std::uint64_t dropped = 0;
    std::uint64_t invalid = 0;
    std::uint32_t queued = 0;
    int output_errno = 0;
};
class AuditSink {
    struct State;
    std::unique_ptr<State> state_;
public:
    explicit AuditSink(int output_fd = 1, std::size_t records = SECMON_AUDIT_MAX_RECORDS,
                       std::size_t bytes = SECMON_AUDIT_MAX_BYTES);
    ~AuditSink();
    AuditSink(const AuditSink &) = delete;
    AuditSink &operator=(const AuditSink &) = delete;
    bool enqueue(std::string record) noexcept;
    void note_invalid() noexcept;
    void note_drop() noexcept;
    AuditStats stats() const;
    // 正常退出给非阻塞出口最多 200ms 排空；剩余条目计入 dropped，不无限等待无读者管道。
    void shutdown();
};
