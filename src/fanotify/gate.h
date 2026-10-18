// SPDX-License-Identifier: MIT
// 权限门负责 group、目标 inode 和事件 FD 生命周期，并协调有界队列与可选的独立分析器。
// 成员按声明的逆序析构：group 先于 target 和 analyzer 释放，避免监听器关闭后仍等待分析清理。
#pragma once
#include "decisions.h"
#include "gate_stats.h"
#include "event_kind.h"
#include "analysis/client.h"
#include "audit.h"
class AuditSink;
#include <memory>
#include <cstdint>
#include <string>

// A single inode mark with bounded decisions and an optional external scanner.
class PermissionGate {
    // 析构按成员声明的逆序进行：先销毁 pending，再关闭 group，最后才回收分析进程；
    // 不要随意调换。
    std::unique_ptr<AnalysisClient> analyzer_; // Destroy only after group closure.
    OwnedFd target_; // Pin before marking; release after the fanotify group.
    OwnedFd group_;
    std::uint64_t mask_;
    bool requester_pidfd_;
    GateStats stats_;
    AuditSink *audit_; // 借用服务统一出口；不创建第二个 stdout 写线程。
    PermissionAuditIdentity audit_identity_;
    std::uint64_t revision_;
    PendingDecisions pending_;
    void respond(int fd, const PermissionRequest &request, Verdict verdict);
    void service_analysis();
public:
    PermissionGate(const std::string &path, DecisionConfig config,
                   PermissionEvent event = PermissionEvent::open,
                   const AnalyzerConfig &analyzer = {}, const std::string &policy_path = {},
                   AuditSink *audit = nullptr, std::uint64_t instance_ns = 0, std::uint64_t revision = 0,
                   bool requester_pidfd = false);
    PermissionGate(const PermissionGate &) = delete;
    PermissionGate &operator=(const PermissionGate &) = delete;
    // pending 的回复 lambda 捕获当前 this；
    // 若允许移动对象，回调可能继续访问旧地址。
    PermissionGate(PermissionGate &&) = delete; // The reply callback captures this.
    PermissionGate &operator=(PermissionGate &&) = delete;
    // Process at most one incoming event. False means poll timed out or was interrupted.
    // timeout_ms 是本轮等待上限，实际等待还受最近请求截止时间限制；
    // 返回 false 不表示分析器离线。
    bool poll_once(int timeout_ms);
    void validate_reconfigure(DecisionConfig config) const;
    void commit_reconfigure(DecisionConfig config, std::uint64_t revision) noexcept {
        pending_.commit_reconfigure(config);
        revision_ = revision;
    }
    void reconfigure(DecisionConfig config);
    // 先回复已交付请求并关闭 group，再停止分析器；在结束统计可能阻塞前释放内核未读等待。
    // 不依赖外层对象析构才能关闭 mark；调用后不再 poll/reconfigure。
    void shutdown();
    int target_fd() const { return target_.get(); } // Borrowed; never close or read.
    pid_t analyzer_pid() const { return analyzer_ ? analyzer_->pid() : -1; }
    // 这是监督器最近观测到的通信状态；
    // 查询不会主动 ping，进程刚刚死亡而尚未处理断连时可能仍显示在线。
    bool analyzer_online() const { return analyzer_ && analyzer_->online(); }
    std::size_t pending_count() const { return pending_.size(); }
    const GateStats &stats() const { return stats_; }
};
