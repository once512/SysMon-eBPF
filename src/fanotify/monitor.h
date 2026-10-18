// SPDX-License-Identifier: MIT
// fanotify 模块对象：固定监听资源，准备可失败的候选，提供无异常提交和状态填充。
#pragma once
#include "gate.h"
#include <iosfwd>
#include "options.h"
#include "policy_config.h"
#include "management/protocol.h"
class FanotifyMonitor {
    FanotifyOptions options_;
    PermissionGate gate_;
public:
    FanotifyMonitor(FanotifyOptions options, const std::string &policy_path, AuditSink *audit,
                    std::uint64_t instance_ns, std::uint64_t revision);
    FanotifyOptions prepare(const PolicyConfig &candidate) const;
    void commit(FanotifyOptions candidate, std::uint64_t revision) noexcept;
    void poll_once(int timeout_ms) { gate_.poll_once(timeout_ms); }
    int target_fd() const { return gate_.target_fd(); }
    void snapshot(management::Reply &reply) const;
    void shutdown() { gate_.shutdown(); }
    void report(std::ostream &out) const;
};
