// SPDX-License-Identifier: MIT
// 每条回复的对象快照与服务实例；格式转换不解析路径或按 PID 查询进程。
#pragma once
#include "decisions.h"
#include "event_kind.h"
#include <string>
struct PermissionAuditIdentity {
    std::uint64_t instance_ns = 0;
    std::int32_t listener_pid = 0;
    std::uint32_t major = 0, minor = 0;
    std::uint64_t inode = 0;
    PermissionEvent event = PermissionEvent::open;
    // Namespace captured when creating the group; metadata.pid is a TGID in this coordinate.
    std::uint64_t pid_namespace_inode = 0;
};
std::string format_permission_decision(const PermissionAuditIdentity &identity, const PermissionRequest &request,
                                       Verdict verdict, PendingDecisions::Clock::time_point responded);
