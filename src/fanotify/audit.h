// SPDX-License-Identifier: MIT
// 固定单目标与服务实例；格式转换不解析路径、不读取文件或按 PID 查询进程。
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
};
std::string format_permission_decision(const PermissionAuditIdentity &identity, const PermissionRequest &request,
                                       Verdict verdict, PendingDecisions::Clock::time_point responded);
