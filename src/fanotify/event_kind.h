// SPDX-License-Identifier: MIT
// 把用户可读的事件名称映射到单一 fanotify 权限事件，避免将不同监控语义混为一谈。
#pragma once
#include <cstdint>
#include <string_view>

enum class PermissionEvent { open, access, exec };
PermissionEvent parse_permission_event(std::string_view text);
std::uint64_t permission_mask(PermissionEvent event);
const char *permission_name(PermissionEvent event);
