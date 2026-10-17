// SPDX-License-Identifier: MIT
// 把用户可读的事件名称映射到单一 fanotify 权限事件，避免将不同监控语义混为一谈。
#pragma once
#include <cstdint>
#include <string_view>

// 选择的是订阅/裁决入口，不是通用访问权限集合；
// 本原型每个 group 只选一种事件。
enum class PermissionEvent { open, access, exec };
PermissionEvent parse_permission_event(std::string_view text);
std::uint64_t permission_mask(PermissionEvent event);
const char *permission_name(PermissionEvent event);
