// SPDX-License-Identifier: MIT
#pragma once
#include <cstdint>
#include <string_view>

enum class PermissionEvent { open, access, exec };
PermissionEvent parse_permission_event(std::string_view text);
std::uint64_t permission_mask(PermissionEvent event);
const char *permission_name(PermissionEvent event);
