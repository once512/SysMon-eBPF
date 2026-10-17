// SPDX-License-Identifier: MIT
#include "event_kind.h"
#include <stdexcept>
#include <sys/fanotify.h>

PermissionEvent parse_permission_event(std::string_view text)
{
    if (text == "open") return PermissionEvent::open;
    if (text == "access") return PermissionEvent::access;
    if (text == "exec") return PermissionEvent::exec;
    throw std::invalid_argument("--event requires open|access|exec");
}
std::uint64_t permission_mask(PermissionEvent event)
{
    switch (event) {
    case PermissionEvent::open: return FAN_OPEN_PERM;
    case PermissionEvent::access: return FAN_ACCESS_PERM;
    case PermissionEvent::exec: return FAN_OPEN_EXEC_PERM;
    }
    throw std::invalid_argument("Invalid permission event");
}
const char *permission_name(PermissionEvent event)
{
    switch (event) {
    case PermissionEvent::open: return "open";
    case PermissionEvent::access: return "access";
    case PermissionEvent::exec: return "exec";
    }
    throw std::invalid_argument("Invalid permission event");
}
