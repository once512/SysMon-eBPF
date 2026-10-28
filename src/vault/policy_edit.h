// SPDX-License-Identifier: MIT
#pragma once
#include "policy_config.h"
namespace vault {
enum class Action { open, close, lock };
struct Edit {
    explicit Edit(Action value = Action::open) : action(value) {}
    Action action;
    std::uint64_t id = 0;
    std::string program, target, mode;
    std::uint32_t uid = 0;
    unsigned duration_ms = 0;
    std::vector<std::string> alias_targets; // lock: configured vault paths sharing the selected inode.
};
struct Candidate {
    std::string text;
    PolicyConfig policy;
    std::uint64_t session_id = 0, deadline = 0;
    unsigned removed = 0;
    bool changed = false;
};
Candidate edit_policy(const std::string &text, const Edit &edit,
                      const std::string &boot_id, std::uint64_t issued_ns);
}
