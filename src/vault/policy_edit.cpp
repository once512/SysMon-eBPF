// SPDX-License-Identifier: MIT
#include "policy_edit.h"
#include <algorithm>
#include <iomanip>
#include <set>
#include <sstream>
#include <stdexcept>
namespace vault {
Candidate edit_policy(const std::string &text, const Edit &edit,
                      const std::string &boot_id, std::uint64_t issued_ns)
{
    std::istringstream input(text);
    const auto original = parse_policy(input);
    Candidate candidate;
    // Any successful policy reload would renew this unrelated relative lease.
    // Refuse instead of silently granting fresh maintenance privileges.
    if (original.writer_lease_ms) throw std::runtime_error("Vault editing refuses writer-lease-ms policies: reload would renew unrelated maintenance access");
    if (original.revision == UINT64_MAX) throw std::runtime_error("Policy revision exhausted");
    std::set<std::uint64_t> removed;
    std::set<std::string> locked{edit.target};
    if (edit.action == Action::lock) {
        for (const auto &alias : edit.alias_targets) {
            if (std::find(original.vaults.begin(), original.vaults.end(), alias) == original.vaults.end())
                throw std::runtime_error("Lock alias must be an explicit vault path");
            locked.insert(alias);
        }
    }
    if (edit.action == Action::open || edit.action == Action::lock) {
        if (std::find(original.vaults.begin(), original.vaults.end(), edit.target) == original.vaults.end())
            throw std::runtime_error("Target must already be an explicit vault path");
    }
    for (const auto &session : original.vault_sessions) {
        if (edit.action == Action::open && session.id == edit.id)
            throw std::runtime_error("Session ID already configured");
        if ((edit.action == Action::close && session.id == edit.id) ||
            (edit.action == Action::lock && locked.count(session.target))) removed.insert(session.id);
    }
    if (edit.action == Action::close && removed.empty()) throw std::runtime_error("Session ID not configured");
    if (edit.action == Action::lock && removed.empty()) {
        candidate.text = text; candidate.policy = original; return candidate;
    }
    std::ostringstream output;
    // Preserve every unrelated line byte-for-byte, including its final newline.
    for (std::size_t begin = 0; begin < text.size();) {
        const auto end = text.find('\n', begin);
        const auto count = end == std::string::npos ? text.size() - begin : end - begin;
        const auto line = text.substr(begin, count);
        std::istringstream fields(line);
        std::string key; fields >> key;
        if (key == "revision") output << "revision " << original.revision + 1 << (end == std::string::npos ? "" : "\n");
        else if (key == "vault-session") {
            std::uint64_t id = 0; fields >> id;
            if (!removed.count(id)) output << line << (end == std::string::npos ? "" : "\n");
        } else output << line << (end == std::string::npos ? "" : "\n");
        if (end == std::string::npos) break;
        begin = end + 1;
    }
    if (edit.action == Action::open) {
        if (!output.str().empty() && output.str().back() != '\n') output << '\n';
        output << "vault-session " << edit.id << ' ' << std::quoted(edit.program) << ' ' << edit.uid
               << ' ' << std::quoted(edit.target) << ' ' << edit.mode << ' ' << edit.duration_ms
               << ' ' << boot_id << ' ' << issued_ns << '\n';
        candidate.session_id = edit.id;
    }
    candidate.text = output.str();
    std::istringstream check(candidate.text);
    candidate.policy = parse_policy(check); // Shared grammar and capacity limits.
    candidate.policy.source_digest = content_digest(candidate.text);
    if (edit.action == Action::open) {
        const auto &session = candidate.policy.vault_sessions.back();
        candidate.deadline = session.issued_boot_ns + static_cast<std::uint64_t>(session.duration_ms) * 1000000;
    }
    candidate.changed = true; candidate.removed = removed.size();
    return candidate;
}
}
