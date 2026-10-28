// SPDX-License-Identifier: MIT
// Root administration workflow; kernel authorization remains in the one policy.
#include "policy_edit.h"
#include "policy_file.h"
#include "boot_clock.h"
#include "control_client.h"
#include "policy/fields.h"
#include "cached_inode.h"
#include <cerrno>
#include <iostream>
#include <map>
#include <sstream>
#include <string_view>
#include <sys/random.h>
#include <unistd.h>
namespace {
struct Options {
    std::string command, policy, socket;
    std::uint64_t expected = 0;
    vault::Edit edit{vault::Action::open};
};
void usage()
{
    std::cout << "Usage: secmon-vaultctl status --policy ABS_PATH --socket ABS_PATH\n"
                 "       secmon-vaultctl open --policy ABS_PATH --socket ABS_PATH [--expect-revision N]\n"
                 "         --program ABS_PATH --uid UID --target ABS_PATH --mode read|read-write --duration-ms 100..3600000\n"
                 "       secmon-vaultctl close --policy ABS_PATH --socket ABS_PATH [--expect-revision N] --id N\n"
                 "       secmon-vaultctl lock --policy ABS_PATH --socket ABS_PATH [--expect-revision N] --target ABS_PATH\n"
                 "Root-only atomic policy editing and verified reload. Policy must be mode 0600 in a trusted root directory.\n"
                 "open prints a random session ID. lock removes sessions for the target and its configured inode aliases.\n"
                 "Exit 0: confirmed result; 1: failed/rejected; 2: usage; 3: publication/activation uncertain.\n";
}
Options options(int argc, char **argv)
{
    if (argc < 2) throw std::invalid_argument("Require status, open, close or lock; use --help");
    Options result; result.command = argv[1];
    if (result.command != "status" && result.command != "open" && result.command != "close" && result.command != "lock")
        throw std::invalid_argument("Unknown vault command");
    std::map<std::string, std::string> fields;
    for (int i = 2; i < argc; ++i) {
        const std::string name(argv[i]);
        if (i + 1 == argc || !fields.emplace(name, argv[++i]).second) throw std::invalid_argument("Duplicate or incomplete option");
    }
    auto take = [&](const std::string &name) {
        const auto it = fields.find(name);
        if (it == fields.end()) throw std::invalid_argument("Missing " + name);
        auto value = it->second; fields.erase(it); return value;
    };
    result.policy = take("--policy"); result.socket = take("--socket");
    if (result.policy.empty() || result.policy.front() != '/' || result.socket.empty() || result.socket.front() != '/')
        throw std::invalid_argument("Policy/socket must be absolute");
    if (fields.count("--expect-revision")) result.expected = policy_fields::number<std::uint64_t>(take("--expect-revision"), 1, UINT64_MAX);
    if (result.command == "open") {
        result.edit.program = take("--program"); result.edit.target = take("--target"); result.edit.mode = take("--mode");
        result.edit.uid = policy_fields::number<std::uint32_t>(take("--uid"), 0, UINT32_MAX - 1);
        result.edit.duration_ms = policy_fields::number<unsigned>(take("--duration-ms"), 100, 3600000);
        if (result.edit.program.empty() || result.edit.program.front() != '/' || result.edit.target.empty() || result.edit.target.front() != '/' ||
            (result.edit.mode != "read" && result.edit.mode != "read-write")) throw std::invalid_argument("Invalid program/target/mode");
    } else if (result.command == "close") {
        result.edit.action = vault::Action::close;
        result.edit.id = policy_fields::number<std::uint64_t>(take("--id"), 1, UINT64_MAX);
    } else if (result.command == "lock") {
        result.edit.action = vault::Action::lock; result.edit.target = take("--target");
        if (result.edit.target.empty() || result.edit.target.front() != '/') throw std::invalid_argument("Target must be absolute");
    }
    if (!fields.empty()) throw std::invalid_argument("Unknown or inapplicable option: " + fields.begin()->first);
    return result;
}
bool active(const management::Reply &reply, std::uint64_t instance, const PolicyConfig &policy)
{
    return reply.code == management::Code::ok && reply.instance_ns == instance && (reply.flags & management::configured) &&
        reply.revision == policy.revision && reply.source_digest == policy.source_digest;
}
std::uint64_t random_id()
{
    std::uint64_t id = 0;
    do {
        ssize_t count;
        do { count = getrandom(&id, sizeof(id), 0); } while (count < 0 && errno == EINTR);
        if (count != sizeof(id)) throw std::runtime_error("Cannot obtain random session ID");
    } while (!id);
    return id;
}
bool utf8(const std::string &input)
{
    for (std::size_t i = 0; i < input.size();) {
        const auto lead = static_cast<unsigned char>(input[i]);
        if (lead < 0x80) { ++i; continue; }
        const unsigned size = lead >= 0xc2 && lead <= 0xdf ? 2 :
            lead >= 0xe0 && lead <= 0xef ? 3 : lead >= 0xf0 && lead <= 0xf4 ? 4 : 0;
        if (!size || i + size > input.size()) return false;
        for (unsigned j = 1; j < size; ++j)
            if ((static_cast<unsigned char>(input[i+j]) & 0xc0) != 0x80) return false;
        const auto second = static_cast<unsigned char>(input[i+1]);
        if ((lead == 0xe0 && second < 0xa0) || (lead == 0xed && second >= 0xa0) ||
            (lead == 0xf0 && second < 0x90) || (lead == 0xf4 && second >= 0x90)) return false;
        i += size;
    }
    return true;
}
std::string json(const std::string &input)
{
    const bool valid_utf8 = utf8(input);
    constexpr char hex[] = "0123456789abcdef";
    std::string out = "\"";
    for (const unsigned char c : input) {
        if (c == '"' || c == '\\') { out += '\\'; out += c; }
        else if (c < 0x20 || (!valid_utf8 && c >= 0x7f)) { out += "\\u00"; out += hex[c >> 4]; out += hex[c & 15]; }
        else out += c;
    }
    return out + '"';
}
int applied(const vault::Candidate &candidate, const management::Reply &reply, bool recovered)
{
    std::cout << "{\"code\":\"" << (candidate.changed ? "applied" : "unchanged")
              << "\",\"revision\":" << reply.revision << ",\"session_id\":" << candidate.session_id
              << ",\"deadline_boot_ns\":" << candidate.deadline << ",\"removed_sessions\":" << candidate.removed
              << ",\"response_recovered\":" << (recovered ? "true" : "false")
              << ",\"status\":" << management::reply_json(reply) << "}\n";
    return 0;
}
int restore(vault::PolicyFile &file, const std::string &original, const vault::Candidate &candidate,
            const Options &options, const management::Reply &before, const PolicyConfig &old,
            const char *code)
{
    try {
        const auto observed = query_status(options.socket);
        if (!active(observed, before.instance_ns, old)) throw std::runtime_error("Active service changed during rejection");
        const auto current = file.read();
        if (current == candidate.text) file.replace(candidate.text, original);
        else if (current != original) throw std::runtime_error("Policy changed before rollback");
        std::cout << "{\"code\":\"" << code << "\",\"rolled_back\":true,\"status\":" << management::reply_json(observed) << "}\n";
        return 1;
    } catch (const std::exception &error) {
        std::cerr << "secmon-vaultctl: Cannot confirm/restore policy: " << error.what() << '\n';
        std::cout << "{\"code\":\"activation_unknown\",\"rolled_back\":false,\"candidate_revision\":" << candidate.policy.revision << "}\n";
        return 3;
    }
}
int run(Options options)
{
    if (geteuid() != 0) throw std::runtime_error("Vault administration requires root");
    vault::PolicyFile file(options.policy, options.command != "status");
    const auto original = file.read();
    std::istringstream input(original); auto old = parse_policy(input); old.source_digest = content_digest(original);
    const auto before = query_status(options.socket);
    const bool source_matches = active(before, before.instance_ns, old);
    const bool revision_matches = !options.expected || before.revision == options.expected;
    if (before.code != management::Code::ok || before.backend == management::Backend::fanotify)
        throw std::runtime_error("Require a configured BPF service");
    if (options.command != "status" && (!source_matches || !revision_matches))
        throw std::runtime_error("Policy file, active revision/digest or expected revision does not match a BPF service");
    const auto boot = secmon_clock::boot_id(); const auto now = secmon_clock::global_boot_ns();
    if (options.command == "status") {
        const char *code = !source_matches ? "policy_mismatch" : !revision_matches ? "unexpected_revision" : "ok";
        std::cout << "{\"code\":\"" << code << "\",\"revision\":" << old.revision
                  << ",\"source_matches\":" << (source_matches ? "true" : "false") << ",\"sessions\":[";
        bool first = true;
        for (const auto &session : old.vault_sessions) {
            const auto deadline = session.issued_boot_ns + static_cast<std::uint64_t>(session.duration_ms) * 1000000;
            if (!first) std::cout << ',';
            first = false;
            std::cout << "{\"id\":" << session.id << ",\"program\":" << json(session.program) << ",\"uid\":" << session.euid
                      << ",\"target\":" << json(session.target) << ",\"mode\":\"" << (session.access == 1 ? "read" : "read-write")
                      << "\",\"deadline_boot_ns\":" << deadline << ",\"live\":"
                      << (source_matches && session.boot_id == boot && session.issued_boot_ns <= now && now < deadline ? "true" : "false")
                      << ",\"time_valid\":" << (session.boot_id == boot && session.issued_boot_ns <= now && now < deadline ? "true" : "false") << '}';
        }
        std::cout << "],\"status\":" << management::reply_json(before) << "}\n";
        return source_matches && revision_matches ? 0 : 1;
    }
    std::vector<OwnedFd> alias_pins;
    if (options.command == "lock") {
        std::map<std::string, std::pair<dev_t, ino_t>> identities;
        for (const auto &path : old.vaults) {
            OwnedFd fd(open(path.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC));
            struct stat stat{};
            if (fd.get() < 0 || cached_inode_stat(fd.get(), &stat) || !S_ISREG(stat.st_mode))
                throw std::runtime_error("Cannot inspect vault aliases before lock");
            identities.emplace(path, std::make_pair(stat.st_dev, stat.st_ino));
            alias_pins.push_back(std::move(fd));
        }
        const auto selected = identities.find(options.edit.target);
        if (selected == identities.end()) throw std::runtime_error("Target must already be an explicit vault path");
        for (const auto &[path, identity] : identities)
            if (identity == selected->second) options.edit.alias_targets.push_back(path);
    }
    if (options.command == "open") options.edit.id = random_id();
    const auto candidate = vault::edit_policy(original, options.edit, boot, now);
    if (!candidate.changed) return applied(candidate, before, false);
    // Recheck the same live instance after preparing the candidate, before any
    // disk mutation. Other root editors/reloads must be serialized by operators.
    if (!active(query_status(options.socket), before.instance_ns, old)) throw std::runtime_error("Active policy changed before publication");
    try { file.replace(original, candidate.text); }
    catch (const std::exception &error) {
        std::cerr << "secmon-vaultctl: Policy publication failed: " << error.what() << '\n';
        return restore(file, original, candidate, options, before, old, "publication_failed");
    }
    management::Reply reply;
    try { reply = reload_policy(options.socket); }
    catch (const std::exception &error) {
        // A timed-out/lost reply does not prove rejection: preparation or commit
        // may still finish. Never restore an older policy based on this alone.
        std::cerr << "secmon-vaultctl: Reload response lost: " << error.what() << '\n';
        try {
            const auto observed = query_status(options.socket);
            if (active(observed, before.instance_ns, candidate.policy)) return applied(candidate, observed, true);
        } catch (...) {}
        std::cout << "{\"code\":\"activation_unknown\",\"rolled_back\":false,\"candidate_revision\":" << candidate.policy.revision << "}\n";
        return 3;
    }
    if (reply.code != management::Code::ok)
        return restore(file, original, candidate, options, before, old, management::code_name(reply.code));
    if (!active(reply, before.instance_ns, candidate.policy)) {
        std::cout << "{\"code\":\"activation_unknown\",\"rolled_back\":false,\"candidate_revision\":" << candidate.policy.revision << "}\n";
        return 3;
    }
    return applied(candidate, reply, false);
}
}
int main(int argc, char **argv)
{
    if (argc == 2 && std::string_view(argv[1]) == "--help") { usage(); return 0; }
    Options parsed;
    try { parsed = options(argc, argv); }
    catch (const std::exception &error) { std::cerr << "secmon-vaultctl: " << error.what() << '\n'; return 2; }
    try { return run(std::move(parsed)); }
    catch (const std::exception &error) {
        std::cerr << "secmon-vaultctl: " << error.what() << '\n';
        std::cout << "{\"code\":\"failed\"}\n"; return 1;
    }
}
