// SPDX-License-Identifier: MIT
// 单一配置格式：revision 负责重载顺序，不要求格式版本；旧 version 字段和非法参数均拒绝。
#include "policy_config.h"
#include <sstream>
#include <stdexcept>
#include <iostream>

static void require(bool value) { if (!value) throw std::runtime_error("policy parser assertion"); }
static void reject(const std::string &text) {
    std::istringstream input(text);
    try { (void)parse_policy(input); } catch (const std::runtime_error &) { return; }
    throw std::runtime_error("invalid policy accepted");
}
int main() {
    std::istringstream input("# sample\nrevision 18446744073709551615\nprotect \"/path with spaces\"\nprotect \"/quote\\\"file\"\n");
    auto policy = parse_policy(input);
    require(policy.revision == UINT64_MAX && policy.paths.size() == 2);
    require(policy.paths[0] == "/path with spaces" && policy.paths[1] == "/quote\"file");
    std::istringstream empty("revision 1\n");
    require(parse_policy(empty).paths.empty());
    for (const auto *text : {"", "protect \"/a\"", "revision 0", "revision -1", "revision +1",
            "revision 18446744073709551616", "revision 1x", "revision 1\nrevision 2",
            "revision 1\nprotect /a", "revision 1\nprotect \"relative\"",
            "revision 1\nprotect \"/a", "revision 1\nunknown 1", "revision 1 extra",
            "revision 1\nprotect \"/a\" x", "revision 1\nprotect \"/a\"\nprotect \"/a\""}) reject(text);
    for (const auto *version : {"1", "2", "3", "999"})
        reject(std::string("version ") + version + "\nrevision 1\n");
    const std::string prefix = "revision 1\n#";
    std::istringstream exact(prefix + std::string(65536 - prefix.size(), 'x'));
    require(parse_policy(exact).revision == 1);
    reject(prefix + std::string(65536, 'x'));
    reject(std::string("revision 1\nprotect \"/a") + '\0' + "b\"\n");
    std::string many = "revision 1\n";
    for (int i = 0; i < 257; ++i) many += "protect \"/file" + std::to_string(i) + "\"\n";
    reject(many);
    std::istringstream unified("revision 7\nprotect \"/bpf\"\nfanotify-file \"/gate\"\nfanotify-decision allow\nfanotify-delay-ms 4\nfanotify-timeout-ms 900\nfanotify-max-pending 3\nfanotify-event access\nfanotify-timeout-decision allow\nfanotify-overload-decision deny\n");
    auto combined = parse_policy(unified);
    require(combined.fanotify && combined.paths.size() == 1 && combined.revision == 7);
    require(combined.fanotify->event == "access" && combined.fanotify->delay_ms == 4 &&
            combined.fanotify->timeout_ms == 900 && combined.fanotify->max_pending == 3 && combined.fanotify->timeout_allow);
    const std::string base = "revision 1\nfanotify-file \"/gate\"\n";
    for (const auto *tail : {"", "fanotify-decision maybe", "fanotify-decision allow\nfanotify-decision deny",
            "fanotify-decision deny\nfanotify-event read", "fanotify-decision deny\nfanotify-timeout-decision maybe",
            "fanotify-decision deny\nfanotify-overload-decision maybe", "fanotify-decision allow\nfanotify-timeout-ms 0",
            "fanotify-decision deny\nfanotify-max-pending 4097", "fanotify-decision deny\nfanotify-delay-ms -1",
            "fanotify-decision deny\nfanotify-scan-limit-bytes 1", "fanotify-decision deny\nfanotify-error-decision allow",
            "fanotify-analyzer \"/worker\"", "fanotify-analyzer \"/worker\"\nfanotify-marker \"x\"\nfanotify-delay-ms 0",
            "fanotify-analyzer \"/worker\"\nfanotify-marker \"x\"\nfanotify-decision deny", "fanotify-unknown x"}) reject(base + tail);
    reject("revision 1\nfanotify-decision deny");
    std::istringstream analyzer(base + "fanotify-analyzer \"/worker\"\nfanotify-marker \"BLOCK\"\nfanotify-scan-limit-bytes 99\nfanotify-error-decision allow");
    auto analyzed = parse_policy(analyzer);
    require(analyzed.fanotify && analyzed.fanotify->scan_limit == 99 && analyzed.fanotify->analyzer_error_allow);
    std::istringstream writer(base + "fanotify-decision deny\nprotect \"/data\"\nallow-writer \"/program\" 65534\n");
    auto authorized = parse_policy(writer);
    require(authorized.fanotify && authorized.paths.size() == 1 && authorized.writers.size() == 1);
    require(authorized.writers[0].path == "/program" && authorized.writers[0].euid == 65534);
    for (const auto *tail : {"", "-1", "+1", "4294967295", "4294967296", "1x", "1 extra"})
        reject(std::string("revision 1\nallow-writer \"/exe\" ") + tail);
    reject("revision 1\nallow-writer /exe 0");
    reject("revision 1\nallow-writer \"relative\" 0");
    reject("revision 1\nallow-writer \"/exe\" 0\nallow-writer \"/exe\" 1");
    std::string writers = "revision 1\n";
    for (int i = 0; i < 65; ++i) writers += "allow-writer \"/exe" + std::to_string(i) + "\" 0\n";
    reject(writers);
    std::istringstream maximum(writers.substr(0, writers.rfind("allow-writer")));
    require(parse_policy(maximum).writers.size() == 64);
    std::istringstream largest_uid("revision 1\nallow-writer \"/exe\" 4294967294\n");
    require(parse_policy(largest_uid).writers[0].euid == 4294967294U);
    std::cout << "PASS single policy format, revisions, combined features and strict boundaries\n";
}
