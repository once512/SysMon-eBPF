// SPDX-License-Identifier: MIT
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
    std::istringstream input("# sample\nversion 1\nrevision 18446744073709551615\nprotect \"/path with spaces\"\nprotect \"/quote\\\"file\"\n");
    auto policy = parse_policy(input);
    require(policy.revision == UINT64_MAX && policy.paths.size() == 2);
    require(policy.paths[0] == "/path with spaces" && policy.paths[1] == "/quote\"file");
    std::istringstream empty("revision 1\nversion 1\n");
    require(parse_policy(empty).paths.empty());
    for (const auto *text : {"", "version 3\nrevision 1", "version 1", "revision 1",
            "version 1\nrevision 0", "version 1\nrevision -1", "version 1\nrevision +1",
            "version 1\nrevision 18446744073709551616", "version 1\nrevision 1x",
            "version 1\nrevision 1\nrevision 2", "version 1\nversion 1\nrevision 1",
            "version 1\nrevision 1\nprotect /a", "version 1\nrevision 1\nprotect \"relative\"",
            "version 1\nrevision 1\nprotect \"/a", "version 1\nrevision 1\nunknown 1",
            "version 1 extra\nrevision 1", "version 1\nrevision 1\nprotect \"/a\" x",
            "version 1\nrevision 1\nprotect \"/a\"\nprotect \"/a\""}) reject(text);
    const std::string prefix = "version 1\nrevision 1\n#";
    std::istringstream exact(prefix + std::string(65536 - prefix.size(), 'x'));
    require(parse_policy(exact).revision == 1);
    reject(std::string("version 1\nrevision 1\n#") + std::string(65536, 'x'));
    reject(std::string("version 1\nrevision 1\nprotect \"/a") + '\0' + "b\"\n");
    std::string many = "version 1\nrevision 1\n";
    for (int i = 0; i < 257; ++i) many += "protect \"/file" + std::to_string(i) + "\"\n";
    reject(many);
    std::istringstream unified("version 2\nrevision 7\nprotect \"/bpf\"\nfanotify-file \"/gate\"\nfanotify-decision allow\nfanotify-delay-ms 4\nfanotify-timeout-ms 900\nfanotify-max-pending 3\nfanotify-event access\nfanotify-timeout-decision allow\nfanotify-overload-decision deny\n");
    auto combined = parse_policy(unified);
    require(combined.fanotify && combined.paths.size() == 1 && combined.revision == 7);
    require(combined.fanotify->event == "access" && combined.fanotify->delay_ms == 4 &&
            combined.fanotify->timeout_ms == 900 && combined.fanotify->max_pending == 3 && combined.fanotify->timeout_allow);
    const std::string base = "version 2\nrevision 1\nfanotify-file \"/gate\"\n";
    for (const auto *tail : {"", "fanotify-decision maybe", "fanotify-decision allow\nfanotify-decision deny",
            "fanotify-decision deny\nfanotify-event read", "fanotify-decision deny\nfanotify-timeout-decision maybe",
            "fanotify-decision deny\nfanotify-overload-decision maybe", "fanotify-decision allow\nfanotify-timeout-ms 0",
            "fanotify-decision deny\nfanotify-max-pending 4097", "fanotify-decision deny\nfanotify-delay-ms -1",
            "fanotify-decision deny\nfanotify-scan-limit-bytes 1", "fanotify-decision deny\nfanotify-error-decision allow",
            "fanotify-analyzer \"/worker\"", "fanotify-analyzer \"/worker\"\nfanotify-marker \"x\"\nfanotify-delay-ms 0",
            "fanotify-analyzer \"/worker\"\nfanotify-marker \"x\"\nfanotify-decision deny", "fanotify-unknown x"}) reject(base + tail);
    reject("version 1\nrevision 1\nfanotify-file \"/gate\"\nfanotify-decision deny");
    reject("version 2\nrevision 1\nfanotify-decision deny");
    std::istringstream analyzer(base + "fanotify-analyzer \"/worker\"\nfanotify-marker \"BLOCK\"\nfanotify-scan-limit-bytes 99\nfanotify-error-decision allow");
    auto analyzed = parse_policy(analyzer);
    require(analyzed.fanotify && analyzed.fanotify->scan_limit == 99 && analyzed.fanotify->analyzer_error_allow);
    std::cout << "PASS policy syntax, limits, revisions and quoted paths\n";
}
