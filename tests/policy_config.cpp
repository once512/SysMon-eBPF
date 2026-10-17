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
    for (const auto *text : {"", "version 2\nrevision 1", "version 1", "revision 1",
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
    std::cout << "PASS policy syntax, limits, revisions and quoted paths\n";
}
