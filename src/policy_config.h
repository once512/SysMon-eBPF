// SPDX-License-Identifier: MIT
#pragma once
#include <cstdint>
#include <istream>
#include <string>
#include <vector>
#include <optional>

struct FanotifyPolicy {
    std::string path;
    std::string event = "open";
    std::string decision; // Required for a static backend; empty with analyzer.
    std::string analyzer;
    std::string marker;
    unsigned int scan_limit = 65536;
    unsigned int delay_ms = 0;
    unsigned int timeout_ms = 250;
    unsigned int max_pending = 64;
    bool timeout_allow = false;
    bool overload_allow = false;
    bool analyzer_error_allow = false;
};
struct PolicyConfig {
    std::uint64_t revision = 0;
    std::optional<FanotifyPolicy> fanotify;
    std::vector<std::string> paths;
};
// Versioned, bounded text format. Parsing performs no filesystem changes.
PolicyConfig parse_policy(std::istream &input);
// Pins and reads one root-owned, non-writable-by-others regular file (no symlinks).
// forbidden_inode_fd prevents a fanotify listener from opening its own marked inode.
PolicyConfig load_policy(const std::string &path, int forbidden_inode_fd = -1);
