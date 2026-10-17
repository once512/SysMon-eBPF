// SPDX-License-Identifier: MIT
#pragma once
#include <cstdint>
#include <istream>
#include <string>
#include <vector>

struct PolicyConfig {
    std::uint64_t revision = 0;
    std::vector<std::string> paths;
};
// Versioned, bounded text format. Parsing performs no filesystem changes.
PolicyConfig parse_policy(std::istream &input);
// Pins and reads one root-owned, non-writable-by-others regular file (no symlinks).
PolicyConfig load_policy(const std::string &path);
