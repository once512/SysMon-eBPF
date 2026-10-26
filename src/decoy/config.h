// SPDX-License-Identifier: MIT
#pragma once
#include <algorithm>
#include <string>
#include <vector>
inline bool valid_decoy_name(const std::string &name)
{
    if (name.empty() || name.size() > 255 || name == "." || name == "..") return false;
    return std::all_of(name.begin(), name.end(), [](unsigned char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
               (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
    });
}
struct DecoyConfig {
    std::string executable, mountpoint;
    std::vector<std::string> files;
    bool allow_other = false;
    bool enabled() const { return !executable.empty(); }
};
