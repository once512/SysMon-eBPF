// SPDX-License-Identifier: MIT
#pragma once
#include <string>
#include <vector>

// Pins active policy inodes until replacement; the owner must outlive BPF links.
class ProtectedFiles {
    std::vector<int> descriptors_;
public:
    ProtectedFiles() = default;
    ProtectedFiles(const ProtectedFiles &) = delete;
    ProtectedFiles &operator=(const ProtectedFiles &) = delete;
    ~ProtectedFiles();
    // Build a complete candidate, atomically replace outer-map slot 0, then release old pins.
    // Failure before the swap leaves the active map and pins untouched.
    void install(int map_fd, const std::vector<std::string> &paths);
};
