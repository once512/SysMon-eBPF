// SPDX-License-Identifier: MIT
#pragma once
#include <string>
#include <vector>

// Pins each inode until after the BPF links have been released.
class ProtectedFiles {
    std::vector<int> descriptors_;
public:
    ProtectedFiles() = default;
    ProtectedFiles(const ProtectedFiles &) = delete;
    ProtectedFiles &operator=(const ProtectedFiles &) = delete;
    ~ProtectedFiles();
    void install(int map_fd, const std::vector<std::string> &paths);
};
