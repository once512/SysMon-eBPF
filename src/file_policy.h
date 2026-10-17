// SPDX-License-Identifier: MIT
// 文件策略的资源所有者：固定当前策略的 inode，并负责候选 Map 准备和完整替换。
// 对象需比 BPF 链接活得更久；重载成功时旧策略的句柄可以释放，失败时保留原集合。
#pragma once
#include <string>
#include <vector>
#include "policy_config.h"

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
    void install(int map_fd, const PolicyConfig &policy);
};
