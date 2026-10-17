// SPDX-License-Identifier: MIT
// 文件策略的资源所有者：固定当前策略的 inode，并负责候选 Map 准备和完整替换。
// 对象需比 BPF 链接活得更久；重载成功时旧策略的句柄可以释放，失败时保留原集合。
#pragma once
#include "owned_fd.h"
#include <string>
#include <vector>
#include "policy_config.h"

// Pins active policy inodes until replacement; the owner must outlive BPF links.
class ProtectedFiles {
    std::vector<OwnedFd> descriptors_;
public:
    ProtectedFiles() = default;
    ProtectedFiles(const ProtectedFiles &) = delete;
    ProtectedFiles &operator=(const ProtectedFiles &) = delete;
    ~ProtectedFiles() = default; // 每个 FD 都由独立 RAII 对象持有，候选失败时自动释放。
    // Build a complete candidate, atomically replace outer-map slot 0, then release old pins.
    // Failure before the swap leaves the active map and pins untouched.
    // 调用者借出外层 Map FD，本对象不负责关闭它；
    // 成功返回表示已发布整份候选，不表示所有在途系统调用已结束。
    void install(int map_fd, const PolicyConfig &policy);
};
