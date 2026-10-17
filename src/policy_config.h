// SPDX-License-Identifier: MIT
// 共用配置模型：version 是文本语法版本，revision 是进程内单调递增的运行策略版本。
// 同一文件可供两个宿主读取；BPF 应用 protect，fanotify 应用可选的 fanotify 配置，分别提交。
#pragma once
#include "content_digest.h"
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
    ContentDigest source_digest{}; // 仅 load_policy 对完整原始文件字节计算；CLI/纯解析结果没有来源摘要。
    std::optional<FanotifyPolicy> fanotify;
    std::vector<std::string> paths;
};
// Versioned, bounded text format. Parsing performs no filesystem changes.
PolicyConfig parse_policy(std::istream &input);
// Pins and reads one root-owned, non-writable-by-others regular file (no symlinks).
// forbidden_inode_fd prevents a fanotify listener from opening its own marked inode.
PolicyConfig load_policy(const std::string &path, int forbidden_inode_fd = -1);
