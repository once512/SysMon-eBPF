// SPDX-License-Identifier: MIT
// 共用配置模型：version 是文本语法版本，revision 是进程内单调递增的运行策略版本。
// 同一文件可供两个宿主读取；BPF 应用 protect/allow-writer，fanotify 应用可选的 fanotify 配置，分别提交。
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
    // 扫描上限按字节计算；
    // 下面 delay_ms/timeout_ms 按毫秒，max_pending 按已交付请求条目计算。
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
    // 这里保存显式 protect 的路径文本；
    // 安装后真正匹配 inode，运行时路径被替换不会使策略自动迁移。
    std::vector<std::string> paths;
    // v3：当前 mm->exe_file 的对象身份 + 初始 user namespace 的有效 UID，不按进程名/PID 授权。
    struct Writer { std::string path; std::uint32_t euid; };
    std::vector<Writer> writers;
};
// Versioned, bounded text format. Parsing performs no filesystem changes.
// 返回经过文本与字段组合校验的值对象；
// 不会验证目标存在、所有者权限，也不会生成来源摘要。
PolicyConfig parse_policy(std::istream &input);
// Pins and reads one root-owned, non-writable-by-others regular file (no symlinks).
// forbidden_inode_fd prevents a fanotify listener from opening its own marked inode.
// forbidden_inode_fd 是借用句柄，-1 代表没有排除对象；
// 成功读取并计算摘要，不代表任何后端已经应用。
PolicyConfig load_policy(const std::string &path, int forbidden_inode_fd = -1);
