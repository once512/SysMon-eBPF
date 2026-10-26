// SPDX-License-Identifier: MIT
// 共用单一配置模型：revision 是进程内单调递增的运行策略编号，不做历史格式兼容。
// 同一主服务读取一份配置；BPF 应用 protect/allow-writer，fanotify 应用可选字段，由协调器统一提交。
#pragma once
#include "content_digest.h"
#include <cstdint>
#include <istream>
#include <string>
#include <vector>
#include <optional>

struct FanotifyPolicy {
    std::vector<std::string> paths;
    std::uint64_t rebind_epoch = 0; // Higher epochs explicitly re-pin all targets.
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
    // 当前 mm->exe_file 的对象身份 + 初始 user namespace 的有效 UID，不按进程名/PID 授权。
    // 一条规则只选中一个显式 protect 路径；同程序可对多个目标分别声明权限，最多 64 条规则。
    struct Writer {
        std::string path;
        std::uint32_t euid;
        std::string target;
        std::uint32_t operations;
    };
    std::vector<Writer> writers;
    // vault paths are also in paths, but deny reads as well as modification.
    std::vector<std::string> vaults;
    std::vector<std::string> canaries;
    struct CanaryResponse { std::uint64_t epoch; unsigned int duration_ms; };
    std::optional<CanaryResponse> canary_response;
    struct VaultSession {
        std::uint64_t id;
        std::string program;
        std::uint32_t euid;
        std::string target;
        std::uint32_t access;
        unsigned int duration_ms;
        std::string boot_id;
        std::uint64_t issued_boot_ns;
    };
    std::vector<VaultSession> vault_sessions;
    // Optional policy-wide maintenance lease. Zero means no deadline.
    // A successful new BPF policy activation starts a new lease, never a failed reload.
    unsigned int writer_lease_ms = 0;
};
// 有界单一文本格式；解析不访问文件系统，旧 version 指令按未知字段拒绝。
// 返回经过文本与字段组合校验的值对象；
// 不会验证目标存在、所有者权限，也不会生成来源摘要。
PolicyConfig parse_policy(std::istream &input);
// Pins and reads one root-owned, non-writable-by-others regular file (no symlinks).
// All forbidden_inode_fds are borrowed; exclude every marked inode before reading.
// 空列表表示没有排除对象；句柄必须在本次加载期间保持有效。
// 成功读取并计算摘要，不代表任何后端已经应用。
PolicyConfig load_policy(const std::string &path, const std::vector<int> &forbidden_inode_fds = {});
