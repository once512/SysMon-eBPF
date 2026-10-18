// SPDX-License-Identifier: MIT
// 宿主命令行的数据模型；这里只表达启动意图，实际文件读取、BPF 加载和控制连接在后续阶段进行。
#pragma once
#include "fanotify/options.h"
#include <string>
#include <vector>

struct Options {
    bool check = false;
    bool permission_audit = false;
    // 默认 BPF 常驻，配置有 fanotify 字段时同时启用；单模块模式仅供诊断/机制测试。
    enum class Modules { automatic, bpf_only, fanotify_only } modules = Modules::automatic;
    FanotifyOptions fanotify;
    std::vector<std::string> paths;
    std::string control_path;
    unsigned int run_seconds = 0;
    std::string policy_path;
};
enum class CliAction { run, help, stop, reload, status };
// Throws std::invalid_argument for malformed options; performs no BPF/socket I/O.
// run 才进入所选模块的生命周期；
// help/stop/reload/status 在主入口提前处理，不顺便 attach 一套监控。
CliAction parse_options(int argc, char **argv, Options &options);
