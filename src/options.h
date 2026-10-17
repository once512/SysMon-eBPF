// SPDX-License-Identifier: MIT
// 宿主命令行的数据模型；这里只表达启动意图，实际文件读取、BPF 加载和控制连接在后续阶段进行。
#pragma once
#include <string>
#include <vector>

struct Options {
    bool check = false;
    std::vector<std::string> paths;
    std::string control_path;
    unsigned int run_seconds = 0;
    std::string policy_path;
};
enum class CliAction { run, help, stop, reload, status };
// Throws std::invalid_argument for malformed options; performs no BPF/socket I/O.
CliAction parse_options(int argc, char **argv, Options &options);
