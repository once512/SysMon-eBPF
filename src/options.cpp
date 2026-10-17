// SPDX-License-Identifier: MIT
// 宿主参数解析与互斥检查；提前拒绝无效组合，避免参数错误时已经挂载了部分内核策略。
#include "options.h"
#include <charconv>
#include <iostream>
#include <stdexcept>
#include <string_view>

CliAction parse_options(int argc, char **argv, Options &options)
{
    auto &check = options.check;
    auto &paths = options.paths;
    auto &control_path = options.control_path;
    auto &run_seconds = options.run_seconds;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg(argv[i]);
        if (arg == "--help" && argc == 2) {
            std::cout << "Usage: secmon [--check] [--protect-file PATH ...] [--self-protect SOCKET] [--run-for SECONDS] [--policy FILE]\n"
                         "Default: execution/credential audit. --protect-file enforces read-only\n"
                         "on an existing regular file inode for all tasks, including root.\n"
                         "--self-protect SOCKET: protect this process; requires a root-owned private directory.\n"
                         "secmon --stop SOCKET: authorized root shutdown.\n"
                         "--policy FILE: versioned file policy; reload via secmon --reload SOCKET.\n"
                         "secmon --status SOCKET: JSON activity/revision snapshot without reading config.\n"
                         "--run-for SECONDS: exit internally after 1..3600 seconds.\n"
                         "--check: inspect environment without attaching BPF.\n";
            return CliAction::help;
        }
        if (arg == "--check") check = true;
        else if (arg == "--run-for" && i + 1 < argc) {
            std::string_view value(argv[++i]);
            auto result = std::from_chars(value.data(), value.data() + value.size(), run_seconds);
            if (result.ec != std::errc{} || result.ptr != value.data() + value.size() ||
                run_seconds == 0 || run_seconds > 3600) {
                std::cerr << "--run-for requires 1..3600 seconds\n";
                throw std::invalid_argument("Invalid command line");
            }
        }
        else if (arg == "--self-protect" && i + 1 < argc && control_path.empty())
            control_path = argv[++i];
        else if (arg == "--policy" && i + 1 < argc && options.policy_path.empty()) {
            options.policy_path = argv[++i];
            if (options.policy_path.empty() || options.policy_path.front() != '/') {
                std::cerr << "--policy requires an absolute file path\n";
                throw std::invalid_argument("Invalid command line");
            }
        }
        else if ((arg == "--stop" || arg == "--reload" || arg == "--status") && argc == 3 && i == 1) {
            options.control_path = argv[2];
            return arg == "--stop" ? CliAction::stop : (arg == "--reload" ? CliAction::reload : CliAction::status);
        }
        else if (arg == "--protect-file" && i + 1 < argc) paths.emplace_back(argv[++i]);
        else {
            std::cerr << "Invalid argument; use --help\n";
            throw std::invalid_argument("Invalid command line");
        }
    }
    if ((check && (!paths.empty() || !control_path.empty() || run_seconds || !options.policy_path.empty())) ||
        (!options.policy_path.empty() && !paths.empty()) || paths.size() > 256) {
        std::cerr << "--check cannot install policies; --policy and --protect-file are mutually exclusive; at most 256 files are supported\n";
        throw std::invalid_argument("Invalid command line");
    }
    return CliAction::run;
}
