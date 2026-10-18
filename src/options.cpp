// SPDX-License-Identifier: MIT
// 一个服务的参数入口；公共生命周期参数与 fanotify 策略参数分别解析，不创建内核资源。
#include <secmon/policy_limits.h>
#include "options.h"
#include <charconv>
#include <iostream>
#include <set>
#include <stdexcept>
#include <string_view>

CliAction parse_options(int argc, char **argv, Options &options)
{
    if (argc == 2 && std::string_view(argv[1]) == "--help") {
        std::cout << "Usage: secmon [--policy ABSOLUTE_FILE | --protect-file PATH ...] [--control SOCKET] [--run-for SECONDS]\n"
                     "One service owns BPF audit/protection and optional fanotify permission decisions.\n"
                     "--self-protect SOCKET: same control socket with BPF process protection.\n"
                     "--policy FILE: unified policy; revision must increase on reload.\n"
                     "secmon --status SOCKET | --reload SOCKET | --stop SOCKET\n"
                     "--check: inspect BPF environment without attaching.\n"
                     "--run-for SECONDS: optional internal lifetime, 1..3600; otherwise run until stopped.\n"
                     "Diagnostics: --bpf-only | --fanotify-only (same process and entry point).\n"
                     "--audit-permissions: emit fanotify reply JSONL; final fanotify stats go to stderr.\n"
                     "Fanotify CLI instead of policy: --file PATH --decision allow|deny\n"
                     "  or --file PATH --analyzer ABSOLUTE_PATH --deny-marker TEXT\n"
                     "  --event open|access|exec --scan-limit-bytes 1..1048576\n"
                     "  --decision-delay-ms 0..60000 --request-timeout-ms 1..60000 --max-pending 1..4096\n"
                     "  --timeout-decision allow|deny --overload-decision allow|deny\n"
                     "  --analyzer-error-decision allow|deny\n";
        return CliAction::help;
    }
    if (argc == 3 && (std::string_view(argv[1]) == "--stop" || std::string_view(argv[1]) == "--reload" || std::string_view(argv[1]) == "--status")) {
        options.control_path = argv[2];
        return std::string_view(argv[1]) == "--stop" ? CliAction::stop :
            (std::string_view(argv[1]) == "--reload" ? CliAction::reload : CliAction::status);
    }
    std::set<std::string_view> seen;
    std::vector<char *> fan_args{argv[0]};
    const std::set<std::string_view> fan_flags = {"--file", "--decision", "--analyzer", "--deny-marker", "--event",
        "--scan-limit-bytes", "--analyzer-error-decision", "--decision-delay-ms", "--request-timeout-ms",
        "--max-pending", "--timeout-decision", "--overload-decision"};
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg(argv[i]);
        if (arg != "--protect-file" && !seen.insert(arg).second) throw std::invalid_argument("Duplicate option");
        if (arg == "--audit-permissions") options.permission_audit = true;
        else if (arg == "--check") options.check = true;
        else if (arg == "--bpf-only" || arg == "--fanotify-only") {
            if (options.modules != Options::Modules::automatic) throw std::invalid_argument("Choose one diagnostic module");
            options.modules = arg == "--bpf-only" ? Options::Modules::bpf_only : Options::Modules::fanotify_only;
        } else {
            if (i + 1 >= argc) throw std::invalid_argument("Missing option value");
            auto *value = argv[++i];
            if (arg == "--run-for") {
                const std::string_view text(value);
                const auto result = std::from_chars(text.data(), text.data() + text.size(), options.run_seconds);
                if (result.ec != std::errc{} || result.ptr != text.data() + text.size() ||
                    !options.run_seconds || options.run_seconds > 3600) throw std::invalid_argument("--run-for requires 1..3600 seconds");
            } else if (arg == "--control" || arg == "--self-protect") {
                if (!options.control_path.empty() || value[0] != '/') throw std::invalid_argument("Require one absolute control socket");
                options.control_path = value;
            } else if (arg == "--policy") {
                if (value[0] != '/') throw std::invalid_argument("--policy requires an absolute path");
                options.policy_path = value;
            } else if (arg == "--protect-file") options.paths.emplace_back(value);
            else if (fan_flags.count(arg)) { fan_args.push_back(argv[i - 1]); fan_args.push_back(value); }
            else throw std::invalid_argument("Unknown option; use --help");
        }
    }
    if ((options.check && argc != 2) || options.paths.size() > SECMON_MAX_PROTECTED_PATHS ||
        (!options.policy_path.empty() && (!options.paths.empty() || fan_args.size() > 1)) ||
        (options.modules == Options::Modules::bpf_only && (fan_args.size() > 1 || options.permission_audit)) ||
        (options.modules == Options::Modules::fanotify_only && !options.paths.empty()))
        throw std::invalid_argument("Conflicting service/policy options");
    if (fan_args.size() > 1) parse_fanotify_options(static_cast<int>(fan_args.size()), fan_args.data(), options.fanotify);
    if (options.modules == Options::Modules::fanotify_only && fan_args.size() == 1 && options.policy_path.empty())
        throw std::invalid_argument("Fanotify-only requires --policy or --file with a decision");
    return CliAction::run;
}
