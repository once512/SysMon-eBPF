// SPDX-License-Identifier: MIT
// 只读跨后端核对工具：不读取磁盘候选、不发 reload；按固定顺序采样实际活动来源。
#include "consistency.h"
#include "control.h"
#include <charconv>
#include <iostream>
#include <set>
#include <string_view>

int main(int argc, char **argv)
{
    std::string bpf_socket, fanotify_socket;
    std::uint64_t expected = 0;
    try {
        if (argc == 2 && std::string_view(argv[1]) == "--help") {
            std::cout << "Usage: secmon-policyctl --bpf-socket PATH --fanotify-socket PATH [--expect-revision N]\n"
                         "Read-only active-source consistency check. Requires root.\n"
                         "Exit: 0 consistent, 1 inconsistent/unstable/transport error, 2 invalid arguments.\n";
            return 0;
        }
        std::set<std::string_view> seen;
        for (int i = 1; i < argc; ++i) {
            const std::string_view option(argv[i]);
            if (!seen.insert(option).second || i + 1 >= argc) throw std::invalid_argument("Duplicate or incomplete option");
            const std::string_view value(argv[++i]);
            if (option == "--expect-revision") {
                const auto parsed = std::from_chars(value.data(), value.data() + value.size(), expected);
                if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() || !expected)
                    throw std::invalid_argument("Expected revision must be a positive uint64");
            } else if (option == "--bpf-socket" || option == "--fanotify-socket") {
                if (value.empty() || value.front() != '/') throw std::invalid_argument("Require absolute socket paths");
                (option == "--bpf-socket" ? bpf_socket : fanotify_socket) = value;
            } else throw std::invalid_argument("Unknown option");
        }
        if (bpf_socket.empty() || fanotify_socket.empty()) throw std::invalid_argument("Require both sockets; use --help");
    } catch (const std::invalid_argument &error) {
        std::cerr << "secmon-policyctl: " << error.what() << '\n';
        return 2;
    }
    try {
        const auto b1 = query_status(bpf_socket);
        const auto f1 = query_status(fanotify_socket);
        const auto b2 = query_status(bpf_socket);
        const auto f2 = query_status(fanotify_socket);
        const auto result = management::check_consistency(b1, f1, b2, f2, expected);
        std::cout << management::consistency_json(result, b2, f2) << '\n';
        return result == management::Consistency::consistent ? 0 : 1;
    } catch (const std::exception &error) {
        std::cerr << "secmon-policyctl: " << error.what() << '\n';
        std::cout << "{\"code\":\"transport_error\",\"scope\":\"active_configuration_bytes\"}\n";
        return 1;
    }
}
