// SPDX-License-Identifier: MIT
// 只读核对一个主服务的活动策略；不再对两个进程进行四次采样或维护跨进程一致性协议。
#include "control_client.h"
#include <charconv>
#include <iostream>
#include <set>
#include <string_view>
int main(int argc, char **argv)
{
    std::string socket;
    std::uint64_t expected = 0;
    try {
        if (argc == 2 && std::string_view(argv[1]) == "--help") {
            std::cout << "Usage: secmon-policyctl --socket PATH [--expect-revision N]\n"
                         "Read-only active policy check of the single monitor service. Requires root.\n";
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
            } else if (option == "--socket") {
                if (value.empty() || value.front() != '/') throw std::invalid_argument("Require an absolute socket path");
                socket = value;
            } else throw std::invalid_argument("Unknown option");
        }
        if (socket.empty()) throw std::invalid_argument("Require --socket; use --help");
    } catch (const std::invalid_argument &error) {
        std::cerr << "secmon-policyctl: " << error.what() << '\n';
        return 2;
    }
    try {
        const auto reply = query_status(socket);
        const auto *code = reply.code != management::Code::ok ? "query_failed" :
            (!(reply.flags & management::configured) ? "unconfigured" :
             (expected && reply.revision != expected ? "unexpected_revision" : "ok"));
        std::cout << "{\"code\":\"" << code << "\",\"status\":" << management::reply_json(reply) << "}\n";
        return std::string_view(code) == "ok" ? 0 : 1;
    } catch (const std::exception &error) {
        std::cerr << "secmon-policyctl: " << error.what() << '\n';
        std::cout << "{\"code\":\"transport_error\"}\n";
        return 1;
    }
}
