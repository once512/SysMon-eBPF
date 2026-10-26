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
    bool require_ready = false, require_decoy = false;
    try {
        if (argc == 2 && std::string_view(argv[1]) == "--help") {
            std::cout << "Usage: secmon-policyctl --socket PATH [--expect-revision N] [--require-ready] [--require-decoy]\n"
                         "Read-only active policy check of the single monitor service. Requires root.\n"
                         "--require-ready: also check observed reader/analyzer/configured-provider readiness.\n"
                         "--require-decoy: require a configured, responsive managed view.\n";
            return 0;
        }
        std::set<std::string_view> seen;
        for (int i = 1; i < argc; ++i) {
            const std::string_view option(argv[i]);
            if (!seen.insert(option).second) throw std::invalid_argument("Duplicate option");
            if (option == "--require-ready") { require_ready = true; continue; }
            if (option == "--require-decoy") { require_decoy = true; continue; }
            if (i + 1 >= argc) throw std::invalid_argument("Incomplete option");
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
        const char *code = reply.code != management::Code::ok ? "query_failed" :
            (!(reply.flags & management::configured) ? "unconfigured" :
             (expected && reply.revision != expected ? "unexpected_revision" : "ok"));
        if (std::string_view(code) == "ok") {
            if (require_decoy && !reply.decoy_files) code = "decoy_missing";
            else if (require_ready && reply.backend != management::Backend::bpf && reply.reader_state != management::ReaderState::responsive)
                code = "reader_unresponsive";
            else if (require_ready && (reply.flags & management::analyzer) && !(reply.flags & management::analyzer_online))
                code = "analyzer_offline";
            else if ((require_ready || require_decoy) && reply.decoy_files && reply.decoy_provider_state != management::ProviderState::responsive)
                code = reply.decoy_provider_state == management::ProviderState::offline ? "decoy_provider_offline" : "decoy_provider_unresponsive";
        }
        std::cout << "{\"code\":\"" << code << "\",\"status\":" << management::reply_json(reply) << "}\n";
        return std::string_view(code) == "ok" ? 0 : 1;
    } catch (const std::exception &error) {
        std::cerr << "secmon-policyctl: " << error.what() << '\n';
        std::cout << "{\"code\":\"transport_error\"}\n";
        return 1;
    }
}
