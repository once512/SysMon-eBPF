// SPDX-License-Identifier: MIT
#include "gate.h"
#include <charconv>
#include <chrono>
#include <csignal>
#include <iostream>
#include <stdexcept>
#include <string_view>

namespace {
volatile std::sig_atomic_t stopping = 0;
void stop(int) { stopping = 1; }
}

int main(int argc, char **argv)
{
    if (argc == 2 && std::string_view(argv[1]) == "--help") {
        std::cout << "Usage: secmon-fanotify --file PATH --decision allow|deny --run-for SECONDS\n"
                     "Single-inode FAN_OPEN_PERM experiment; requires CAP_SYS_ADMIN.\n"
                     "SECONDS: 1..3600. Closing/crashing releases pending requests.\n";
        return 0;
    }
    std::string path;
    std::string_view decision;
    unsigned int seconds = 0;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg(argv[i]);
        if (i + 1 >= argc) { std::cerr << "Missing option value\n"; return 2; }
        const std::string_view value(argv[++i]);
        if (arg == "--file" && path.empty() && !value.empty()) path = value;
        else if (arg == "--decision" && decision.empty()) decision = value;
        else if (arg == "--run-for" && !seconds) {
            const auto parsed = std::from_chars(value.data(), value.data() + value.size(), seconds);
            if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() ||
                !seconds || seconds > 3600) {
                std::cerr << "--run-for requires 1..3600 seconds\n"; return 2;
            }
        } else { std::cerr << "Invalid or duplicate option; use --help\n"; return 2; }
    }
    if (path.empty() || (decision != "allow" && decision != "deny") || !seconds) {
        std::cerr << "Require --file, --decision allow|deny and --run-for; use --help\n";
        return 2;
    }
    GateStats stats;
    try {
        struct sigaction action{};
        action.sa_handler = stop;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGINT, &action, nullptr) || sigaction(SIGTERM, &action, nullptr))
            throw std::runtime_error("Cannot install signal handlers");
        {
            PermissionGate gate(path, decision == "allow");
            std::cerr << "Fanotify active; decision=" << decision << '\n';
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
            try {
                while (!stopping && std::chrono::steady_clock::now() < deadline)
                    gate.poll_once(100);
            } catch (...) { stats = gate.stats(); throw; }
            stats = gate.stats();
        } // Close the group before writing statistics to a potentially slow sink.
    } catch (const std::exception &error) {
        std::cerr << "secmon-fanotify: " << error.what() << '\n'
                  << "allowed=" << stats.allowed << " denied=" << stats.denied
                  << " overflow=" << stats.overflow << '\n';
        return 1;
    }
    std::cout << "{\"allowed\":" << stats.allowed << ",\"denied\":" << stats.denied
              << ",\"overflow\":" << stats.overflow << "}\n";
    return std::cout ? 0 : 1;
}
