// SPDX-License-Identifier: MIT
#include "gate.h"
#include "options.h"
#include <chrono>
#include <csignal>
#include <iostream>
#include <stdexcept>

namespace {
volatile std::sig_atomic_t stopping = 0;
void stop(int) { stopping = 1; }
}

int main(int argc, char **argv)
{
    FanotifyOptions options;
    try {
        if (!parse_fanotify_options(argc, argv, options)) return 0;
    } catch (const std::invalid_argument &error) {
        std::cerr << error.what() << '\n';
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
            PermissionGate gate(options.path, options.decision, options.event);
            std::cerr << "Fanotify active; decision=" << (options.decision.allow ? "allow" : "deny")
                      << " event=" << permission_name(options.event) << '\n';
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(options.seconds);
            try {
                while (!stopping && std::chrono::steady_clock::now() < deadline)
                    gate.poll_once(100);
                gate.shutdown();
            } catch (...) { stats = gate.stats(); throw; }
            stats = gate.stats();
        } // Close the group before writing statistics to a potentially slow sink.
    } catch (const std::exception &error) {
        std::cerr << "secmon-fanotify: " << error.what() << '\n'
                  << "allowed=" << stats.allowed << " denied=" << stats.denied
                  << " overflow=" << stats.overflow
                  << " timed_out=" << stats.timed_out << " overloaded=" << stats.overloaded << '\n';
        return 1;
    }
    std::cout << "{\"permission_event\":\"" << permission_name(options.event) << "\",\"allowed\":" << stats.allowed << ",\"denied\":" << stats.denied
              << ",\"overflow\":" << stats.overflow << ",\"timed_out\":" << stats.timed_out
              << ",\"overloaded\":" << stats.overloaded
              << ",\"shutdown_denied\":" << stats.shutdown_denied
              << ",\"peak_pending\":" << stats.peak_pending << "}\n";
    return std::cout ? 0 : 1;
}
