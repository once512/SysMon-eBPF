// SPDX-License-Identifier: MIT
// fanotify 宿主入口：建立可选管理通道，创建权限事件监听器，在事件循环中串行处理裁决和重载。
// 它是独立服务；与 BPF 的 LSM 拒绝是叠加关系，fanotify 放行不能推翻其他安全层的拒绝。
#include "gate.h"
#include "options.h"
#include "policy.h"
#include "control.h"
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
        if (options.action == FanotifyOptions::Action::stop) { request_stop(options.control_path); return 0; }
        if (options.action == FanotifyOptions::Action::reload) { request_reload(options.control_path); return 0; }
        PolicyConfig active;
        if (!options.policy_path.empty()) {
            active = load_policy(options.policy_path);
            apply_fanotify_policy(active, options);
        }
        std::unique_ptr<ControlServer> control;
        if (!options.control_path.empty()) control = std::make_unique<ControlServer>(options.control_path);
        struct sigaction action{};
        action.sa_handler = stop;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGINT, &action, nullptr) || sigaction(SIGTERM, &action, nullptr))
            throw std::runtime_error("Cannot install signal handlers");
        {
            PermissionGate gate(options.path, options.decision, options.event, options.analyzer, options.policy_path);
            std::cerr << "Fanotify active; decision=" << (options.decision.external ? "analysis" : (options.decision.allow ? "allow" : "deny"))
                      << " analyzer_pid=" << gate.analyzer_pid() << " event=" << permission_name(options.event) << '\n';
            if (active.revision) std::cerr << "Fanotify policy active revision=" << active.revision << '\n';
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(options.seconds);
            try {
                while (!stopping && std::chrono::steady_clock::now() < deadline) {
                    if (control) control->dispatch([&](ControlCommand command) {
                        if (command == ControlCommand::stop) { stopping = 1; return; }
                        try {
                            if (options.policy_path.empty()) throw std::runtime_error("Reload requires --policy at startup");
                            auto candidate = load_policy(options.policy_path, gate.target_fd());
                            if (candidate.revision <= active.revision) throw std::runtime_error("Policy revision must increase");
                            auto next = options;
                            apply_fanotify_policy(candidate, next);
                            if (!same_fanotify_backend(options, next))
                                throw std::runtime_error("Changing fanotify target, event or analyzer requires restart");
                            // 先完整解析并检查固定后端，再要求队列/分析器空闲；拒绝时不更新 active revision，可稍后重试。
                            gate.reconfigure(next.decision);
                            options = std::move(next);
                            active = std::move(candidate);
                            std::cerr << "Fanotify policy active revision=" << active.revision << '\n';
                        } catch (const std::exception &error) {
                            std::cerr << "Fanotify policy reload rejected: " << error.what() << '\n';
                            throw;
                        }
                    });
                    if (!stopping) gate.poll_once(100);
                }
                // 正常停止显式拒绝已交付请求；未读内核队列在 group 关闭时释放，不能宣称关闭仍保持拒绝保护。
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
              << ",\"analysis_denied\":" << stats.analysis_denied
              << ",\"analyzed\":" << stats.analyzed << ",\"analyzer_error\":" << stats.analyzer_error
              << ",\"analyzer_failures\":" << stats.analyzer_failures
              << ",\"peak_pending\":" << stats.peak_pending << "}\n";
    return std::cout ? 0 : 1;
}
