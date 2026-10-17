// SPDX-License-Identifier: MIT
// fanotify 宿主入口：建立可选管理通道，创建权限事件监听器，在事件循环中串行处理裁决和重载。
// 它是独立服务；与 BPF 的 LSM 拒绝是叠加关系，fanotify 放行不能推翻其他安全层的拒绝。
#include "gate.h"
#include "options.h"
#include "policy.h"
#include "control.h"
#include "control_client.h"
#include "status.h"
#include "stats.h"
#include <chrono>
#include <csignal>
#include <iostream>
#include <stdexcept>
#include <type_traits>
static_assert(std::is_nothrow_move_assignable_v<FanotifyOptions>);

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
        if (options.action == FanotifyOptions::Action::status) { request_status(options.control_path); return 0; }
        PolicyConfig initial;
        if (!options.policy_path.empty()) {
            initial = load_policy(options.policy_path);
            apply_fanotify_policy(initial, options);
        }
        PolicyRuntime runtime(options.policy_path, std::move(initial));
        const auto &active = runtime.active();
        // 这个管理端只提供 root 控制，不像 BPF 宿主那样安装 TASK_STORAGE 自保护。
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
                        auto code = management::Code::ok;
                        if (command == ControlCommand::stop) stopping = 1;
                        else if (command == ControlCommand::reload) {
                            code = runtime.reload([&](const PolicyConfig &candidate) {
                                // 先在副本上转换、验证候选；
                                // 固定后端变化或忙队列拒绝时，不让活动 options 混入半份新配置。
                                auto next = options;
                                apply_fanotify_policy(candidate, next);
                                if (!same_fanotify_backend(options, next))
                                    throw management::Error(management::Code::restart_required,
                                        "Changing fanotify target, event or analyzer requires restart");
                                // 固定后端检查和资源准备在前；空闲时提交后只做不分配内存的移动赋值。
                                // 本调用只有空闲时才提交裁决合同；
                                // 随后 options 移动赋值不再分配内存，避免提交后另行失败。
                                gate.reconfigure(next.decision);
                                options = std::move(next);
                            }, gate.target_fd());
                            if (code == management::Code::ok)
                                std::cerr << "Fanotify policy active revision=" << active.revision << '\n';
                        }
                        auto reply = fanotify_status(runtime, options, gate);
                        reply.code = code;
                        return reply;
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
    write_gate_stats(std::cout, options.event, stats);
    return std::cout ? 0 : 1;
}
