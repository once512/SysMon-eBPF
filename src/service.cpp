// SPDX-License-Identifier: MIT
// 事件处理、管理和重载都在此线程串行执行，不创建第二个监控进程或后台重载线程。
#include "service.h"
#include "diagnostic_output.h"
#include "bpf/monitor.h"
#include "fanotify/monitor.h"
#include "fanotify/policy.h"
#include "control.h"
#include <csignal>
#include <atomic>
#include <iostream>
#include <optional>
#include <stdexcept>
namespace {
// 现在存在审计 I/O 线程，信号可能投递到任一线程；普通 volatile 不足以提供跨线程同步。
// 始终无锁的 atomic 才能在异步信号处理器中安全设置停止标志，不持任何业务互斥锁。
static_assert(std::atomic<bool>::is_always_lock_free);
std::atomic<bool> stopping{false};
void stop(int) { stopping.store(true, std::memory_order_relaxed); }
PolicyConfig initial_policy(const Options &options)
{
    if (!options.policy_path.empty()) return load_policy(options.policy_path);
    PolicyConfig initial;
    initial.paths = options.paths;
    return initial;
}
}
MonitorService::MonitorService(Options options, DiagnosticOutput &diagnostics)
    : diagnostics_(diagnostics), options_(std::move(options)), runtime_(options_.policy_path, initial_policy(options_))
{
    stopping.store(false, std::memory_order_relaxed);
    struct sigaction action{};
    action.sa_handler = stop;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, nullptr) || sigaction(SIGTERM, &action, nullptr))
        throw std::runtime_error("Cannot install signal handlers");
    if (!options_.control_path.empty()) control_ = std::make_unique<ControlServer>(options_.control_path);
    const auto &active = runtime_.active();
    auto fan_options = options_.fanotify;
    const bool use_fan = options_.modules != Options::Modules::bpf_only && (active.fanotify || !fan_options.path.empty());
    if (options_.modules == Options::Modules::fanotify_only && !use_fan)
        throw std::runtime_error("Policy has no fanotify configuration");
    // 所有启动失败都通过对象逆序析构回收；任一模块失败，整个服务启动失败。
    if (options_.modules != Options::Modules::fanotify_only)
        bpf_ = std::make_unique<BpfMonitor>(active, control_ != nullptr);
    if (use_fan) {
        if (active.fanotify) apply_fanotify_policy(active, fan_options);
        fanotify_ = std::make_unique<FanotifyMonitor>(std::move(fan_options), options_.policy_path);
    }
    std::cerr << "Policy active revision=" << active.revision << '\n';
    std::cerr << "Service active; bpf=" << bool(bpf_) << " fanotify=" << bool(fanotify_) << '\n';
}
MonitorService::~MonitorService() = default;
void MonitorService::commit(const PolicyConfig &candidate)
{
    std::optional<FanotifyOptions> next;
    if (fanotify_) next = fanotify_->prepare(candidate);
    else if (candidate.fanotify && options_.modules != Options::Modules::bpf_only)
        throw management::Error(management::Code::restart_required, "Enabling fanotify requires restart");
    // prepare 完成所有可能失败的 fanotify 检查。BPF install 内部先准备完整候选再原子替换 Map。
    // 若 BPF 失败，两个模块保持旧策略；一旦成功，余下提交仅做 noexcept 的值移动。
    if (bpf_) bpf_->install(candidate);
    if (fanotify_) fanotify_->commit(std::move(*next));
    // 这是用户态提交顺序保证，不声称不同内核钩子或在途系统调用的全局原子切换。
}
management::Reply MonitorService::snapshot() const
{
    const auto backend = bpf_ ? (fanotify_ ? management::Backend::combined : management::Backend::bpf) : management::Backend::fanotify;
    auto reply = runtime_.snapshot(backend);
    const auto diagnostic = diagnostics_.stats();
    reply.diagnostic_written = diagnostic.written;
    reply.diagnostic_dropped = diagnostic.dropped;
    reply.diagnostic_invalid = diagnostic.invalid;
    reply.diagnostic_queued = diagnostic.queued;
    reply.diagnostic_errno = diagnostic.output_errno;
    if (bpf_) {
        reply.protected_paths = runtime_.active().paths.size();
        reply.writer_paths = runtime_.active().writers.size();
        const auto audit = bpf_->audit_stats();
        reply.audit_written = audit.written;
        reply.audit_dropped = audit.dropped;
        reply.audit_invalid = audit.invalid;
        reply.audit_queued = audit.queued;
        reply.audit_errno = audit.output_errno;
        if (control_) reply.flags |= management::self_protected;
    }
    if (fanotify_) fanotify_->snapshot(reply);
    return reply;
}
void MonitorService::run()
{
    const auto started = std::chrono::steady_clock::now();
    auto next_report = started + std::chrono::seconds(10);
    while (!stopping.load(std::memory_order_relaxed)) {
        if (options_.run_seconds && std::chrono::steady_clock::now() - started >= std::chrono::seconds(options_.run_seconds)) break;
        if (control_) control_->dispatch([&](ControlCommand command) {
            auto code = management::Code::ok;
            if (command == ControlCommand::stop) stopping.store(true, std::memory_order_relaxed);
            else if (command == ControlCommand::reload) {
                code = runtime_.reload([&](const PolicyConfig &candidate) { commit(candidate); }, fanotify_ ? fanotify_->target_fd() : -1);
                if (code == management::Code::ok) std::cerr << "Policy active revision=" << runtime_.active().revision << '\n';
            }
            auto reply = snapshot();
            reply.code = code;
            return reply;
        });
        if (stopping.load(std::memory_order_relaxed)) break;
        // 两个模块轮流处理有界工作；fanotify 开启时 BPF 不阻塞等待，避免把裁决延迟叠加到审计等待上。
        if (bpf_) bpf_->poll_once(fanotify_ ? 0 : 50);
        if (fanotify_) fanotify_->poll_once(10);
        if (bpf_ && std::chrono::steady_clock::now() >= next_report) {
            bpf_->report();
            next_report = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        }
    }
    if (fanotify_) fanotify_->shutdown();
    if (bpf_) bpf_->shutdown();
    // 审计流继续使用 stdout JSONL；混合模式的结束统计写 stderr，避免污染事件消费者。
    if (fanotify_) fanotify_->report(bpf_ ? std::cerr : std::cout);
}
