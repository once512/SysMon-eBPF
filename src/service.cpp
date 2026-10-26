// SPDX-License-Identifier: MIT
// 事件处理、管理和重载都在此线程串行执行，不创建第二个监控进程或后台重载线程。
#include "service.h"
#include "diagnostic_output.h"
#include "audit_sink.h"
#include "events.h"
#include "bpf/monitor.h"
#include "fanotify/monitor.h"
#include "fanotify/policy.h"
#include "control.h"
#include "policy_pins.h"
#include "boot_clock.h"
#include "decoy/provider.h"
#include <algorithm>
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
    : diagnostics_(diagnostics), options_(std::move(options)), decoy_(options_.decoy.enabled() ? std::make_unique<DecoyProvider>(options_.decoy) : nullptr), runtime_(options_.policy_path, initial_policy(options_))
{
    stopping.store(false, std::memory_order_relaxed);
    struct sigaction action{};
    action.sa_handler = stop;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, nullptr) || sigaction(SIGTERM, &action, nullptr))
        throw std::runtime_error("Cannot install signal handlers");
    if (!options_.control_path.empty()) control_ = std::make_unique<ControlServer>(options_.control_path);
    const auto &active = runtime_.active();
    if (options_.modules == Options::Modules::fanotify_only && (!active.vaults.empty() || active.canary_response))
        throw std::runtime_error("Vault/canary policy requires the BPF module");
    auto fan_options = options_.fanotify;
    const bool use_fan = options_.modules != Options::Modules::bpf_only && (active.fanotify || !fan_options.paths.empty());
    if (options_.modules == Options::Modules::fanotify_only && !use_fan)
        throw std::runtime_error("Policy has no fanotify configuration");
    if (options_.permission_audit && !use_fan)
        throw std::runtime_error("--audit-permissions requires an enabled fanotify module");
    if (options_.modules != Options::Modules::fanotify_only || options_.permission_audit)
        audit_ = std::make_unique<AuditSink>();
    // 所有启动失败都通过对象逆序析构回收；任一模块失败，整个服务启动失败。
    if (use_fan) {
        if (active.fanotify) apply_fanotify_policy(active, fan_options);
        fanotify_ = std::make_unique<FanotifyMonitor>(std::move(fan_options), options_.policy_path,
            options_.permission_audit ? audit_.get() : nullptr, runtime_.snapshot(management::Backend::fanotify).instance_ns, active.revision, options_.requester_pidfd);
    }
    // Pin actual fanotify objects before BPF preparation so cross-backend
    // read conflicts are checked against the exact retained inode references.
    if (options_.modules != Options::Modules::fanotify_only)
        bpf_ = std::make_unique<BpfMonitor>(active, control_ != nullptr, *audit_,
                                          fanotify_ ? fanotify_->target_fds() : std::vector<int>{});
    std::cerr << "Policy active revision=" << active.revision << '\n';
    std::cerr << "Service active; bpf=" << bool(bpf_) << " fanotify=" << bool(fanotify_) << '\n';
}
MonitorService::~MonitorService() = default;
void MonitorService::commit(const PolicyConfig &candidate)
{
    if (!bpf_ && (!candidate.vaults.empty() || candidate.canary_response))
        throw std::runtime_error("Vault/canary policy requires the BPF module");
    if (!fanotify_ && candidate.fanotify && options_.modules != Options::Modules::bpf_only)
        throw management::Error(management::Code::restart_required, "Enabling fanotify requires restart");
    if (fanotify_) fanotify_->validate_candidate(candidate); // Reject unsafe rebind before VFS preparation.
    auto paths = bpf_ ? candidate.paths : std::vector<std::string>{};
    if (bpf_) for (const auto &writer : candidate.writers) paths.push_back(writer.path);
    // Include active-boot grants only: stale boot grants must not require a
    // program which may no longer exist (same rule as ProtectedFiles).
    const auto boot = (!bpf_ || candidate.vault_sessions.empty()) ? std::string() : secmon_clock::boot_id();
    if (bpf_) for (const auto &session : candidate.vault_sessions)
        if (session.boot_id == boot) paths.push_back(session.program);
    if (fanotify_ && candidate.fanotify) for (const auto &path : candidate.fanotify->paths) {
        const auto &old = runtime_.active().fanotify;
        if (!old || candidate.fanotify->rebind_epoch > old->rebind_epoch ||
            std::find(old->paths.begin(), old->paths.end(), path) == old->paths.end()) paths.push_back(path);
    }
    PolicyPins pins(paths, [this] { preparation_progress(); });
    std::optional<FanotifyMonitor::Prepared> next;
    if (fanotify_) next = fanotify_->prepare(candidate);
    else if (candidate.fanotify && options_.modules != Options::Modules::bpf_only)
        throw management::Error(management::Code::restart_required, "Enabling fanotify requires restart");
    // prepare 完成所有可能失败的 fanotify 检查。BPF install 内部先准备完整候选再原子替换 Map。
    // 若 BPF 失败，两个模块保持旧策略；一旦成功，余下提交仅做 noexcept 的值移动。
    if (bpf_) bpf_->install(candidate, next ? fanotify_->prepared_target_fds(*next) : std::vector<int>{});
    if (fanotify_) fanotify_->commit(std::move(*next), candidate.revision);
    // 这是用户态提交顺序保证，不声称不同内核钩子或在途系统调用的全局原子切换。
}
void MonitorService::preparation_progress()
{
    if (control_) control_->dispatch([this](ControlCommand command) {
        if (command == ControlCommand::stop) stopping.store(true, std::memory_order_relaxed);
        if (command == ControlCommand::reload) runtime_.reject_busy();
        auto reply = snapshot();
        if (command == ControlCommand::reload) reply.code = management::Code::busy;
        return reply;
    });
    if (run_deadline_ != std::chrono::steady_clock::time_point{} &&
        std::chrono::steady_clock::now() >= run_deadline_)
        stopping.store(true, std::memory_order_relaxed);
    if (stopping.load(std::memory_order_relaxed)) throw std::runtime_error("Policy preparation cancelled by stop");
    if (decoy_) decoy_->poll_once();
    if (bpf_) bpf_->poll_once(0);
    if (fanotify_) fanotify_->poll_once(0);
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
        reply.vault_paths = runtime_.active().vaults.size();
        reply.canary_paths = runtime_.active().canaries.size();
        bpf_->snapshot(reply);
        if (control_) reply.flags |= management::self_protected;
    }
    if (options_.permission_audit) reply.flags |= management::permission_audit;
    if (options_.requester_pidfd) reply.flags |= management::requester_pidfd;
    if (audit_) {
        const auto audit = audit_->stats();
        reply.audit_written = audit.written;
        reply.audit_dropped = audit.dropped;
        reply.audit_invalid = audit.invalid;
        reply.audit_queued = audit.queued;
        reply.audit_errno = audit.output_errno;
    }
    if (fanotify_) fanotify_->snapshot(reply);
    if (decoy_) decoy_->snapshot(reply);
    return reply;
}
void MonitorService::run()
{
    const std::vector<int> no_targets;
    const auto started = std::chrono::steady_clock::now();
    if (options_.run_seconds) run_deadline_ = started + std::chrono::seconds(options_.run_seconds);
    auto next_report = started + std::chrono::seconds(10);
    while (!stopping.load(std::memory_order_relaxed)) {
        PolicyPins::reap();
        EventReader::reap();
        if (decoy_) decoy_->poll_once();
        if (options_.run_seconds && std::chrono::steady_clock::now() - started >= std::chrono::seconds(options_.run_seconds)) break;
        if (control_) control_->dispatch([&](ControlCommand command) {
            auto code = management::Code::ok;
            if (command == ControlCommand::stop) stopping.store(true, std::memory_order_relaxed);
            else if (command == ControlCommand::reload) {
                code = runtime_.reload([&](const PolicyConfig &candidate) { commit(candidate); }, fanotify_ ? fanotify_->target_fds() : no_targets);
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
        if (audit_ && std::chrono::steady_clock::now() >= next_report) {
            if (bpf_) bpf_->report();
            report_audit_stats(audit_->stats());
            next_report = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        }
    }
    if (fanotify_) fanotify_->shutdown();
    if (bpf_) bpf_->shutdown();
    if (audit_) audit_->shutdown();
    if (bpf_) bpf_->report();
    if (audit_) report_audit_stats(audit_->stats());
    // 审计流继续使用 stdout JSONL；混合模式的结束统计写 stderr，避免污染事件消费者。
    if (fanotify_) fanotify_->report(audit_ ? std::cerr : std::cout);
    PolicyPins::reap();
    EventReader::reap();
}
