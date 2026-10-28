// SPDX-License-Identifier: MIT
// 私有定长报文先校验再解释；CLI 仅输出固定枚举和数值，配置路径等非可信字符串不进入 JSON。
#include <secmon/policy_limits.h>
#include <secmon/audit_limits.h>
#include <secmon/diagnostic_limits.h>
#include "protocol.h"
#include <sstream>

namespace management {
const char *code_name(Code code)
{
    switch (code) {
    case Code::ok: return "ok";
    case Code::no_policy: return "no_policy";
    case Code::not_newer: return "not_newer";
    case Code::invalid_policy: return "invalid_policy";
    case Code::prepare_failed: return "prepare_failed";
    case Code::busy: return "busy";
    case Code::restart_required: return "restart_required";
    case Code::internal_error: return "internal_error";
    }
    return nullptr;
}
const char *command_name(Command command)
{
    switch (command) {
    case Command::stop: return "stop";
    case Command::reload: return "reload";
    case Command::status: return "status";
    }
    return nullptr;
}
void validate_reply(const Reply &r, Command expected)
{
    // 这是外部输入边界，错误值一律先拒绝；
    // 渲染函数不应靠“服务通常不会发错”来避免越界。
    if (r.magic_value != magic || r.abi != version || r.size != sizeof(r) || r.command != expected ||
        !command_name(r.command) || !code_name(r.code) || !code_name(r.last_code) || !r.pid || !r.instance_ns || r.reserved ||
        (r.flags & ~63U) || ((r.flags & requester_pidfd) && !(r.flags & permission_audit)) || ((r.flags & permission_audit) && r.backend == Backend::bpf) || (r.fallbacks & ~7U) ||
        r.vault_stale_sessions > r.vault_sessions || r.vault_clock_valid > 1 ||
        r.vault_paths > r.protected_paths || r.vault_sessions > SECMON_MAX_VAULT_SESSIONS ||
        r.vault_session_history > SECMON_MAX_VAULT_SESSION_HISTORY ||
        r.vault_session_history < r.vault_sessions - r.vault_stale_sessions ||
        r.vault_live_sessions > r.vault_sessions - r.vault_stale_sessions ||
        (!r.vault_clock_valid && r.vault_live_sessions) ||
        (r.vault_sessions && !r.vault_paths) ||
        ((r.vault_sessions != r.vault_stale_sessions) && !r.vault_next_deadline_boot_ns) ||
        (r.vault_sessions == r.vault_stale_sessions && r.vault_next_deadline_boot_ns) ||
        (r.backend == Backend::fanotify && (r.vault_paths || r.vault_sessions || r.vault_session_history || r.vault_clock_valid)) ||
        r.canary_paths > r.protected_paths ||
        (r.canary_paths && !r.response_epoch) ||
        (r.response_epoch ? (r.response_duration_ms < 100 || r.response_duration_ms > 3600000) : r.response_duration_ms != 0) ||
        (r.backend == Backend::fanotify && (r.canary_paths || r.response_epoch || r.response_started || r.response_failed || r.response_denied)) ||
        r.reader_reserved || static_cast<unsigned>(r.reader_failure) > static_cast<unsigned>(ReaderFailure::resource) ||
        r.reader_error_requests > r.denied ||
        ((r.reader_error_requests || r.reader_unconfirmed_requests) && !r.reader_failures) ||
        (r.backend == Backend::bpf ?
            (r.reader_pid != -1 || r.reader_state != ReaderState::none || r.reader_progress_age_ms ||
             r.reader_failure != ReaderFailure::none || r.reader_failures || r.reader_error_requests || r.reader_unconfirmed_requests) :
            (r.reader_state == ReaderState::offline ?
                (r.reader_pid != -1 || r.reader_failure == ReaderFailure::none || !r.reader_failures) :
                (r.reader_pid <= 0 || r.reader_failure != ReaderFailure::none ||
                 (r.reader_state != ReaderState::responsive && r.reader_state != ReaderState::unresponsive) ||
                 ((r.reader_state == ReaderState::responsive) != (r.reader_progress_age_ms < reader_stall_ms))))) ||
        static_cast<unsigned>(r.decoy_provider_error) > static_cast<unsigned>(ProviderError::sequence) ||
        ((r.decoy_provider_state == ProviderState::offline) != (r.decoy_provider_error != ProviderError::none)) ||
        r.decoy_files > 64 ||
        static_cast<unsigned>(r.decoy_mount_state) > static_cast<unsigned>(decoy::MountState::unknown) ||
        r.decoy_mount_errno < 0 || r.decoy_mount_errno > 4095 ||
        (r.decoy_mount_state == decoy::MountState::unknown ? !r.decoy_mount_errno : r.decoy_mount_errno != 0) ||
        (r.decoy_files ? (r.decoy_mount_state == decoy::MountState::none ||
            (!r.decoy_mount_id && r.decoy_mount_state != decoy::MountState::unknown)) :
            (r.decoy_mount_id || r.decoy_mount_state != decoy::MountState::none || r.decoy_mount_sample_age_ms)) ||
        (r.decoy_provider_state == ProviderState::none ?
            (r.decoy_files || r.decoy_provider_pid != -1 || r.decoy_provider_progress_age_ms) :
            (!r.decoy_files || r.decoy_provider_pid == 0 || r.decoy_provider_pid < -1 ||
             (r.decoy_provider_state != ProviderState::responsive && r.decoy_provider_state != ProviderState::unresponsive && r.decoy_provider_state != ProviderState::offline) ||
             (r.decoy_provider_state != ProviderState::offline &&
              (r.decoy_provider_pid <= 0 || ((r.decoy_provider_state == ProviderState::responsive) != (r.decoy_provider_progress_age_ms < reader_stall_ms)))))) ||
        r.fanotify_targets > SECMON_MAX_FANOTIFY_TARGETS ||
        (r.backend == Backend::bpf ? r.fanotify_targets != 0 : r.fanotify_targets == 0) ||
        r.protected_paths > SECMON_MAX_PROTECTED_PATHS || r.writer_paths > SECMON_MAX_WRITER_RULES ||
        r.diagnostic_queued > SECMON_DIAGNOSTIC_MAX_RECORDS || r.diagnostic_errno < 0 || r.diagnostic_errno > 4095 ||
        r.diagnostic_invalid > r.diagnostic_dropped ||
        r.audit_queued > SECMON_AUDIT_MAX_RECORDS || r.audit_errno < 0 || r.audit_errno > 4095 ||
        r.pending > SECMON_MAX_PENDING || r.peak_pending > SECMON_MAX_PENDING || r.event > 3 || r.mode > 3 ||
        !analysis::valid_scan_error(r.last_scan_error, r.last_scan_errno) ||
        (r.backend != Backend::bpf && r.backend != Backend::fanotify && r.backend != Backend::combined))
        throw std::runtime_error("Invalid management response");
    // 原因拆分与总错误数保持守恒；用减法边界检查避免恶意计数触发求和溢出。
    if (r.scan_errors[0] || r.backend_error_requests > r.analysis_errors)
        throw std::runtime_error("Invalid management error accounting");
    // 先用总量减去已计数部分，再比较下一项，避免攻击性 uint64 计数相加回绕后绕过守恒校验。
    auto counted = r.backend_error_requests;
    for (std::size_t i = 1; i < r.scan_errors.size(); ++i) {
        if (r.scan_errors[i] > r.analysis_errors - counted)
            throw std::runtime_error("Invalid management error accounting");
        counted += r.scan_errors[i];
    }
    if (counted != r.analysis_errors) throw std::runtime_error("Incomplete management error accounting");
}
std::string reply_json(const Reply &r)
{
    validate_reply(r, r.command);
    if (!command_name(r.command)) throw std::runtime_error("Invalid management command");
    std::ostringstream out;
    out << "{\"protocol_version\":" << r.abi << ",\"command\":\"" << command_name(r.command)
        << "\",\"code\":\"" << code_name(r.code) << "\",\"backend\":\""
        << (r.backend == Backend::bpf ? "bpf" : (r.backend == Backend::fanotify ? "fanotify" : "combined")) << "\",\"pid\":" << r.pid
        << ",\"instance_ns\":" << r.instance_ns << ",\"uptime_ms\":" << r.uptime_ms
        << ",\"configured\":" << ((r.flags & configured) ? "true" : "false")
        << ",\"revision\":" << r.revision << ",\"reloads\":" << r.reloads << ",\"rejections\":" << r.rejections
        << ",\"last_code\":\"" << code_name(r.last_code) << "\",\"last_attempt_revision\":" << r.last_attempt_revision;
    out << ",\"source_sha256\":";
    if (r.flags & configured) out << '\"' << digest_hex(r.source_digest) << '\"';
    else out << "null";
    out << ",\"permission_audit\":" << ((r.flags & permission_audit) ? "true" : "false")
        << ",\"requester_pidfd\":" << ((r.flags & requester_pidfd) ? "true" : "false");
    out << ",\"diagnostic_written\":" << r.diagnostic_written << ",\"diagnostic_dropped\":" << r.diagnostic_dropped
        << ",\"diagnostic_invalid\":" << r.diagnostic_invalid << ",\"diagnostic_queued\":" << r.diagnostic_queued
        << ",\"diagnostic_errno\":" << r.diagnostic_errno;
    const char *provider_errors[] = {"none", "disconnected", "protocol", "transport", "sequence"};
    const char *provider_states[] = {"none", "responsive", "unresponsive", "offline"};
    static const char *mount_states[] = {"none", "attached", "covered", "moved", "detached", "unknown"};
    out << ",\"reader_failure\":\"" << reader_failure_name(r.reader_failure)
        << "\",\"reader_failures\":" << r.reader_failures << ",\"reader_error_requests\":" << r.reader_error_requests
        << ",\"reader_unconfirmed_requests\":" << r.reader_unconfirmed_requests;
    out << ",\"decoy_mount_id\":" << r.decoy_mount_id
        << ",\"decoy_mount_state\":\"" << mount_states[static_cast<unsigned>(r.decoy_mount_state)]
        << "\",\"decoy_mount_errno\":" << r.decoy_mount_errno
        << ",\"decoy_mount_sample_age_ms\":" << r.decoy_mount_sample_age_ms;
    out << ",\"decoy_provider_pid\":" << r.decoy_provider_pid
        << ",\"decoy_provider_state\":\"" << provider_states[static_cast<unsigned>(r.decoy_provider_state)]
        << "\",\"decoy_provider_progress_age_ms\":" << r.decoy_provider_progress_age_ms
        << ",\"decoy_files\":" << r.decoy_files
        << ",\"decoy_provider_error\":\"" << provider_errors[static_cast<unsigned>(r.decoy_provider_error)] << '"';
    // 按后端输出实际支持的字段，不给 BPF 状态填造 fanotify 的裁决业务计数。
    if (r.backend != Backend::fanotify)
        out << ",\"self_protected\":" << ((r.flags & self_protected) ? "true" : "false")
            << ",\"protected_paths\":" << r.protected_paths << ",\"writer_paths\":" << r.writer_paths
            << ",\"canary_paths\":" << r.canary_paths
            << ",\"response_epoch\":" << r.response_epoch << ",\"response_duration_ms\":" << r.response_duration_ms
            << ",\"response_started\":" << r.response_started << ",\"response_failed\":" << r.response_failed
            << ",\"response_denied\":" << r.response_denied
            << ",\"vault_paths\":" << r.vault_paths << ",\"vault_sessions\":" << r.vault_sessions
            << ",\"vault_live_sessions\":" << r.vault_live_sessions
            << ",\"vault_stale_sessions\":" << r.vault_stale_sessions
            << ",\"vault_session_history\":" << r.vault_session_history
            << ",\"vault_clock_valid\":" << (r.vault_clock_valid ? "true" : "false")
            << ",\"vault_next_deadline_boot_ns\":" << r.vault_next_deadline_boot_ns;
    if (r.backend != Backend::fanotify || (r.flags & permission_audit))
        out << ",\"audit_written\":" << r.audit_written << ",\"audit_dropped\":" << r.audit_dropped
            << ",\"audit_invalid\":" << r.audit_invalid << ",\"audit_queued\":" << r.audit_queued
            << ",\"audit_errno\":" << r.audit_errno;
    if (r.backend != Backend::bpf) {
        const char *events[] = {"none", "open", "access", "exec"};
        const char *modes[] = {"none", "allow", "deny", "analysis"};
        out << ",\"permission_event\":\"" << events[r.event] << "\",\"decision\":\"" << modes[r.mode]
            << "\",\"delay_ms\":" << r.delay_ms << ",\"timeout_ms\":" << r.timeout_ms
            << ",\"max_pending\":" << r.max_pending << ",\"pending\":" << r.pending << ",\"peak_pending\":" << r.peak_pending
            << ",\"timeout_allow\":" << ((r.fallbacks & 1) ? "true" : "false")
            << ",\"overload_allow\":" << ((r.fallbacks & 2) ? "true" : "false")
            << ",\"analyzer_error_allow\":" << ((r.fallbacks & 4) ? "true" : "false")
            << ",\"fanotify_targets\":" << r.fanotify_targets
            << ",\"reader_pid\":" << r.reader_pid
            << ",\"reader_state\":\"" << (r.reader_state == ReaderState::offline ? "offline" : r.reader_state == ReaderState::responsive ? "responsive" : "unresponsive")
            << "\",\"reader_progress_age_ms\":" << r.reader_progress_age_ms
            << ",\"analyzer_online\":" << ((r.flags & analyzer_online) ? "true" : "false")
            << ",\"analyzer_pid\":" << r.worker_pid << ",\"scan_limit_bytes\":" << r.scan_limit
            << ",\"allowed\":" << r.allowed << ",\"denied\":" << r.denied
            << ",\"analyzer_error\":" << r.analysis_errors << ",\"analyzer_failures\":" << r.analysis_failures
            << ",\"overflow\":" << r.overflow << ",\"backend_error_requests\":" << r.backend_error_requests
            << ",\"last_scan_error\":\"" << analysis::scan_error_name(r.last_scan_error)
            << "\",\"last_scan_errno\":" << r.last_scan_errno << ",\"scan_error_counts\":{";
        for (std::size_t i = 1; i < r.scan_errors.size(); ++i)
            out << (i == 1 ? "" : ",") << '\"' << analysis::scan_error_name(static_cast<analysis::ScanError>(i)) << "\":" << r.scan_errors[i];
        out << '}';
    }
    return out.str() + "}";
}
}
