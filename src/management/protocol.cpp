// SPDX-License-Identifier: MIT
// 私有定长报文先校验再解释；CLI 仅输出固定枚举和数值，配置路径等非可信字符串不进入 JSON。
#include <secmon/policy_limits.h>
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
        !code_name(r.code) || !code_name(r.last_code) || !r.pid || !r.instance_ns || r.reserved ||
        (r.flags & ~15U) || (r.fallbacks & ~7U) || r.protected_paths > SECMON_MAX_PROTECTED_PATHS || r.writer_paths > SECMON_MAX_WRITER_RULES || r.reserved_tail ||
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
    // 按后端输出实际支持的字段，不给 BPF 状态填造 fanotify 的裁决业务计数。
    if (r.backend != Backend::fanotify)
        out << ",\"self_protected\":" << ((r.flags & self_protected) ? "true" : "false")
            << ",\"protected_paths\":" << r.protected_paths << ",\"writer_paths\":" << r.writer_paths;
    if (r.backend != Backend::bpf) {
        const char *events[] = {"none", "open", "access", "exec"};
        const char *modes[] = {"none", "allow", "deny", "analysis"};
        out << ",\"permission_event\":\"" << events[r.event] << "\",\"decision\":\"" << modes[r.mode]
            << "\",\"delay_ms\":" << r.delay_ms << ",\"timeout_ms\":" << r.timeout_ms
            << ",\"max_pending\":" << r.max_pending << ",\"pending\":" << r.pending << ",\"peak_pending\":" << r.peak_pending
            << ",\"timeout_allow\":" << ((r.fallbacks & 1) ? "true" : "false")
            << ",\"overload_allow\":" << ((r.fallbacks & 2) ? "true" : "false")
            << ",\"analyzer_error_allow\":" << ((r.fallbacks & 4) ? "true" : "false")
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
