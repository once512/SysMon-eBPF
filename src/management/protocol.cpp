// SPDX-License-Identifier: MIT
// 私有定长报文先校验再解释；CLI 仅输出固定枚举和数值，配置路径等非可信字符串不进入 JSON。
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
    if (r.magic_value != magic || r.abi != version || r.size != sizeof(r) || r.command != expected ||
        !code_name(r.code) || !code_name(r.last_code) || !r.pid || !r.instance_ns || r.reserved ||
        (r.flags & ~15U) || (r.fallbacks & ~7U) || r.protected_paths > 256 ||
        r.pending > 4096 || r.peak_pending > 4096 || r.event > 3 || r.mode > 3 ||
        (r.backend != Backend::bpf && r.backend != Backend::fanotify))
        throw std::runtime_error("Invalid management response");
}
std::string reply_json(const Reply &r)
{
    validate_reply(r, r.command);
    if (!command_name(r.command)) throw std::runtime_error("Invalid management command");
    std::ostringstream out;
    out << "{\"protocol_version\":" << r.abi << ",\"command\":\"" << command_name(r.command)
        << "\",\"code\":\"" << code_name(r.code) << "\",\"backend\":\""
        << (r.backend == Backend::bpf ? "bpf" : "fanotify") << "\",\"pid\":" << r.pid
        << ",\"instance_ns\":" << r.instance_ns << ",\"uptime_ms\":" << r.uptime_ms
        << ",\"configured\":" << ((r.flags & configured) ? "true" : "false")
        << ",\"revision\":" << r.revision << ",\"reloads\":" << r.reloads << ",\"rejections\":" << r.rejections
        << ",\"last_code\":\"" << code_name(r.last_code) << "\",\"last_attempt_revision\":" << r.last_attempt_revision;
    out << ",\"source_sha256\":";
    if (r.flags & configured) out << '\"' << digest_hex(r.source_digest) << '\"';
    else out << "null";
    if (r.backend == Backend::bpf)
        out << ",\"self_protected\":" << ((r.flags & self_protected) ? "true" : "false")
            << ",\"protected_paths\":" << r.protected_paths;
    else {
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
            << ",\"overflow\":" << r.overflow;
    }
    return out.str() + "}";
}
}
