// SPDX-License-Identifier: MIT
// 同包组件的当前本地管理布局；ABI 仅用于发现不匹配，不协商或转换历史格式。
#pragma once
#include "content_digest.h"
#include "analysis/protocol.h"
#include "decoy/mount_identity.h"
#include "fanotify/reader_error.h"
#include <cstdint>
#include <stdexcept>
#include <string>

namespace management {
constexpr std::uint32_t magic = 0x53434d43;
constexpr std::uint16_t version = 11;
enum class Command : std::uint32_t { stop = 1, reload = 2, status = 3 };
// 这些 code 描述管理操作结果，不能拿来代替 fanotify 的 Result 或内核钩子返回的负 errno。
enum class Code : std::uint32_t {
    ok = 0, no_policy = 1, not_newer = 2, invalid_policy = 3,
    prepare_failed = 4, busy = 5, restart_required = 6, internal_error = 7
};
enum class Backend : std::uint32_t { bpf = 1, fanotify = 2, combined = 3 };
enum class ProviderError : std::uint32_t { none = 0, disconnected = 1, protocol = 2, transport = 3, sequence = 4 };
enum class ProviderState : std::uint32_t { none = 0, responsive = 1, unresponsive = 2, offline = 3 };
enum class ReaderState : std::uint32_t { none = 0, responsive = 1, unresponsive = 2, offline = 3 };
constexpr std::uint64_t reader_stall_ms = 2000;
enum Flag : std::uint32_t { configured = 1, self_protected = 2, analyzer = 4, analyzer_online = 8, permission_audit = 16, requester_pidfd = 32 };
// 只描述服务内存中的活动状态，查询不读取磁盘配置、不执行到期处理、不重启分析器。
struct Reply {
    std::uint32_t magic_value = magic;
    std::uint16_t abi = version;
    std::uint16_t size = sizeof(Reply);
    Command command = Command::status;
    Code code = Code::ok;
    Backend backend = Backend::bpf;
    std::uint32_t flags = 0;
    std::uint64_t revision = 0;
    // 候选版本仅在成功读出配置后才可知；
    // 读取/语法失败时为 0，活动 revision 仍保留旧值。
    std::uint64_t last_attempt_revision = 0;
    std::uint64_t instance_ns = 0;
    std::uint64_t uptime_ms = 0;
    std::uint64_t reloads = 0;
    std::uint64_t rejections = 0;
    std::uint64_t allowed = 0;
    std::uint64_t denied = 0;
    std::uint64_t analysis_errors = 0;
    std::uint64_t analysis_failures = 0;
    std::uint64_t overflow = 0;
    std::uint32_t pid = 0;
    std::uint32_t protected_paths = 0;
    std::uint32_t pending = 0;
    std::uint32_t peak_pending = 0;
    std::uint32_t event = 0; // 0=BPF, 1=open, 2=access, 3=exec（不复用内核 mask）。
    std::uint32_t mode = 0; // 0=BPF, 1=static allow, 2=static deny, 3=analysis。
    std::uint32_t delay_ms = 0;
    std::uint32_t timeout_ms = 0;
    std::uint32_t max_pending = 0;
    std::uint32_t fallbacks = 0; // bit 0/1/2 对应 timeout/overload/analyzer error 的 allow。
    std::int32_t worker_pid = -1;
    std::uint32_t scan_limit = 0;
    // 当前 status 的 code 通常为 ok，但 last_code 保留最近一次重载结果；
    // 查询不会清除诊断历史。
    Code last_code = Code::ok;
    std::uint32_t reserved = 0;
    ContentDigest source_digest{};
    // 单文件扫描错误与后端故障分开描述，原因计数遵循总量守恒。
    analysis::ScanError last_scan_error = analysis::ScanError::none;
    std::int32_t last_scan_errno = 0;
    std::uint64_t backend_error_requests = 0;
    std::array<std::uint64_t, analysis::scan_error_count> scan_errors{};
    // 显式 writer 路径条数，不等同不同 inode 数。
    std::uint32_t writer_paths = 0;
    std::uint32_t fanotify_targets = 0;
    // 用户态出口计数与内核 ringbuf_dropped 分开；written 只计完整写出的 JSONL。
    std::uint64_t audit_written = 0;
    std::uint64_t audit_dropped = 0;
    std::uint64_t audit_invalid = 0;
    std::uint32_t audit_queued = 0;
    std::int32_t audit_errno = 0;
    // stderr 与 stdout 审计各自有独立预算；所有监控后端都提供诊断出口状态。
    std::uint64_t diagnostic_written = 0;
    std::uint64_t diagnostic_dropped = 0;
    std::uint64_t diagnostic_invalid = 0;
    std::uint32_t diagnostic_queued = 0;
    std::int32_t diagnostic_errno = 0;
    std::uint32_t vault_paths = 0;
    std::uint32_t vault_sessions = 0; // Configured sessions, including expired ones.
    std::uint32_t vault_live_sessions = 0; // Clock sample; never an authorization token.
    std::uint32_t vault_session_history = 0;
    std::uint32_t vault_clock_valid = 0;
    std::uint32_t vault_stale_sessions = 0;
    std::uint32_t canary_paths = 0;
    std::uint32_t response_duration_ms = 0;
    std::uint64_t response_epoch = 0;
    std::uint64_t response_started = 0;
    std::uint64_t response_failed = 0;
    std::uint64_t response_denied = 0;
    std::uint64_t vault_next_deadline_boot_ns = 0; // Earliest configured deadline, even if expired.
    std::int32_t reader_pid = -1;
    ReaderState reader_state = ReaderState::none;
    std::uint64_t reader_progress_age_ms = 0;
    std::int32_t decoy_provider_pid = -1;
    ProviderState decoy_provider_state = ProviderState::none;
    std::uint64_t decoy_provider_progress_age_ms = 0;
    std::uint32_t decoy_files = 0;
    ProviderError decoy_provider_error = ProviderError::none;
    std::uint64_t decoy_mount_id = 0;
    decoy::MountState decoy_mount_state = decoy::MountState::none;
    std::int32_t decoy_mount_errno = 0;
    std::uint64_t decoy_mount_sample_age_ms = 0;
    ReaderFailure reader_failure = ReaderFailure::none;
    std::uint32_t reader_reserved = 0;
    std::uint64_t reader_failures = 0, reader_error_requests = 0, reader_unconfirmed_requests = 0;
};
// 只约束当前完整结构的布局；调整字段时同步修改本包两端与测试，不保留历史前缀。
static_assert(sizeof(Reply) == 528);
class Error : public std::runtime_error {
    Code code_;
public:
    Error(Code code, const std::string &detail) : std::runtime_error(detail), code_(code) {}
    Code code() const { return code_; }
};
const char *code_name(Code code);
const char *command_name(Command command);
// expected 绑定本次请求的命令，拒绝把 reload 响应当作 status；
// 校验失败时不能继续渲染字段。
void validate_reply(const Reply &reply, Command expected);
std::string reply_json(const Reply &reply);
}
