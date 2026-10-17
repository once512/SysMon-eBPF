// SPDX-License-Identifier: MIT
// root 本地管理协议，与 BPF 事件 ABI/分析器 ABI 分开版本化；不传指针、字符串或 FD。
#pragma once
#include "content_digest.h"
#include "analysis/protocol.h"
#include <cstdint>
#include <stdexcept>
#include <string>

namespace management {
constexpr std::uint32_t magic = 0x53434d43;
constexpr std::uint16_t version = 3;
enum class Command : std::uint32_t { stop = 1, reload = 2, status = 3 };
enum class Code : std::uint32_t {
    ok = 0, no_policy = 1, not_newer = 2, invalid_policy = 3,
    prepare_failed = 4, busy = 5, restart_required = 6, internal_error = 7
};
enum class Backend : std::uint32_t { bpf = 1, fanotify = 2 };
enum Flag : std::uint32_t { configured = 1, self_protected = 2, analyzer = 4, analyzer_online = 8 };
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
    Code last_code = Code::ok;
    std::uint32_t reserved = 0;
    ContentDigest source_digest{};
    // v1 的前 200 字节保持布局；v2 附加扫描原因，旧客户端可继续请求 v1 前缀。
    analysis::ScanError last_scan_error = analysis::ScanError::none;
    std::int32_t last_scan_errno = 0;
    std::uint64_t backend_error_requests = 0;
    std::array<std::uint64_t, analysis::scan_error_count> scan_errors{};
    // v3 追加显式 writer 路径数，不把路径条数误当不同 inode 数；旧前缀保持逐字节布局。
    std::uint32_t writer_paths = 0;
    std::uint32_t reserved_v3 = 0;
};
static_assert(sizeof(Reply) == 296);
static_assert(offsetof(Reply, last_scan_error) == 200);
static_assert(offsetof(Reply, writer_paths) == 288);
class Error : public std::runtime_error {
    Code code_;
public:
    Error(Code code, const std::string &detail) : std::runtime_error(detail), code_(code) {}
    Code code() const { return code_; }
};
const char *code_name(Code code);
const char *command_name(Command command);
void validate_reply(const Reply &reply, Command expected);
std::string reply_json(const Reply &reply);
}
