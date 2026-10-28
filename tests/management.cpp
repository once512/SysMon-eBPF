// SPDX-License-Identifier: MIT
// 无特权校验本地管理 ABI 与 JSON 边界；真实服务、权限与 FD 附件另由权限专题覆盖。
#include "management/protocol.h"
#include "policy_runtime.h"
#include <iostream>
#include <cerrno>
#include <stdexcept>
#include <unistd.h>

void require(bool condition) { if (!condition) throw std::runtime_error("Management assertion failed"); }
int main()
{
    require(digest_hex(content_digest("")) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    require(digest_hex(content_digest("abc")) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    require(content_digest("abc") != content_digest("abc\n"));
    using namespace management;
    PolicyConfig initial;
    initial.paths = {"/one", "/two"};
    PolicyRuntime runtime("", initial);
    auto r = runtime.snapshot(Backend::bpf);
    require(r.revision == 0 && !r.flags && r.last_code == Code::ok);
    require(runtime.reload([](const PolicyConfig &) { throw std::runtime_error("must not call"); }) == Code::no_policy);
    r = runtime.snapshot(Backend::bpf);
    require(r.rejections == 1 && r.reloads == 0 && r.last_attempt_revision == 0 && r.last_code == Code::no_policy);
    validate_reply(r, Command::status);
    const auto text = reply_json(r);
    require(text.find("\"backend\":\"bpf\"") != std::string::npos && text.find("\"last_code\":\"no_policy\"") != std::string::npos);
    auto reject = [&](auto mutate) {
        auto bad = r;
        mutate(bad);
        try { validate_reply(bad, Command::status); } catch (const std::runtime_error &) { return; }
        throw std::runtime_error("Bad management response accepted");
    };
    reject([](Reply &x) { x.decoy_provider_state = static_cast<ProviderState>(99); });
    reject([](Reply &x) { x.decoy_files = 65; });
    reject([](Reply &x) { x.decoy_provider_pid = 123; });
    reject([](Reply &x) { x.decoy_provider_progress_age_ms = 1; });
    reject([](Reply &x) { x.decoy_provider_error = static_cast<ProviderError>(99); });
    reject([](Reply &x) { x.reader_pid = 123; });
    reject([](Reply &x) { x.reader_state = static_cast<ReaderState>(99); });
    reject([](Reply &x) { x.reader_progress_age_ms = 1; });
    reject([](Reply &x) { x.magic_value = 0; });
    reject([](Reply &x) { ++x.abi; });
    reject([](Reply &x) { --x.size; });
    reject([](Reply &x) { x.command = Command::reload; });
    reject([](Reply &x) { x.code = static_cast<Code>(99); });
    reject([](Reply &x) { x.last_code = static_cast<Code>(99); });
    reject([](Reply &x) { x.backend = static_cast<Backend>(99); });
    reject([](Reply &x) { x.flags = 64; });
    reject([](Reply &x) { x.flags = requester_pidfd; });
    reject([](Reply &x) { x.flags |= permission_audit; });
    reject([](Reply &x) { x.fallbacks = 8; });
    reject([](Reply &x) { x.protected_paths = 257; });
    reject([](Reply &x) { x.pending = 4097; });
    reject([](Reply &x) { x.peak_pending = 4097; });
    reject([](Reply &x) { x.event = 4; });
    reject([](Reply &x) { x.mode = 4; });
    reject([](Reply &x) { x.pid = 0; });
    reject([](Reply &x) { x.instance_ns = 0; });
    reject([](Reply &x) { x.reserved = 1; });
    reject([](Reply &x) { x.vault_stale_sessions = 1; });
    reject([](Reply &x) { x.vault_clock_valid = 2; });
    reject([](Reply &x) { x.vault_paths = 1; });
    reject([](Reply &x) { x.vault_sessions = 17; });
    reject([](Reply &x) { x.vault_session_history = 4097; });
    reject([](Reply &x) { x.vault_live_sessions = 1; });
    reject([](Reply &x) { x.vault_next_deadline_boot_ns = 1; });
    reject([](Reply &x) { x.writer_paths = 65; });
    reject([](Reply &x) { x.canary_paths = 1; });
    reject([](Reply &x) { x.response_epoch = 1; });
    reject([](Reply &x) { x.response_duration_ms = 100; });
    reject([](Reply &x) { x.fanotify_targets = 65; });
    reject([](Reply &x) { x.fanotify_targets = 1; });
    reject([](Reply &x) { x.audit_queued = 1025; });
    reject([](Reply &x) { x.audit_errno = -1; });
    reject([](Reply &x) { x.audit_errno = 4096; });
    reject([](Reply &x) { x.diagnostic_queued = 257; });
    reject([](Reply &x) { x.diagnostic_errno = -1; });
    reject([](Reply &x) { x.diagnostic_errno = 4096; });
    reject([](Reply &x) { x.diagnostic_invalid = 1; });
    reject([](Reply &x) { x.decoy_mount_state = static_cast<decoy::MountState>(99); });
    reject([](Reply &x) { x.decoy_mount_id = 123; });
    reject([](Reply &x) { x.decoy_mount_errno = 1; });
    reject([](Reply &x) { x.decoy_mount_sample_age_ms = 1; });
    reject([](Reply &x) { x.decoy_mount_errno = -1; });
    reject([](Reply &x) { x.decoy_mount_errno = 4096; });
    r.decoy_mount_id = 123; r.decoy_mount_state = decoy::MountState::attached;
    r.decoy_files = 2; r.decoy_provider_pid = 123; r.decoy_provider_state = ProviderState::responsive;
    reject([](Reply &x) { x.decoy_mount_id = 0; });
    reject([](Reply &x) { x.decoy_mount_state = decoy::MountState::none; });
    reject([](Reply &x) { x.decoy_mount_state = decoy::MountState::unknown; });
    for (const auto state : {decoy::MountState::covered, decoy::MountState::moved, decoy::MountState::detached}) {
        auto sample = r; sample.decoy_mount_state = state; validate_reply(sample, Command::status);
    }
    auto unknown = r; unknown.decoy_mount_state = decoy::MountState::unknown; unknown.decoy_mount_errno = EIO;
    validate_reply(unknown, Command::status);
    unknown.decoy_mount_id = 0; unknown.decoy_mount_errno = ENODATA; validate_reply(unknown, Command::status);
    reject([](Reply &x) { x.decoy_files = 0; });
    reject([](Reply &x) { x.decoy_provider_pid = -1; });
    reject([](Reply &x) { x.decoy_provider_state = ProviderState::unresponsive; });
    reject([](Reply &x) { x.decoy_provider_progress_age_ms = reader_stall_ms; });
    r.decoy_provider_state = ProviderState::offline; r.decoy_provider_pid = -1; r.decoy_provider_error = ProviderError::disconnected;
    require(reply_json(r).find("\"decoy_provider_state\":\"offline\"") != std::string::npos);
    r.decoy_mount_id = 0; r.decoy_mount_state = decoy::MountState::none;
    r.decoy_files = 0; r.decoy_provider_state = ProviderState::none; r.decoy_provider_error = ProviderError::none;
    r.diagnostic_written = 5;
    r.diagnostic_dropped = 2;
    r.diagnostic_invalid = 1;
    require(reply_json(r).find("\"diagnostic_written\":5") != std::string::npos);
    r.writer_paths = 64;
    require(reply_json(r).find("\"writer_paths\":64") != std::string::npos);
    r.writer_paths = 0;
    reject([](Reply &x) { x.last_scan_error = static_cast<analysis::ScanError>(99); });
    reject([](Reply &x) { x.last_scan_errno = -1; });
    reject([](Reply &x) { x.backend_error_requests = 1; });
    reject([](Reply &x) { x.scan_errors[0] = 1; });
    reject([](Reply &x) { x.scan_errors[5] = 1; });
    reject([](Reply &x) { x.analysis_errors = UINT64_MAX; x.backend_error_requests = UINT64_MAX; x.scan_errors[5] = 1; });
    r.backend = Backend::fanotify; r.event = 2; r.mode = 3; r.flags |= analyzer | analyzer_online;
    r.fanotify_targets = 1; r.reader_pid = 123; r.reader_state = ReaderState::responsive;
    reject([](Reply &x) { x.reader_pid = -1; });
    reject([](Reply &x) { x.reader_state = ReaderState::none; });
    reject([](Reply &x) { x.reader_state = static_cast<ReaderState>(99); });
    reject([](Reply &x) { x.reader_progress_age_ms = reader_stall_ms; });
    r.reader_progress_age_ms = reader_stall_ms; r.reader_state = ReaderState::unresponsive;
    require(reply_json(r).find("\"reader_state\":\"unresponsive\"") != std::string::npos);
    r.reader_progress_age_ms = 0; r.reader_state = ReaderState::responsive;
    r.pending = 1; r.peak_pending = 3; r.max_pending = 4; r.fallbacks = 5;
    require(reply_json(r).find("\"permission_event\":\"access\"") != std::string::npos);
    require(reply_json(r).find("\"analyzer_online\":true") != std::string::npos);
    r.flags |= permission_audit;
    r.audit_written = 12;
    const auto fan_audit = reply_json(r);
    require(fan_audit.find("\"permission_audit\":true") != std::string::npos);
    require(fan_audit.find("\"audit_written\":12") != std::string::npos);
    r.flags |= requester_pidfd;
    require(reply_json(r).find("\"requester_pidfd\":true") != std::string::npos);
    r.analysis_errors = 3; r.backend_error_requests = 1; r.scan_errors[5] = 2;
    r.last_scan_error = analysis::ScanError::oversized;
    require(reply_json(r).find("\"oversized\":2") != std::string::npos);
    r.backend = Backend::combined;
    r.protected_paths = 2; r.writer_paths = 1; r.flags |= self_protected;
    r.audit_dropped = 7;
    const auto combined = reply_json(r);
    require(combined.find("\"audit_dropped\":7") != std::string::npos);
    require(combined.find("\"backend\":\"combined\"") != std::string::npos);
    require(combined.find("\"protected_paths\":2") != std::string::npos);
    require(combined.find("\"permission_event\":\"access\"") != std::string::npos);
    std::cout << "PASS management framing, status rendering and no-policy reload isolation\n";
}
