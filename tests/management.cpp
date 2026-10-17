// SPDX-License-Identifier: MIT
// 无特权校验本地管理 ABI 与 JSON 边界；真实服务、权限与 FD 附件另由权限专题覆盖。
#include "management/protocol.h"
#include "policy_runtime.h"
#include <iostream>
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
    reject([](Reply &x) { x.magic_value = 0; });
    reject([](Reply &x) { ++x.abi; });
    reject([](Reply &x) { --x.size; });
    reject([](Reply &x) { x.command = Command::reload; });
    reject([](Reply &x) { x.code = static_cast<Code>(99); });
    reject([](Reply &x) { x.last_code = static_cast<Code>(99); });
    reject([](Reply &x) { x.backend = static_cast<Backend>(99); });
    reject([](Reply &x) { x.flags = 16; });
    reject([](Reply &x) { x.fallbacks = 8; });
    reject([](Reply &x) { x.protected_paths = 257; });
    reject([](Reply &x) { x.pending = 4097; });
    reject([](Reply &x) { x.peak_pending = 4097; });
    reject([](Reply &x) { x.event = 4; });
    reject([](Reply &x) { x.mode = 4; });
    reject([](Reply &x) { x.pid = 0; });
    reject([](Reply &x) { x.instance_ns = 0; });
    reject([](Reply &x) { x.reserved = 1; });
    reject([](Reply &x) { x.writer_paths = 65; });
    reject([](Reply &x) { x.reserved_v3 = 1; });
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
    r.pending = 1; r.peak_pending = 3; r.max_pending = 4; r.fallbacks = 5;
    require(reply_json(r).find("\"permission_event\":\"access\"") != std::string::npos);
    require(reply_json(r).find("\"analyzer_online\":true") != std::string::npos);
    r.analysis_errors = 3; r.backend_error_requests = 1; r.scan_errors[5] = 2;
    r.last_scan_error = analysis::ScanError::oversized;
    require(reply_json(r).find("\"oversized\":2") != std::string::npos);
    std::cout << "PASS management framing, status rendering and no-policy reload isolation\n";
}
