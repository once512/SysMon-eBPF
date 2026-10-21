// SPDX-License-Identifier: MIT
#include "fanotify/audit.h"
#include <secmon/audit_limits.h>
#include <cerrno>
#include <iostream>
#include <stdexcept>
#include <limits>
using namespace std::chrono_literals;
void require(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
int main()
{
    PermissionAuditIdentity identity{123, 321, 8, 1, 999, PermissionEvent::open, 4026531836ULL};
    PermissionRequest request{1, 77, 456, PendingDecisions::Clock::time_point(1ms)};
    const auto responded = PendingDecisions::Clock::time_point(3500us);
    const auto text = format_permission_decision(identity, request, {true, DecisionReason::policy}, responded);
    require(text == "{\"event\":\"fanotify_decision\",\"listener_pid\":321,\"instance_ns\":123,\"request_id\":1,"
                    "\"requester_pid\":456,\"requester_pid_kind\":\"tgid\",\"pid_namespace_inode\":4026531836,\"subscription_generation\":1,\"revision\":77,\"major\":8,\"minor\":1,\"inode\":999,"
                    "\"permission_event\":\"open\",\"decision\":\"allow\",\"reason\":\"policy\","
                    "\"scan_error\":\"none\",\"scan_errno\":0,\"received_ns\":1000000,\"responded_ns\":3500000,\"latency_us\":2500}\n",
            "stable permission reply identity, timestamps and reason fields");
    const DecisionReason reasons[] = {DecisionReason::timeout, DecisionReason::capacity, DecisionReason::shutdown,
                                      DecisionReason::analysis, DecisionReason::analyzer_error};
    const char *names[] = {"timeout", "capacity", "shutdown", "analysis", "analyzer_error"};
    for (unsigned i = 0; i < 5; ++i) {
        const auto line = format_permission_decision(identity, request, {false, reasons[i]}, responded);
        require(line.find(std::string("\"reason\":\"") + names[i] + '"') != std::string::npos,
                "every completion reason has stable encoding");
    }
    auto missing_namespace = identity;
    missing_namespace.pid_namespace_inode = 0;
    bool rejected_namespace = false;
    try { format_permission_decision(missing_namespace, request, {true, DecisionReason::policy}, responded); }
    catch (const std::invalid_argument &) { rejected_namespace = true; }
    require(rejected_namespace, "namespace identity cannot be silently omitted");
    auto zero_generation = identity;
    zero_generation.subscription_generation = 0;
    bool rejected_generation = false;
    try { format_permission_decision(zero_generation, request, {true, DecisionReason::policy}, responded); }
    catch (const std::invalid_argument &) { rejected_generation = true; }
    require(rejected_generation, "subscription generation cannot be omitted");
    identity.event = PermissionEvent::access;
    auto line = format_permission_decision(identity, request,
        {false, DecisionReason::analyzer_error, analysis::ScanError::read_failed, EIO}, responded);
    require(line.find("\"permission_event\":\"access\"") != std::string::npos &&
            line.find("\"scan_error\":\"read_failed\",\"scan_errno\":5") != std::string::npos,
            "typed scan error preserved with decision");
    auto reject = [&](auto mutate_request, Verdict verdict) {
        auto bad = request;
        mutate_request(bad);
        try { format_permission_decision(identity, bad, verdict, responded); }
        catch (const std::invalid_argument &) { return; }
        throw std::runtime_error("Invalid audit context accepted");
    };
    reject([](auto &r) { r.id = 0; }, {false, DecisionReason::policy});
    reject([](auto &r) { r.received = PendingDecisions::Clock::time_point(4ms); }, {false, DecisionReason::policy});
    reject([](auto &r) { r.received = PendingDecisions::Clock::time_point(-1ns); }, {false, DecisionReason::policy});
    reject([](auto &) {}, {false, static_cast<DecisionReason>(99)});
    reject([](auto &) {}, {false, DecisionReason::policy, analysis::ScanError::read_failed, EIO});
    reject([](auto &) {}, {false, DecisionReason::analyzer_error, analysis::ScanError::read_failed, -1});
    reject([](auto &r) { r.process.state = static_cast<ProcessReferenceState>(99); }, {true, DecisionReason::policy});
    reject([](auto &r) { r.process = {ProcessReferenceState::present, 0, 0}; }, {true, DecisionReason::policy});
    reject([](auto &r) { r.process = {ProcessReferenceState::present, 123, EIO}; }, {true, DecisionReason::policy});
    reject([](auto &r) { r.process.inode = 123; }, {true, DecisionReason::policy});
    for (auto state : {ProcessReferenceState::unavailable, ProcessReferenceState::error}) {
        request.process = {state, 0, 0};
        const auto encoded = format_permission_decision(identity, request, {true, DecisionReason::policy}, responded);
        require(encoded.find("\"requester_process_inode\":0") != std::string::npos, "missing identity cannot become a cookie");
    }
    request.process = {ProcessReferenceState::present, std::numeric_limits<std::uint64_t>::max(), 0};
    request.id = request.revision = identity.subscription_generation = identity.pid_namespace_inode = identity.instance_ns = identity.inode = std::numeric_limits<std::uint64_t>::max();
    identity.major = identity.minor = std::numeric_limits<std::uint32_t>::max();
    identity.event = PermissionEvent::exec;
    request.requester_pid = -1; // 内核原始值不会被 /proc 查询或无证据的 UID 字段替换。
    line = format_permission_decision(identity, request, {false, DecisionReason::shutdown}, responded);
    require(line.size() <= SECMON_AUDIT_MAX_LINE_BYTES && line.back() == '\n' &&
            line.find("\"requester_pid\":-1") != std::string::npos, "maximum numeric fields remain bounded");
    std::cout << "PASS permission audit identities, receive/reply clocks, all reasons and scan errors\n";
}
