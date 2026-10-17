// SPDX-License-Identifier: MIT
// 纯统计数据：不拥有 group、队列或分析进程，日志渲染不必依赖 PermissionGate 的实现。
// scan_errors 与 backend_error_requests 拆分 analyzer_error，不额外增加业务回复总数。
#pragma once
#include "analysis/protocol.h"
#include <array>
#include <cstddef>
#include <cstdint>

struct GateStats {
    std::uint64_t allowed = 0;
    std::uint64_t denied = 0;
    std::uint64_t overflow = 0;
    std::uint64_t timed_out = 0;
    std::uint64_t overloaded = 0;
    std::uint64_t shutdown_denied = 0;
    std::uint64_t analyzed = 0;
    std::uint64_t analysis_denied = 0;
    std::uint64_t analyzer_error = 0;
    std::uint64_t analyzer_failures = 0;
    std::uint64_t backend_error_requests = 0;
    std::array<std::uint64_t, analysis::scan_error_count> scan_errors{};
    analysis::ScanError last_scan_error = analysis::ScanError::none;
    int last_scan_errno = 0;
    std::size_t peak_pending = 0;
};
