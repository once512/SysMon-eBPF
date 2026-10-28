// SPDX-License-Identifier: MIT
// 裁决日志统一渲染，保留已有字段并增加错误原因拆分；原因数是子集，不能重复计算回复总量。
#include "stats.h"
void write_gate_stats(std::ostream &out, PermissionEvent event, const GateStats &s)
{
    out << "{\"permission_event\":\"" << permission_name(event) << "\",\"allowed\":" << s.allowed << ",\"denied\":" << s.denied
        << ",\"overflow\":" << s.overflow << ",\"timed_out\":" << s.timed_out << ",\"overloaded\":" << s.overloaded
        << ",\"shutdown_denied\":" << s.shutdown_denied << ",\"analysis_denied\":" << s.analysis_denied
        << ",\"analyzed\":" << s.analyzed << ",\"analyzer_error\":" << s.analyzer_error
        << ",\"analyzer_failures\":" << s.analyzer_failures << ",\"peak_pending\":" << s.peak_pending
        << ",\"target_updates\":" << s.target_updates
        << ",\"reader_failures\":" << s.reader_failures << ",\"reader_error_requests\":" << s.reader_error_requests << ",\"reader_unconfirmed_requests\":" << s.reader_unconfirmed_requests
        << ",\"backend_error_requests\":" << s.backend_error_requests << ",\"last_scan_error\":\""
        << analysis::scan_error_name(s.last_scan_error) << "\",\"last_scan_errno\":" << s.last_scan_errno << ",\"scan_error_counts\":{";
    // none 不属于错误原因，从 1 开始输出；
    // 扫描错误原因之和加后端错误请求等于 analyzer_error。
    for (std::size_t i = 1; i < s.scan_errors.size(); ++i)
        out << (i == 1 ? "" : ",") << '"' << analysis::scan_error_name(static_cast<analysis::ScanError>(i)) << "\":" << s.scan_errors[i];
    out << "}}\n";
}
