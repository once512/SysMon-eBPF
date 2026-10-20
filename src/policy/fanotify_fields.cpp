// SPDX-License-Identifier: MIT
// 先记录字段是否显式出现，读完后再验证静态/分析模式互斥，因此字段可换序。
#include "fanotify_fields.h"
#include "fields.h"
#include <secmon/policy_limits.h>
#include <algorithm>
namespace policy_fields {
void FanotifyFields::parse(const std::string &key, std::istream &fields)
{
    if (key != "fanotify-file" && !seen_.insert(key).second) invalid("duplicate fanotify field: " + key);
    if (key == "fanotify-file") {
        const auto target = path(fields);
        if (value_.paths.size() == SECMON_MAX_FANOTIFY_TARGETS ||
            std::find(value_.paths.begin(), value_.paths.end(), target) != value_.paths.end())
            invalid("fanotify targets must be distinct, at most 64");
        value_.paths.push_back(target);
        seen_.insert(key);
    }
    else if (key == "fanotify-analyzer") value_.analyzer = path(fields);
    else if (key == "fanotify-marker") value_.marker = quoted(fields, 256);
    else {
        const auto value = word(fields);
        if (key == "fanotify-event") {
            if (value != "open" && value != "access" && value != "exec") invalid("unknown fanotify event");
            value_.event = value;
        } else if (key == "fanotify-decision") { (void)allow(value); value_.decision = value; }
        else if (key == "fanotify-delay-ms") value_.delay_ms = number<unsigned>(value, 0, 60000);
        else if (key == "fanotify-timeout-ms") value_.timeout_ms = number<unsigned>(value, 1, 60000);
        else if (key == "fanotify-max-pending") value_.max_pending = number<unsigned>(value, 1, SECMON_MAX_PENDING);
        else if (key == "fanotify-scan-limit-bytes") value_.scan_limit = number<unsigned>(value, 1, 1048576);
        else if (key == "fanotify-timeout-decision") value_.timeout_allow = allow(value);
        else if (key == "fanotify-overload-decision") value_.overload_allow = allow(value);
        else if (key == "fanotify-error-decision") value_.analyzer_error_allow = allow(value);
        else invalid("unknown field: " + key);
    }
}
std::optional<FanotifyPolicy> FanotifyFields::finish()
{
    if (seen_.empty()) return std::nullopt;
    if (value_.paths.empty()) invalid("fanotify fields require fanotify-file");
    if (value_.analyzer.empty()) {
        if (value_.decision.empty() || seen_.count("fanotify-marker") || seen_.count("fanotify-scan-limit-bytes") || seen_.count("fanotify-error-decision"))
            invalid("static fanotify requires a decision and forbids analyzer-only fields");
    } else if (value_.marker.empty() || !value_.decision.empty() || seen_.count("fanotify-delay-ms"))
        invalid("analyzer fanotify requires a marker and forbids static decision/delay");
    return std::move(value_);
}
}
