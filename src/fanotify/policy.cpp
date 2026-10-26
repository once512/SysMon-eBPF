// SPDX-License-Identifier: MIT
// 事件和分析后端固定；目标列表的在线切换条件由 FanotifyMonitor 单独检查。
#include "policy.h"
#include <stdexcept>

void apply_fanotify_policy(const PolicyConfig &policy, FanotifyOptions &options)
{
    if (!policy.fanotify) throw std::runtime_error("Policy has no fanotify configuration");
    const auto &source = *policy.fanotify;
    options.paths = source.paths;
    options.rebind_epoch = source.rebind_epoch;
    // 文本配置与运行枚举在适配层转换；
    // 内核 FAN_* 掩码不直接作为配置/管理协议的枚举数值。
    options.event = parse_permission_event(source.event);
    options.analyzer = {source.analyzer, source.marker, source.scan_limit};
    options.decision.allow = source.decision == "allow";
    options.decision.external = !source.analyzer.empty();
    options.decision.delay = std::chrono::milliseconds(source.delay_ms);
    options.decision.timeout = std::chrono::milliseconds(source.timeout_ms);
    options.decision.max_pending = source.max_pending;
    options.decision.timeout_allow = source.timeout_allow;
    options.decision.overload_allow = source.overload_allow;
    options.decision.analyzer_error_allow = source.analyzer_error_allow;
}
bool same_fanotify_backend(const FanotifyOptions &a, const FanotifyOptions &b)
{
    // Target identity has a separate, restricted handover contract. Changing
    // event kind or analyzer settings still requires an explicit restart.
    return a.event == b.event &&
        a.decision.external == b.decision.external &&
        a.analyzer.executable == b.analyzer.executable && a.analyzer.marker == b.analyzer.marker &&
        a.analyzer.scan_limit == b.analyzer.scan_limit;
}
