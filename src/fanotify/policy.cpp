// SPDX-License-Identifier: MIT
// 在线只改裁决规则，不重建 mark 或分析器；固定目标/事件/扫描参数的变化必须显式重启。
#include "policy.h"
#include <stdexcept>

void apply_fanotify_policy(const PolicyConfig &policy, FanotifyOptions &options)
{
    if (!policy.fanotify) throw std::runtime_error("Policy has no fanotify configuration");
    const auto &source = *policy.fanotify;
    options.path = source.path;
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
    // 比较配置身份而不重新解析路径；运行中的 mark 固定原 inode，路径重命名不会让它自动转移到新对象。
    // 后端身份变化需要重建 mark/工作进程；
    // 在线重载只允许换裁决设置，不隐式迁移到新对象。
    return a.path == b.path && a.event == b.event &&
        a.decision.external == b.decision.external &&
        a.analyzer.executable == b.analyzer.executable && a.analyzer.marker == b.analyzer.marker &&
        a.analyzer.scan_limit == b.analyzer.scan_limit;
}
