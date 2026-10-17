// SPDX-License-Identifier: MIT
#include "policy.h"
#include <stdexcept>

void apply_fanotify_policy(const PolicyConfig &policy, FanotifyOptions &options)
{
    if (!policy.fanotify) throw std::runtime_error("Policy has no fanotify configuration");
    const auto &source = *policy.fanotify;
    options.path = source.path;
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
    return a.path == b.path && a.event == b.event &&
        a.decision.external == b.decision.external &&
        a.analyzer.executable == b.analyzer.executable && a.analyzer.marker == b.analyzer.marker &&
        a.analyzer.scan_limit == b.analyzer.scan_limit;
}
