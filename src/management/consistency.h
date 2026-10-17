// SPDX-License-Identifier: MIT
// 对两后端各取两次只读状态，检查共同观测窗口内活动配置来源是否稳定一致；不修改策略。
#pragma once
#include "protocol.h"
namespace management {
enum class Consistency { consistent, revision_mismatch, source_mismatch, unstable, unconfigured,
                         unexpected_revision, wrong_backend, query_failed };
const char *consistency_name(Consistency result);
Consistency check_consistency(const Reply &bpf_before, const Reply &fanotify_before,
                              const Reply &bpf_after, const Reply &fanotify_after,
                              std::uint64_t expected_revision = 0);
std::string consistency_json(Consistency result, const Reply &bpf, const Reply &fanotify);
}
