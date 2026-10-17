// SPDX-License-Identifier: MIT
// 顺序 B1→F1→B2→F2：各自两次间没有提交/重启时，稳定区间在 F1..B2 相交；这不是原子更新事务。
#include "consistency.h"
namespace management {
const char *consistency_name(Consistency result)
{
    switch (result) {
    case Consistency::consistent: return "consistent";
    case Consistency::revision_mismatch: return "revision_mismatch";
    case Consistency::source_mismatch: return "source_mismatch";
    case Consistency::unstable: return "unstable";
    case Consistency::unconfigured: return "unconfigured";
    case Consistency::unexpected_revision: return "unexpected_revision";
    case Consistency::wrong_backend: return "wrong_backend";
    case Consistency::query_failed: return "query_failed";
    }
    return nullptr;
}
namespace {
bool stable(const Reply &before, const Reply &after)
{
    // 拒绝次数/业务计数可变化；它们不改变活动来源。成功提交或实例变化则使本次采样无效。
    return before.pid == after.pid && before.instance_ns == after.instance_ns && before.revision == after.revision &&
        before.source_digest == after.source_digest && before.reloads == after.reloads &&
        (before.flags & configured) == (after.flags & configured);
}
}
Consistency check_consistency(const Reply &b1, const Reply &f1, const Reply &b2, const Reply &f2,
                              std::uint64_t expected_revision)
{
    for (const auto *reply : {&b1, &f1, &b2, &f2}) {
        validate_reply(*reply, Command::status);
        if (reply->code != Code::ok) return Consistency::query_failed;
    }
    if (b1.backend != Backend::bpf || b2.backend != Backend::bpf ||
        f1.backend != Backend::fanotify || f2.backend != Backend::fanotify) return Consistency::wrong_backend;
    // 必须先排除采样期间的重启/提交，才能比较共同活动来源；
    // 相同候选磁盘文件不能替代这一步。
    if (!stable(b1, b2) || !stable(f1, f2)) return Consistency::unstable;
    if (!(b2.flags & configured) || !(f2.flags & configured)) return Consistency::unconfigured;
    if (b2.revision != f2.revision) return Consistency::revision_mismatch;
    // 相同 revision 仍可能来自不同字节；
    // 摘要只核对配置来源，不证明两端路径解析到同一 inode。
    if (b2.source_digest != f2.source_digest) return Consistency::source_mismatch;
    if (expected_revision && b2.revision != expected_revision) return Consistency::unexpected_revision;
    return Consistency::consistent;
}
std::string consistency_json(Consistency result, const Reply &bpf, const Reply &fanotify)
{
    const auto *name = consistency_name(result);
    if (!name) throw std::runtime_error("Invalid consistency result");
    return std::string("{\"code\":\"") + name + "\",\"scope\":\"active_configuration_bytes\",\"bpf\":" +
        reply_json(bpf) + ",\"fanotify\":" + reply_json(fanotify) + "}";
}
}
