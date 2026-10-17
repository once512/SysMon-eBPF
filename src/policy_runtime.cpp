// SPDX-License-Identifier: MIT
// 版本与错误只在事件循环中修改，status 只复制内存快照；忙队列/固定后端变化有独立稳定错误码。
#include "policy_runtime.h"
#include <iostream>
#include <unistd.h>
#include <utility>
#include <type_traits>
static_assert(std::is_nothrow_move_assignable_v<PolicyConfig>);

PolicyRuntime::PolicyRuntime(std::string source, PolicyConfig initial)
    : source_(std::move(source)), active_(std::move(initial)) {}
management::Code PolicyRuntime::reload(const std::function<void(const PolicyConfig &)> &commit, int excluded_fd)
{
    using management::Code;
    // 每次尝试先清候选版本；
    // 文件尚未成功读取时，不应沿用上一次候选的 revision 造成误诊。
    last_attempt_ = 0;
    Code stage = Code::invalid_policy;
    try {
        if (source_.empty()) throw management::Error(Code::no_policy, "Reload requires --policy at startup");
        auto candidate = load_policy(source_, excluded_fd);
        last_attempt_ = candidate.revision;
        if (candidate.revision <= active_.revision)
            throw management::Error(Code::not_newer, "Policy revision must increase");
        // 同样的普通异常按阶段归类：此前是配置读取/解析失败，此后是后端资源准备失败。
        stage = Code::prepare_failed;
        // 回调必须先做所有可能失败的准备，再完成后端提交；
        // 协调器无法替后端撤销已经发生的副作用。
        commit(candidate);
        // PolicyConfig 的移动赋值不会重新分配；后端提交成功之后不能再有可失败的准备操作。
        active_ = std::move(candidate);
        ++reloads_;
        last_code_ = Code::ok;
    } catch (const management::Error &error) {
        last_code_ = error.code();
        std::cerr << "Policy reload rejected: code=" << management::code_name(last_code_) << " detail=" << error.what() << '\n';
    } catch (const std::exception &error) {
        last_code_ = stage;
        std::cerr << "Policy reload rejected: code=" << management::code_name(last_code_) << " detail=" << error.what() << '\n';
    }
    // 拒绝计数记录管理请求失败，与文件读写被拒绝的业务统计是两套独立口径。
    if (last_code_ != Code::ok) ++rejections_;
    return last_code_;
}
management::Reply PolicyRuntime::snapshot(management::Backend backend) const
{
    management::Reply reply;
    reply.backend = backend;
    reply.pid = static_cast<std::uint32_t>(getpid());
    reply.flags = source_.empty() ? 0U : management::configured;
    reply.revision = active_.revision;
    reply.source_digest = active_.source_digest;
    reply.last_attempt_revision = last_attempt_;
    // 实例标记来自本协调器创建时刻，用于与 PID 一起区分重启；
    // 不是持久 UUID，也不是 task 启动时间。
    reply.instance_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(started_.time_since_epoch()).count();
    reply.uptime_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started_).count();
    reply.reloads = reloads_;
    reply.rejections = rejections_;
    reply.last_code = last_code_;
    return reply;
}
