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
    last_attempt_ = 0;
    Code stage = Code::invalid_policy;
    try {
        if (source_.empty()) throw management::Error(Code::no_policy, "Reload requires --policy at startup");
        auto candidate = load_policy(source_, excluded_fd);
        last_attempt_ = candidate.revision;
        if (candidate.revision <= active_.revision)
            throw management::Error(Code::not_newer, "Policy revision must increase");
        stage = Code::prepare_failed;
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
    reply.instance_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(started_.time_since_epoch()).count();
    reply.uptime_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started_).count();
    reply.reloads = reloads_;
    reply.rejections = rejections_;
    reply.last_code = last_code_;
    return reply;
}
