// SPDX-License-Identifier: MIT
// 两种后端共用的运行版本协调器；资源准备/提交由回调实现，提交成功后才替换活动配置。
#pragma once
#include "policy_config.h"
#include "management/protocol.h"
#include <chrono>
#include <functional>

class PolicyRuntime {
    std::string source_;
    PolicyConfig active_;
    std::chrono::steady_clock::time_point started_ = std::chrono::steady_clock::now();
    std::uint64_t reloads_ = 0;
    std::uint64_t rejections_ = 0;
    std::uint64_t last_attempt_ = 0;
    management::Code last_code_ = management::Code::ok;
public:
    PolicyRuntime(std::string source, PolicyConfig initial);
    // 版本/实例状态属于一个运行协调器，不能复制成第二个看似相同的实例。
    PolicyRuntime(const PolicyRuntime &) = delete;
    PolicyRuntime &operator=(const PolicyRuntime &) = delete;
    // 借出当前配置的只读引用；
    // 不要缓存其中 vector/string 元素地址，成功重载会替换内部存储。
    const PolicyConfig &active() const { return active_; }
    // commit 由具体后端实现完整提交；
    // excluded_fds 向加载器传递全部不能读的 inode，防 fanotify 自我等待。
    management::Code reload(const std::function<void(const PolicyConfig &)> &commit, const std::vector<int> &excluded_fds = {});
    // 只复制协调器自己的版本/历史；
    // 队列数、worker 状态和保护条数由后端适配器补齐。
    management::Reply snapshot(management::Backend backend) const;
};
