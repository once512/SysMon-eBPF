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
    const PolicyConfig &active() const { return active_; }
    management::Code reload(const std::function<void(const PolicyConfig &)> &commit, int excluded_fd = -1);
    management::Reply snapshot(management::Backend backend) const;
};
