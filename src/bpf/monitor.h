// SPDX-License-Identifier: MIT
// BPF 模块独占 skeleton、策略 inode 和 ring buffer；主服务仅调用生命周期接口。
#pragma once
#include "policy_config.h"
#include <memory>

class BpfMonitor {
    struct State;
    std::unique_ptr<State> state_;
public:
    static void check_environment();
    BpfMonitor(const PolicyConfig &policy, bool self_protect);
    ~BpfMonitor();
    BpfMonitor(const BpfMonitor &) = delete;
    BpfMonitor &operator=(const BpfMonitor &) = delete;
    void install(const PolicyConfig &candidate);
    void poll_once(int timeout_ms);
    void report();
    void shutdown();
};
