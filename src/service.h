// SPDX-License-Identifier: MIT
// 单进程服务协调器：一份活动配置、一个管理通道、两个独立资源对象。
#pragma once
#include "options.h"
#include "policy_runtime.h"
#include <memory>
class DiagnosticOutput;
class ControlServer;
class BpfMonitor;
class FanotifyMonitor;
class MonitorService {
    DiagnosticOutput &diagnostics_;
    Options options_;
    PolicyRuntime runtime_;
    std::unique_ptr<ControlServer> control_;
    std::unique_ptr<BpfMonitor> bpf_;
    std::unique_ptr<FanotifyMonitor> fanotify_;
    management::Reply snapshot() const;
    void commit(const PolicyConfig &candidate);
public:
    MonitorService(Options options, DiagnosticOutput &diagnostics);
    ~MonitorService();
    MonitorService(const MonitorService &) = delete;
    MonitorService &operator=(const MonitorService &) = delete;
    void run();
};
