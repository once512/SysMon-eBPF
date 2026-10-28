// SPDX-License-Identifier: MIT
// 单进程服务协调器：一份活动配置、一个管理通道、两个独立资源对象。
#pragma once
#include "options.h"
#include "policy_runtime.h"
#include <memory>
class AuditSink;
class DiagnosticOutput;
class ControlServer;
class BpfMonitor;
class FanotifyMonitor;
class DecoyProvider;
class ServiceNotify;
class MonitorService {
    DiagnosticOutput &diagnostics_;
    Options options_;
    std::unique_ptr<DecoyProvider> decoy_; // Outlives all policy/target references.
    PolicyRuntime runtime_;
    std::unique_ptr<AuditSink> audit_; // 两个模块借用；最后释放，整个 stdout 只有一个写线程。
    std::unique_ptr<ControlServer> control_;
    std::unique_ptr<BpfMonitor> bpf_;
    std::unique_ptr<FanotifyMonitor> fanotify_;
    management::Reply snapshot() const;
    void commit(const PolicyConfig &candidate);
    void preparation_progress();
    std::chrono::steady_clock::time_point run_deadline_{};
public:
    MonitorService(Options options, DiagnosticOutput &diagnostics);
    ~MonitorService();
    MonitorService(const MonitorService &) = delete;
    MonitorService &operator=(const MonitorService &) = delete;
    void run(ServiceNotify &notification);
};
