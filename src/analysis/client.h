// SPDX-License-Identifier: MIT
// 宿主侧分析器监督器：私有 socketpair、一次一个在途请求、pidfd 定向终止、非阻塞收取结果。
// 分析器故障后保持离线并由权限门执行回退；这里不自动重启，也不管理被监控业务进程。
#pragma once
#include "owned_fd.h"
#include "protocol.h"
#include <optional>
#include <string>
#include <sys/types.h>

struct AnalyzerConfig {
    std::string executable;
    std::string marker;
    unsigned int scan_limit = 65536;
};
// One worker, one transferred event FD at a time. Never inherits the BPF/fanotify group.
class AnalysisClient {
    OwnedFd channel_;
    OwnedFd process_;
    unsigned int scan_limit_ = 0;
    pid_t pid_ = -1;
    std::uint64_t active_ = 0;
    void reap();
    void wait_for_exit();
public:
    explicit AnalysisClient(const AnalyzerConfig &config);
    ~AnalysisClient();
    AnalysisClient(const AnalysisClient &) = delete;
    AnalysisClient &operator=(const AnalysisClient &) = delete;
    bool online() const { return channel_.get() >= 0; }
    int fd() const { return channel_.get(); }
    pid_t pid() const { return pid_; }
    std::uint64_t active() const { return active_; }
    void submit(std::uint64_t id, int event_fd);
    std::optional<analysis::Response> receive();
    // Kill only this unreaped child; never wait in the permission-processing loop.
    void stop();
};
