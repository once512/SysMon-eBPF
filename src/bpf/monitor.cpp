// SPDX-License-Identifier: MIT
// 把 libbpf 资源收束到一个对象；声明顺序保证先卸载钩子、再释放固定 inode。
#include "monitor.h"
#include "events.h"
#include "file_policy.h"
#include "owned_fd.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <secmon.skel.h>
#include <cerrno>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <sys/syscall.h>
#include <sys/epoll.h>
#include <sys/utsname.h>
#include <unistd.h>

namespace {
std::string read_file(const char *path)
{
    std::ifstream input(path);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
}
struct BpfMonitor::State {
    AuditSink audit; // 先创建出口，最后回收；ring callback 始终借用其稳定地址。
    ProtectedFiles protected_files; // 晚于所有 BPF 链接释放，防止保护期间 inode 被复用。
    std::unique_ptr<secmon_bpf, decltype(&secmon_bpf__destroy)> skel{nullptr, secmon_bpf__destroy};
    std::unique_ptr<ring_buffer, decltype(&ring_buffer__free)> ring{nullptr, ring_buffer__free};
    bool attached = false;
};
void BpfMonitor::check_environment()
{
    utsname info{};
    if (uname(&info)) throw std::runtime_error("uname failed");
    const auto lsm = read_file("/sys/kernel/security/lsm");
    const bool btf = std::ifstream("/sys/kernel/btf/vmlinux").good();
    const auto list = "," + lsm + ",";
    const bool bpf_lsm = list.find(",bpf,") != std::string::npos ||
                         list.find(",bpf\n,") != std::string::npos;
    std::cerr << "kernel=" << info.release << " arch=" << info.machine
              << " btf=" << btf << " bpf_lsm=" << bpf_lsm << '\n';
    if (!btf || !bpf_lsm)
        throw std::runtime_error("BTF or active BPF LSM unavailable (or securityfs inaccessible)");
}
BpfMonitor::BpfMonitor(const PolicyConfig &active, bool self_protect) : state_(std::make_unique<State>())
{
    check_environment();
    auto &skel = state_->skel;
    skel.reset(secmon_bpf__open());
    if (!skel) throw std::runtime_error("Cannot open BPF skeleton");
    // load 创建 Map 并提交 verifier；此刻还没有钩子，先准备策略再 attach。
    if (secmon_bpf__load(skel.get())) throw std::runtime_error("BPF load failed");
    if (self_protect) {
        // TASK_STORAGE 的用户态 Map 更新使用 pidfd 作为 key，不直接把 getpid 的整数当作生命周期身份。
        // pidfd 是当前进程的稳定内核引用；
        // TASK_STORAGE 的用户态 key 使用这个 FD，而不是一个可复用的 PID 数字。
        OwnedFd self(static_cast<int>(syscall(SYS_pidfd_open, getpid(), 0)));
        unsigned int enabled = 1;
        if (self.get() < 0) throw std::runtime_error("Cannot open self pidfd");
        const int fd = self.get();
        if (bpf_map_update_elem(bpf_map__fd(skel->maps.protected_tasks), &fd,
                                &enabled, BPF_NOEXIST))
            throw std::runtime_error("Cannot install task-local self-protection policy");
    }
    state_->protected_files.install(bpf_map__fd(skel->maps.protected_files), active);
    state_->ring.reset(ring_buffer__new(bpf_map__fd(skel->maps.events), consume, &state_->audit, nullptr));
    if (!state_->ring) throw std::runtime_error("Cannot create ring buffer consumer");
    if (secmon_bpf__attach(skel.get())) throw std::runtime_error("BPF attach failed");
    state_->attached = true;
    if (self_protect) std::cerr << "Self protection active; stop via the control socket\n";
    std::cerr << "Audit active; exec_check events are attempts, not successful execs.\n";
}
BpfMonitor::~BpfMonitor() = default;
void BpfMonitor::install(const PolicyConfig &candidate)
{
    state_->protected_files.install(bpf_map__fd(state_->skel->maps.protected_files), candidate);
}
void BpfMonitor::poll_once(int timeout_ms)
{
    if (timeout_ms > 0) {
        epoll_event ready{};
        const int result = epoll_wait(ring_buffer__epoll_fd(state_->ring.get()), &ready, 1, timeout_ms);
        if (result < 0 && errno != EINTR) throw std::runtime_error("Ring buffer wait failed");
    }
    // 不能在持续审计洪流中无限 consume；每轮最多 128 条，把执行权及时还给管理和 fanotify。
    const int result = ring_buffer__consume_n(state_->ring.get(), 128);
    if (result < 0) throw std::runtime_error("Ring buffer consume failed");
}
void BpfMonitor::report()
{
    report_stats(bpf_map__fd(state_->skel->maps.stats));
    const auto audit = audit_stats();
    std::cerr << "audit_written=" << audit.written << " audit_dropped=" << audit.dropped
              << " audit_invalid=" << audit.invalid << " audit_queued=" << audit.queued
              << " audit_errno=" << audit.output_errno << '\n';
}
void BpfMonitor::shutdown()
{
    if (!state_->attached) return;
    secmon_bpf__detach(state_->skel.get());
    state_->attached = false;
    ring_buffer__consume(state_->ring.get());
    state_->audit.shutdown();
    report();
}

AuditStats BpfMonitor::audit_stats() const { return state_->audit.stats(); }
