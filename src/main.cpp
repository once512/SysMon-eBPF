// SPDX-License-Identifier: MIT
// BPF 宿主入口：解析参数 → 环境检查 → open/load skeleton → 写策略 → attach → 消费 ring buffer。
// skeleton 是 bpftool 根据 BPF ELF 生成的管理接口，提供程序/Map 句柄和统一销毁，不在宿主执行 BPF 字节码。
// 资源声明顺序影响异常退出：先销毁链接，再释放当前策略固定的 inode，防止保护期间 inode 被复用。
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <sys/utsname.h>
#include "secmon.h"
#include "file_policy.h"
#include "control.h"
#include "options.h"
#include "policy_config.h"
#include "policy_runtime.h"
#include "events.h"
#include <sys/syscall.h>
#include <secmon.skel.h>

namespace {
volatile std::sig_atomic_t stopping = 0;
void stop(int) { stopping = 1; }
std::string read_file(const char *path)
{
    std::ifstream input(path);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
} // namespace

int main(int argc, char **argv)
{
    Options options;
    CliAction action;
    try { action = parse_options(argc, argv, options); }
    catch (const std::invalid_argument &) { return 2; }
    if (action == CliAction::help) return 0;
    const auto &check = options.check;
    const auto &control_path = options.control_path;
    const auto &run_seconds = options.run_seconds;
    try {
        if (action == CliAction::stop) { request_stop(control_path); return 0; }
        if (action == CliAction::reload) { request_reload(control_path); return 0; }
        if (action == CliAction::status) { request_status(control_path); return 0; }
        PolicyConfig initial;
        initial.paths = options.paths;
        if (!options.policy_path.empty()) initial = load_policy(options.policy_path);
        PolicyRuntime runtime(options.policy_path, std::move(initial));
        const auto &active = runtime.active();
        if (active.fanotify) std::cerr << "secmon applies protect/allow-writer entries; run secmon-fanotify separately for fanotify directives\n";
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
        if (check) {
            std::cerr << "Environment check passed; hook/load permissions require actual attach.\n";
            return 0;
        }
        std::unique_ptr<ControlServer> control;
        if (!control_path.empty()) control = std::make_unique<ControlServer>(control_path);
        // C++ 局部对象逆序析构：skeleton 释放链接后，才允许本对象释放当前 inode 句柄。
        ProtectedFiles protected_files; // Must outlive BPF links.
        std::unique_ptr<secmon_bpf, decltype(&secmon_bpf__destroy)> skel(
            secmon_bpf__open(), secmon_bpf__destroy);
        if (!skel) throw std::runtime_error("Cannot open BPF skeleton");
        // open 只解析 ELF/创建宿主结构；load 才创建内核 Map 并提交程序给 verifier，此时尚未 attach。
        if (secmon_bpf__load(skel.get()))
            throw std::runtime_error("BPF load failed; inspect libbpf diagnostics and privileges");
        if (control) {
            // TASK_STORAGE 的用户态 Map 更新使用 pidfd 作为 key，不直接把 getpid 的整数当作生命周期身份。
            OwnedFd self(static_cast<int>(syscall(SYS_pidfd_open, getpid(), 0)));
            unsigned int enabled = 1;
            if (self.get() < 0) throw std::runtime_error("Cannot open self pidfd");
            const int fd = self.get();
            if (bpf_map_update_elem(bpf_map__fd(skel->maps.protected_tasks), &fd,
                                    &enabled, BPF_NOEXIST))
                throw std::runtime_error("Cannot install task-local self-protection policy");
        }
        protected_files.install(bpf_map__fd(skel->maps.protected_files), active);
        // ring_buffer__new 注册消费回调；它不挂载 BPF，只有后面的 attach 才开始进入安全/跟踪钩子。
        std::unique_ptr<ring_buffer, decltype(&ring_buffer__free)> ring(
            ring_buffer__new(bpf_map__fd(skel->maps.events), consume, nullptr, nullptr),
            ring_buffer__free);
        if (!ring) throw std::runtime_error("Cannot create ring buffer consumer");
        struct sigaction action{};
        action.sa_handler = stop;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGINT, &action, nullptr) || sigaction(SIGTERM, &action, nullptr))
            throw std::runtime_error("Cannot install signal handlers");
        // 策略先准备，链接随后逐个挂载；多个 LSM 钩子的首次启用并不是一次原子操作。
        if (secmon_bpf__attach(skel.get())) throw std::runtime_error("BPF attach failed");
        if (control) std::cerr << "Self protection active; stop via --stop " << control_path << '\n';
        if (!active.paths.empty()) std::cerr << "File read-only policy active for " << active.paths.size() << " paths\n";
        if (active.revision) std::cerr << "Policy active revision=" << active.revision << '\n';
        std::cerr << "Audit active; exec_check events are attempts, not successful execs.\n";
        const auto started = std::chrono::steady_clock::now();
        auto next = started + std::chrono::seconds(10);
        while (!stopping) {
            if (run_seconds && std::chrono::steady_clock::now() - started >=
                std::chrono::seconds(run_seconds)) break;
            // 管理命令和事件处理共用此线程，重载不会与另一个宿主线程同时修改 active/pinned FD 集合。
            if (control) control->dispatch([&](ControlCommand command) {
                auto code = management::Code::ok;
                if (command == ControlCommand::stop) {
                    std::cerr << "Authorized control stop accepted\n";
                    stopping = 1;
                } else if (command == ControlCommand::reload) {
                    code = runtime.reload([&](const PolicyConfig &candidate) {
                        protected_files.install(bpf_map__fd(skel->maps.protected_files), candidate);
                    });
                    if (code == management::Code::ok)
                        std::cerr << "Policy active revision=" << active.revision << '\n';
                }
                auto reply = runtime.snapshot(management::Backend::bpf);
                reply.protected_paths = active.paths.size();
                reply.writer_paths = active.writers.size();
                reply.flags |= management::self_protected;
                reply.code = code;
                return reply;
            });
            if (stopping) break;
            const int result = ring_buffer__poll(ring.get(), 250);
            if (result < 0 && result != -EINTR) throw std::runtime_error("Ring buffer poll failed");
            if (!std::cout) throw std::runtime_error("Event output failed");
            if (std::chrono::steady_clock::now() >= next) {
                report_stats(bpf_map__fd(skel->maps.stats));
                next = std::chrono::steady_clock::now() + std::chrono::seconds(10);
                std::cout.flush();
            }
        }
        // 正常退出先停止事件来源，再消费剩余记录；不是先关 ring buffer 后让 BPF 继续向无人消费的缓冲写。
        secmon_bpf__detach(skel.get());
        ring_buffer__consume(ring.get());
        report_stats(bpf_map__fd(skel->maps.stats));
    } catch (const std::exception &error) {
        std::cerr << "secmon: " << error.what() << '\n';
        return 1;
    }
    return 0;
}
