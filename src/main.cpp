// SPDX-License-Identifier: MIT
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
        PolicyConfig active;
        active.paths = options.paths;
        if (!options.policy_path.empty()) active = load_policy(options.policy_path);
        if (active.fanotify) std::cerr << "secmon applies only protect entries; run secmon-fanotify separately for fanotify directives\n";
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
        ProtectedFiles protected_files; // Must outlive BPF links.
        std::unique_ptr<secmon_bpf, decltype(&secmon_bpf__destroy)> skel(
            secmon_bpf__open(), secmon_bpf__destroy);
        if (!skel) throw std::runtime_error("Cannot open BPF skeleton");
        if (secmon_bpf__load(skel.get()))
            throw std::runtime_error("BPF load failed; inspect libbpf diagnostics and privileges");
        if (control) {
            OwnedFd self(static_cast<int>(syscall(SYS_pidfd_open, getpid(), 0)));
            unsigned int enabled = 1;
            if (self.get() < 0) throw std::runtime_error("Cannot open self pidfd");
            const int fd = self.get();
            if (bpf_map_update_elem(bpf_map__fd(skel->maps.protected_tasks), &fd,
                                    &enabled, BPF_NOEXIST))
                throw std::runtime_error("Cannot install task-local self-protection policy");
        }
        protected_files.install(bpf_map__fd(skel->maps.protected_files), active.paths);
        std::unique_ptr<ring_buffer, decltype(&ring_buffer__free)> ring(
            ring_buffer__new(bpf_map__fd(skel->maps.events), consume, nullptr, nullptr),
            ring_buffer__free);
        if (!ring) throw std::runtime_error("Cannot create ring buffer consumer");
        struct sigaction action{};
        action.sa_handler = stop;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGINT, &action, nullptr) || sigaction(SIGTERM, &action, nullptr))
            throw std::runtime_error("Cannot install signal handlers");
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
            if (control) control->dispatch([&](ControlCommand command) {
                if (command == ControlCommand::stop) {
                    std::cerr << "Authorized control stop accepted\n";
                    stopping = 1;
                    return;
                }
                try {
                    if (options.policy_path.empty()) throw std::runtime_error("Reload requires --policy at startup");
                    auto candidate = load_policy(options.policy_path);
                    if (candidate.revision <= active.revision) throw std::runtime_error("Policy revision must increase");
                    protected_files.install(bpf_map__fd(skel->maps.protected_files), candidate.paths);
                    active = std::move(candidate);
                    std::cerr << "Policy active revision=" << active.revision << '\n';
                } catch (const std::exception &error) {
                    std::cerr << "Policy reload rejected: " << error.what() << '\n';
                    throw;
                }
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
        secmon_bpf__detach(skel.get());
        ring_buffer__consume(ring.get());
        report_stats(bpf_map__fd(skel->maps.stats));
    } catch (const std::exception &error) {
        std::cerr << "secmon: " << error.what() << '\n';
        return 1;
    }
    return 0;
}
