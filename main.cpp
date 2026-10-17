// SPDX-License-Identifier: MIT
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
#include <sys/utsname.h>
#include "secmon.h"
#include "file_policy.h"
#include <secmon.skel.h>

namespace {
volatile std::sig_atomic_t stopping = 0;
void stop(int) { stopping = 1; }
std::string read_file(const char *path)
{
    std::ifstream input(path);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
std::string json_string(const char *data, std::size_t capacity)
{
    constexpr char hex[] = "0123456789abcdef";
    std::string out = "\"";
    for (std::size_t i = 0; i < capacity && data[i]; ++i) {
        const auto c = static_cast<unsigned char>(data[i]);
        if (c == '"' || c == '\\') { out += '\\'; out += static_cast<char>(c); }
        else if (c < 0x20 || c >= 0x7f) {
            out += "\\u00"; out += hex[c >> 4]; out += hex[c & 15];
        } else out += static_cast<char>(c);
    }
    return out + '"';
}
int consume(void *, void *data, std::size_t size)
{
    if (size != sizeof(exec_event)) {
        std::cerr << "Unexpected event size: " << size << '\n';
        return 0;
    }
    exec_event e{};
    std::memcpy(&e, data, sizeof(e));
    if (e.version != SECMON_ABI_VERSION || e.size != sizeof(e)) {
        std::cerr << "Event ABI mismatch\n";
        return 0;
    }
    if (e.kind == SECMON_FILE_DENIED) {
        std::cout << "{\"event\":\"file_denied\",\"timestamp_ns\":" << e.timestamp_ns
                  << ",\"pid\":" << e.pid << ",\"tid\":" << e.tid
                  << ",\"start_ns\":" << e.start_ns
                  << ",\"uid\":" << e.caller_uid << ",\"euid\":" << e.caller_euid
                  << ",\"dev_major\":" << e.file.major << ",\"dev_minor\":" << e.file.minor
                  << ",\"ino\":" << e.file.ino << ",\"operation\":" << e.operation
                  << ",\"errno\":13,\"comm\":" << json_string(e.comm, sizeof(e.comm)) << "}\n";
        return 0;
    }
    const char *kind = e.kind == SECMON_EXEC_CHECK ? "exec_check" :
                       e.kind == SECMON_EXEC_SUCCESS ? "exec_success" : nullptr;
    if (!kind) {
        std::cerr << "Unknown event kind\n";
        return 0;
    }
    std::cout << "{\"event\":\"" << kind << "\",\"timestamp_ns\":" << e.timestamp_ns
              << ",\"old_tid\":" << e.old_tid
              << ",\"start_ns\":" << e.start_ns << ",\"pid\":" << e.pid
              << ",\"tid\":" << e.tid << ",\"ppid\":" << e.ppid
              << ",\"uid\":" << e.caller_uid << ",\"euid\":" << e.caller_euid
              << ",\"target_euid\":" << e.target_euid << ",\"caps\":" << e.caps
              << ",\"mode\":" << e.file_mode << ",\"flags\":" << e.flags
              << ",\"comm\":" << json_string(e.comm, sizeof(e.comm))
              << ",\"filename\":" << json_string(e.filename, sizeof(e.filename)) << "}\n";
    return 0;
}
void report_stats(int fd)
{
    const int cpus = libbpf_num_possible_cpus();
    if (cpus < 1) throw std::runtime_error("Cannot determine possible CPUs");
    std::vector<unsigned long long> values(static_cast<std::size_t>(cpus));
    for (unsigned int key = 0; key < SECMON_STAT_COUNT; ++key) {
        if (bpf_map_lookup_elem(fd, &key, values.data()))
            throw std::runtime_error("Cannot read BPF statistics");
        unsigned long long total = 0;
        for (const auto value : values) total += value;
        const char *names[] = {"ringbuf_dropped=", "baseline_update_failed=", "policy_denied="};
        std::cerr << names[key]
                  << total << '\n';
    }
}
}
int main(int argc, char **argv)
{
    bool check = false;
    std::vector<std::string> paths;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg(argv[i]);
        if (arg == "--help" && argc == 2) {
            std::cout << "Usage: secmon [--check] [--protect-file PATH ...]\n"
                         "Default: execution/credential audit. --protect-file enforces read-only\n"
                         "on an existing regular file inode for all tasks, including root.\n"
                         "--check: inspect environment without attaching BPF.\n";
            return 0;
        }
        if (arg == "--check") check = true;
        else if (arg == "--protect-file" && i + 1 < argc) paths.emplace_back(argv[++i]);
        else {
            std::cerr << "Invalid argument; use --help\n";
            return 2;
        }
    }
    if ((check && !paths.empty()) || paths.size() > 256) {
        std::cerr << "--check cannot install policies; at most 256 files are supported\n";
        return 2;
    }
    try {
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
        ProtectedFiles protected_files; // Must outlive BPF links.
        std::unique_ptr<secmon_bpf, decltype(&secmon_bpf__destroy)> skel(
            secmon_bpf__open(), secmon_bpf__destroy);
        if (!skel) throw std::runtime_error("Cannot open BPF skeleton");
        if (secmon_bpf__load(skel.get()))
            throw std::runtime_error("BPF load failed; inspect libbpf diagnostics and privileges");
        protected_files.install(bpf_map__fd(skel->maps.protected_files), paths);
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
        if (!paths.empty()) std::cerr << "File read-only policy active for " << paths.size() << " paths\n";
        std::cerr << "Audit active; exec_check events are attempts, not successful execs.\n";
        auto next = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        while (!stopping) {
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
