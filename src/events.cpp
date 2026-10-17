// SPDX-License-Identifier: MIT
#include "events.h"
#include "secmon.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
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
} // namespace

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
    if (e.kind == SECMON_SELF_DENIED_EVENT) {
        std::cout << "{\"event\":\"self_denied\",\"timestamp_ns\":" << e.timestamp_ns
                  << ",\"pid\":" << e.pid << ",\"tid\":" << e.tid
                  << ",\"target_pid\":" << e.target_pid << ",\"signal\":" << e.signal
                  << ",\"operation\":" << e.operation << ",\"errno\":1"
                  << ",\"uid\":" << e.caller_uid << ",\"euid\":" << e.caller_euid
                  << ",\"comm\":" << json_string(e.comm, sizeof(e.comm)) << "}\n";
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
        const char *names[] = {"ringbuf_dropped=", "baseline_update_failed=", "policy_denied=", "self_denied="};
        std::cerr << names[key]
                  << total << '\n';
    }
}
