// SPDX-License-Identifier: MIT
// ring buffer 回调只编码和尝试入队；格式错误/资源不足不跨越 C ABI 抛异常，也不等待 stdout。
#include <utility>
#include "events.h"
#include "audit_sink.h"
#include "secmon.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <iostream>
#include <stdexcept>
#include <vector>
int consume(void *context, void *data, std::size_t size) noexcept
{
    auto *sink = static_cast<AuditSink *>(context);
    if (!sink) return 0;
    try {
        auto line = format_event(data, size);
        if (line) sink->enqueue(std::move(*line));
        else sink->note_invalid();
    } catch (...) { sink->note_drop(); }
    return 0;
}
void report_stats(int fd)
{
    // PERCPU_ARRAY 的一次用户态 lookup 返回所有 possible CPU 的值，不只是当前在线 CPU 或单个 u64。
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

void report_audit_stats(const AuditStats &audit)
{
    std::cerr << "audit_written=" << audit.written << " audit_dropped=" << audit.dropped
              << " audit_invalid=" << audit.invalid << " audit_queued=" << audit.queued
              << " audit_errno=" << audit.output_errno << '\n';
}
