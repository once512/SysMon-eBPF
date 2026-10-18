// SPDX-License-Identifier: MIT
// 服务进程内将 cerr 接到独立有界出口；短时 CLI 不启用。按完整行入队，flush 不等待物理输出。
#pragma once
#include "audit_sink.h"
#include <array>
#include <secmon/diagnostic_limits.h>
#include <mutex>
#include <streambuf>

class DiagnosticOutput : private std::streambuf {
    AuditSink sink_;
    std::mutex mutex_;
    std::array<char, SECMON_DIAGNOSTIC_MAX_LINE_BYTES> line_{};
    std::size_t used_ = 0;
    bool overlong_ = false;
    std::streambuf *previous_ = nullptr;
    std::ostream *previous_tie_ = nullptr;
    void append(const char *data, std::size_t size) noexcept;
    void finish() noexcept;
    std::streamsize xsputn(const char *data, std::streamsize size) override;
    int_type overflow(int_type value) override;
    int sync() override { return 0; }
public:
    explicit DiagnosticOutput(int fd = 2);
    ~DiagnosticOutput() override;
    DiagnosticOutput(const DiagnosticOutput &) = delete;
    DiagnosticOutput &operator=(const DiagnosticOutput &) = delete;
    AuditStats stats() const { return sink_.stats(); }
};
