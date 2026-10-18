// SPDX-License-Identifier: MIT
#include "diagnostic_output.h"
#include <iostream>

DiagnosticOutput::DiagnosticOutput(int fd)
    : sink_(fd, SECMON_DIAGNOSTIC_MAX_RECORDS, SECMON_DIAGNOSTIC_MAX_BYTES)
{
    // cerr 默认 tied 到 cout；移除 tie，避免每条诊断先同步 flush stdout。
    previous_tie_ = std::cerr.tie(nullptr);
    previous_ = std::cerr.rdbuf(this);
}
DiagnosticOutput::~DiagnosticOutput()
{
    std::cerr.rdbuf(previous_);
    std::cerr.tie(previous_tie_);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        // 退出时补齐最后一个无换行片段；若已占满行预算，按过长行丢弃。
        if (used_ || overlong_) append("\n", 1);
    }
    sink_.shutdown();
}
void DiagnosticOutput::finish() noexcept
{
    if (overlong_) {
        sink_.note_invalid();
        sink_.note_drop();
    } else {
        try { sink_.enqueue(std::string(line_.data(), used_)); }
        catch (...) { sink_.note_drop(); }
    }
    used_ = 0;
    overlong_ = false;
}
void DiagnosticOutput::append(const char *data, std::size_t size) noexcept
{
    for (std::size_t i = 0; i < size; ++i) {
        if (used_ < line_.size() && !overlong_) line_[used_++] = data[i];
        else overlong_ = true;
        if (data[i] == '\n') finish();
    }
}
std::streamsize DiagnosticOutput::xsputn(const char *data, std::streamsize size)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (size > 0) append(data, static_cast<std::size_t>(size));
    return size;
}
DiagnosticOutput::int_type DiagnosticOutput::overflow(int_type value)
{
    if (traits_type::eq_int_type(value, traits_type::eof())) return traits_type::not_eof(value);
    const char byte = traits_type::to_char_type(value);
    std::lock_guard<std::mutex> lock(mutex_);
    append(&byte, 1);
    return value;
}
