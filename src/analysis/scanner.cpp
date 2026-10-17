// SPDX-License-Identifier: MIT
// 扫描传入的只读普通文件 FD，不重新打开路径，避免路径替换和失去原文件对象身份。
// 超限、读失败或可见并发变化按 error 返回；不把只扫描到的前缀当成完整文件的安全结论。
#include "scanner.h"
#include <algorithm>
#include <cerrno>
#include <new>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace analysis {
Response scan(int fd, std::uint64_t id, const std::string &marker, std::uint32_t limit) try
{
    // 默认结果是 error，只有完整满足条件才改成 allow/deny，错误路径不会意外落入允许。
    Response response;
    response.id = id;
    struct stat before{}, after{};
    const int flags = fcntl(fd, F_GETFL);
    auto failed = [&](ScanError error, int system_errno = 0) {
        response.error = error;
        response.system_errno = system_errno;
        return response;
    };
    if (marker.empty() || marker.size() > 256 || !limit || limit > 1024 * 1024)
        return failed(ScanError::invalid_input);
    if (flags < 0) return failed(ScanError::bad_descriptor, errno);
    if ((flags & O_ACCMODE) != O_RDONLY || (flags & O_PATH)) return failed(ScanError::unsupported_descriptor);
    if (fstat(fd, &before)) return failed(ScanError::metadata_failed, errno);
    if (!S_ISREG(before.st_mode) || before.st_size < 0) return failed(ScanError::unsupported_descriptor);
    if (static_cast<unsigned long long>(before.st_size) > limit) return failed(ScanError::oversized);
    std::string contents;
    contents.reserve(static_cast<std::size_t>(before.st_size));
    char bytes[4096];
    // 最多额外读取一个字节探测增长超限；将片段累计后匹配，因此标记跨越 4096 字节读取边界也能识别。
    while (contents.size() <= limit) {
        const auto capacity = std::min<std::size_t>(sizeof(bytes), limit + 1 - contents.size());
        ssize_t count;
        // pread 不推进共享文件偏移；fanotify 事件 FD 经 SCM_RIGHTS 转交后仍是同一对象，保留非通知属性以避免递归。
        do { count = pread(fd, bytes, capacity, static_cast<off_t>(contents.size())); }
        while (count < 0 && errno == EINTR);
        if (count < 0) return failed(ScanError::read_failed, errno);
        if (!count) break;
        contents.append(bytes, static_cast<std::size_t>(count));
        response.bytes_scanned = static_cast<std::uint32_t>(contents.size());
    }
    if (contents.size() > limit) return failed(ScanError::oversized);
    if (fstat(fd, &after)) return failed(ScanError::metadata_failed, errno);
    // 找到标记直接拒绝；未找到时还需确认完整读到稳定大小，不能只因某次读取没看到标记就允许。
    if (contents.find(marker) != std::string::npos) response.result = Result::deny;
    else if (before.st_size == after.st_size && before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
             before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
             before.st_ctim.tv_sec == after.st_ctim.tv_sec && before.st_ctim.tv_nsec == after.st_ctim.tv_nsec &&
             static_cast<off_t>(contents.size()) == after.st_size)
        response.result = Result::allow;
    if (response.result == Result::error) return failed(ScanError::changed);
    // Metadata comparison catches ordinary concurrent changes, not an immutable snapshot.
    return response;
} catch (const std::bad_alloc &) {
    // 扫描缓冲区不足时返回可诊断的单请求错误，控制响应在栈上构造，无需再次分配。
    Response response;
    response.id = id;
    response.error = ScanError::resource_exhausted;
    response.system_errno = ENOMEM;
    return response;
}
}
