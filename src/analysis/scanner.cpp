// SPDX-License-Identifier: MIT
// 扫描传入的只读普通文件 FD，不重新打开路径，避免路径替换和失去原文件对象身份。
// 超限、读失败或可见并发变化按 error 返回；不把只扫描到的前缀当成完整文件的安全结论。
#include "scanner.h"
#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace analysis {
Response scan(int fd, std::uint64_t id, const std::string &marker, std::uint32_t limit)
{
    // 默认结果是 error，只有完整满足条件才改成 allow/deny，错误路径不会意外落入允许。
    Response response;
    response.id = id;
    struct stat before{}, after{};
    const int flags = fcntl(fd, F_GETFL);
    if (marker.empty() || marker.size() > 256 || !limit || limit > 1024 * 1024 ||
        flags < 0 || (flags & O_ACCMODE) != O_RDONLY || (flags & O_PATH) ||
        fstat(fd, &before) || !S_ISREG(before.st_mode) || before.st_size < 0 ||
        static_cast<unsigned long long>(before.st_size) > limit) return response;
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
        if (count < 0) return response;
        if (!count) break;
        contents.append(bytes, static_cast<std::size_t>(count));
        response.bytes_scanned = static_cast<std::uint32_t>(contents.size());
    }
    if (contents.size() > limit || fstat(fd, &after)) return response;
    // 找到标记直接拒绝；未找到时还需确认完整读到稳定大小，不能只因某次读取没看到标记就允许。
    if (contents.find(marker) != std::string::npos) response.result = Result::deny;
    else if (before.st_size == after.st_size && before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
             before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
             before.st_ctim.tv_sec == after.st_ctim.tv_sec && before.st_ctim.tv_nsec == after.st_ctim.tv_nsec &&
             static_cast<off_t>(contents.size()) == after.st_size)
        response.result = Result::allow;
    // Metadata comparison catches ordinary concurrent changes, not an immutable snapshot.
    return response;
}
}
