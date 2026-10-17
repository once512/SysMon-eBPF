// SPDX-License-Identifier: MIT
#include "scanner.h"
#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace analysis {
Response scan(int fd, std::uint64_t id, const std::string &marker, std::uint32_t limit)
{
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
    while (contents.size() <= limit) {
        const auto capacity = std::min<std::size_t>(sizeof(bytes), limit + 1 - contents.size());
        ssize_t count;
        do { count = pread(fd, bytes, capacity, static_cast<off_t>(contents.size())); }
        while (count < 0 && errno == EINTR);
        if (count < 0) return response;
        if (!count) break;
        contents.append(bytes, static_cast<std::size_t>(count));
        response.bytes_scanned = static_cast<std::uint32_t>(contents.size());
    }
    if (contents.size() > limit || fstat(fd, &after)) return response;
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
