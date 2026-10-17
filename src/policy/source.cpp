// SPDX-License-Identifier: MIT
// 安全配置来源：O_PATH 固定对象 → 排除 fanotify 自身目标 → 有界读取 → 元数据复核 → 解析/摘要。
// 语法解析不负责文件权限；本文件不触碰后端资源，失败时借助 OwnedFd 回收全部临时引用。
#include "policy_config.h"
#include "owned_fd.h"
#include <secmon/policy_limits.h>
#include <cerrno>
#include <fcntl.h>
#include <sstream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

PolicyConfig load_policy(const std::string &path, int forbidden_inode_fd)
{
    if (path.empty() || path.front() != '/') throw std::runtime_error("Policy file must be absolute");
    OwnedFd pinned(open(path.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC));
    struct stat before{}, after{};
    if (pinned.get() < 0 || fstat(pinned.get(), &before) || !S_ISREG(before.st_mode) ||
        before.st_uid != 0 || (before.st_mode & 022) || before.st_size > static_cast<off_t>(SECMON_POLICY_MAX_BYTES))
        throw std::runtime_error("Policy must be a root-owned regular file, not writable by group/others, at most 64 KiB");
    // 必须在 O_RDONLY 打开之前排除监听器自身目标：否则 open/access 权限事件会让服务等待自己的裁决。
    if (forbidden_inode_fd >= 0) {
        struct stat forbidden{};
        if (fstat(forbidden_inode_fd, &forbidden)) throw std::runtime_error("Cannot inspect excluded policy inode");
        if (before.st_dev == forbidden.st_dev && before.st_ino == forbidden.st_ino)
            throw std::runtime_error("Fanotify policy file cannot be the marked inode (including hard links)");
    }
    // Reopen the pinned object, not the mutable pathname. O_PATH above emits no permission event.
    const auto reference = "/proc/self/fd/" + std::to_string(pinned.get());
    OwnedFd fd(open(reference.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC));
    if (fd.get() < 0) throw std::runtime_error("Cannot open pinned policy for reading");
    // 原始字节另行保留用于 SHA-256；
    // 摘要包含注释/空白，与解析后相同语义的配置不一定相同。
    std::string contents;
    char chunk[4096];
    for (;;) {
        const auto count = read(fd.get(), chunk, sizeof(chunk));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) throw std::runtime_error("Cannot read policy");
        if (!count) break;
        contents.append(chunk, static_cast<std::size_t>(count));
        if (contents.size() > SECMON_POLICY_MAX_BYTES) throw std::runtime_error("Policy exceeds 64 KiB");
    }
    // 比较元数据可发现普通并发修改，但不是不可变快照；部署时仍应使用可信目录中的原子文件替换。
    if (fstat(fd.get(), &after) || before.st_size != after.st_size ||
        before.st_mtim.tv_sec != after.st_mtim.tv_sec || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        before.st_ctim.tv_sec != after.st_ctim.tv_sec || before.st_ctim.tv_nsec != after.st_ctim.tv_nsec)
        throw std::runtime_error("Policy changed while reading; retry with an atomic file replacement");
    std::istringstream input(contents);
    auto parsed = parse_policy(input);
    // 摘要随成功加载的候选返回；
    // 是否成为活动摘要由 PolicyRuntime 的后端提交结果决定。
    parsed.source_digest = content_digest(contents);
    return parsed;
}
