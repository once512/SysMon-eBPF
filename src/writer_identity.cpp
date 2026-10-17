// SPDX-License-Identifier: MIT
// O_PATH 不读取程序内容，也不触发 fanotify open/access 权限裁决；FD 活着时 inode 不会被回收复用。
// writer 选择要求 root 所有、不可由组/其他用户写且有执行位；这是对象授权，不是内容签名或完整性证明。
#include "writer_identity.h"
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <stdexcept>
#include <sys/stat.h>
#include <sys/sysmacros.h>

PinnedPolicyFile pin_policy_file(const std::string &path, bool writer)
{
    OwnedFd fd(open(path.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC));
    if (fd.get() < 0) throw std::runtime_error("Cannot pin " + path + ": " + std::strerror(errno));
    struct stat st{};
    if (fstat(fd.get(), &st) || !S_ISREG(st.st_mode))
        throw std::runtime_error("Policy requires an existing regular file: " + path);
    if (writer && (st.st_uid != 0 || (st.st_mode & 022) || !(st.st_mode & 0111)))
        throw std::runtime_error("Writer requires a root-owned executable, not writable by group/others: " + path);
    return {std::move(fd), {major(st.st_dev), minor(st.st_dev), st.st_ino}};
}
