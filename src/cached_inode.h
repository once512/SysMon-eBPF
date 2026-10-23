// SPDX-License-Identifier: MIT
#pragma once
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <cerrno>
// Identity/type only: never use these cached attributes to authorize an
// executable's owner/permissions or to validate configuration contents.
// DONT_SYNC avoids a remote/FUSE GETATTR on an already-held inode.
inline int cached_inode_stat(int fd, struct stat *value)
{
    struct statx result{};
    constexpr unsigned mask = STATX_INO | STATX_TYPE;
    if (statx(fd, "", AT_EMPTY_PATH | AT_STATX_DONT_SYNC, mask, &result)) return -1;
    if ((result.stx_mask & mask) != mask) { errno = EIO; return -1; }
    *value = {};
    value->st_dev = makedev(result.stx_dev_major, result.stx_dev_minor);
    value->st_ino = result.stx_ino;
    value->st_mode = result.stx_mode;
    return 0;
}
