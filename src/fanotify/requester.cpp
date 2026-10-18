// SPDX-License-Identifier: MIT
#include "requester.h"
#include <cerrno>
#include <linux/fanotify.h>
#include <linux/magic.h>
#include <stdexcept>
#include <sys/stat.h>
#include <sys/vfs.h>
ProcessReference process_reference(int descriptor)
{
    ProcessReference reference;
    if (descriptor == FAN_NOPIDFD) reference.identity.state = ProcessReferenceState::unavailable;
    else if (descriptor == FAN_EPIDFD) reference.identity.state = ProcessReferenceState::error;
    else if (descriptor < 0) throw std::runtime_error("Unexpected kernel pidfd sentinel");
    else {
        reference.fd = OwnedFd(descriptor);
        reference.identity.state = ProcessReferenceState::present;
        struct stat metadata{};
        struct statfs filesystem{};
        if (fstat(descriptor, &metadata) || fstatfs(descriptor, &filesystem)) reference.identity.error = errno;
        else if (filesystem.f_type != PID_FS_MAGIC) reference.identity.error = EOPNOTSUPP;
        else if (!metadata.st_ino) reference.identity.error = EIO;
        else reference.identity.inode = metadata.st_ino;
    }
    return reference;
}
const char *process_reference_name(ProcessReferenceState state)
{
    switch (state) {
    case ProcessReferenceState::disabled: return "disabled";
    case ProcessReferenceState::present: return "present";
    case ProcessReferenceState::unavailable: return "unavailable";
    case ProcessReferenceState::error: return "error";
    }
    throw std::invalid_argument("Invalid process reference state");
}
