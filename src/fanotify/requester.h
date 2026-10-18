// SPDX-License-Identifier: MIT
#pragma once
#include "owned_fd.h"
#include <cstdint>
// State describes the kernel attachment at receive time, never current liveness or trust.
enum class ProcessReferenceState { disabled, present, unavailable, error };
struct ProcessIdentity {
    ProcessReferenceState state = ProcessReferenceState::disabled;
    std::uint64_t inode = 0; // Only populated after verifying PID_FS_MAGIC.
    int error = 0; // Local identity inspection errno; kernel FAN_EPIDFD has no detailed errno.
};
struct ProcessReference {
    OwnedFd fd{};
    ProcessIdentity identity{};
};
// Takes ownership of a kernel-delivered pidfd (or FAN_NOPIDFD / FAN_EPIDFD sentinel).
ProcessReference process_reference(int descriptor);
const char *process_reference_name(ProcessReferenceState state);
