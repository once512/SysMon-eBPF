// SPDX-License-Identifier: MIT
#pragma once
#include "requester.h"
#include <cstddef>
#include <cstdint>
struct PermissionMetadata {
    OwnedFd file;
    ProcessReference requester;
    std::uint64_t mask = 0;
    std::int32_t pid = 0;
};
// Kernel-only fixed layout: one metadata plus exactly one PIDFD attachment when requested.
// No batched reads, variable FID records, or borrowed descriptors escape this decoder.
PermissionMetadata decode_permission_metadata(const void *data, std::size_t size, bool pidfd_mode);
