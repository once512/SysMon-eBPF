// SPDX-License-Identifier: MIT
#pragma once
#include <cstdint>
namespace decoy {
enum class Kind : std::uint32_t { ready = 1, probe = 2, progress = 3 };
struct Frame {
    std::uint32_t magic = 0x53434456;
    std::uint16_t version = 2, size = sizeof(Frame);
    Kind kind = Kind::ready;
    std::uint32_t reserved = 0;
    std::uint64_t sequence = 0;
    std::uint64_t mount_id = 0; // Ready only: non-reusable STATX_MNT_ID_UNIQUE.
};
inline bool valid(const Frame &frame, Kind kind)
{
    return frame.magic == 0x53434456 && frame.version == 2 && frame.size == sizeof(Frame) &&
           frame.kind == kind && !frame.reserved && (kind == Kind::ready || !frame.mount_id);
}
static_assert(sizeof(Frame) == 32);
}
