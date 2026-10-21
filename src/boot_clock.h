// SPDX-License-Identifier: MIT
// All persisted deadlines use the kernel's unshifted CLOCK_BOOTTIME coordinate.
#pragma once
#include <cstdint>
#include <string>
#include <string_view>

namespace secmon_clock {
inline bool valid_boot_id(std::string_view value)
{
    if (value.size() != 36) return false;
    bool nonzero = false;
    for (std::size_t index = 0; index < value.size(); ++index) {
        const char c = value[index];
        if (index == 8 || index == 13 || index == 18 || index == 23) {
            if (c != '-') return false;
        } else {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
            nonzero |= c != '0';
        }
    }
    return nonzero;
}
std::string boot_id();
std::uint64_t global_boot_ns();
std::uint64_t deadline_after(unsigned int milliseconds);
}
