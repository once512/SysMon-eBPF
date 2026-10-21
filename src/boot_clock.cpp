// SPDX-License-Identifier: MIT
#include "boot_clock.h"
#include <fstream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <sys/stat.h>
#include <time.h>

namespace secmon_clock {
std::string boot_id()
{
    std::ifstream input("/proc/sys/kernel/random/boot_id");
    std::string value, extra;
    if (!(input >> value) || (input >> extra) || input.bad() || !valid_boot_id(value))
        throw std::runtime_error("Cannot read system boot ID");
    return value;
}
std::uint64_t global_boot_ns()
{
    // /proc/PID/timens_offsets describes the namespace for children. Only use
    // its offset when that is also the current clock namespace.
    struct stat current{}, children{};
    if (stat("/proc/self/ns/time", &current) || stat("/proc/self/ns/time_for_children", &children) ||
        current.st_dev != children.st_dev || current.st_ino != children.st_ino)
        throw std::runtime_error("Cannot resolve current boot-clock namespace for deadline");
    std::ifstream offsets("/proc/self/timens_offsets");
    std::string line;
    long long offset_seconds = 0, offset_nanoseconds = 0;
    bool found = false;
    while (std::getline(offsets, line)) {
        std::istringstream fields(line);
        std::string clock;
        fields >> clock;
        if (clock != "boottime") continue;
        if (found || !(fields >> offset_seconds >> offset_nanoseconds) ||
            offset_nanoseconds < 0 || offset_nanoseconds >= 1000000000LL)
            throw std::runtime_error("Invalid boot-clock namespace offset");
        found = true;
    }
    if (!found || offsets.bad()) throw std::runtime_error("Cannot read boot-clock namespace offset");
    timespec now{};
    if (clock_gettime(CLOCK_BOOTTIME, &now)) throw std::runtime_error("Cannot read boot-time clock");
    // GNU++17 wide arithmetic handles both signed offsets and overflow before
    // conversion. BPF's boot-time helper uses the unshifted kernel clock.
    const __int128 global = static_cast<__int128>(now.tv_sec) * 1000000000 + now.tv_nsec -
                            (static_cast<__int128>(offset_seconds) * 1000000000 + offset_nanoseconds);
    if (global < 0 || global > std::numeric_limits<std::uint64_t>::max())
        throw std::runtime_error("Boot time outside global clock range");
    return static_cast<std::uint64_t>(global);
}
std::uint64_t deadline_after(unsigned int milliseconds)
{
    const auto now = global_boot_ns();
    const auto duration = static_cast<std::uint64_t>(milliseconds) * 1000000;
    if (now > std::numeric_limits<std::uint64_t>::max() - duration)
        throw std::runtime_error("Lease deadline outside global clock range");
    return now + duration;
}
}
