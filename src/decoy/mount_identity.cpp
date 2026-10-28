// SPDX-License-Identifier: MIT
#include "mount_identity.h"
#include "owned_fd.h"
#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <linux/mount.h>
#include <linux/stat.h>
#include <sstream>
#include <stdexcept>
#include <system_error>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unordered_map>
#include <unistd.h>
namespace decoy {
namespace {
constexpr std::size_t max_bytes = 1024 * 1024, max_entries = 8192;
struct Entry { std::uint32_t id, parent; std::string path; };
bool prefix(const std::string &base, const std::string &path)
{
    return base == "/" || path == base || (path.size() > base.size() &&
        path.compare(0, base.size(), base) == 0 && path[base.size()] == '/');
}
bool decode(const std::string &in, std::string &out)
{
    out.clear();
    for (std::size_t i = 0; i < in.size(); ++i) {
        if (in[i] != '\\') { out += in[i]; continue; }
        if (i + 3 >= in.size()) return false;
        const auto code = in.substr(i + 1, 3);
        if (code == "040") out += ' ';
        else if (code == "011") out += '\t';
        else if (code == "012") out += '\n';
        else if (code == "134") out += '\\';
        else return false;
        i += 3;
    }
    return !out.empty() && out.front() == '/';
}
bool number(const std::string &text, std::uint32_t &out)
{
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), out);
    return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size() && out;
}
}
std::uint64_t unique_mount_id(int fd)
{
    struct statx stat{};
    if (statx(fd, "", AT_EMPTY_PATH | AT_STATX_DONT_SYNC, STATX_MNT_ID_UNIQUE, &stat))
        throw std::system_error(errno, std::generic_category(), "decoy mount identity");
    if (!(stat.stx_mask & STATX_MNT_ID_UNIQUE) || !stat.stx_mnt_id)
        throw std::runtime_error("Kernel did not return a unique mount ID");
    return stat.stx_mnt_id;
}
MountSnapshot inspect_mountinfo(std::istream &input, std::uint32_t id, const std::string &path)
{
    std::unordered_map<std::uint32_t, Entry> entries;
    std::unordered_multimap<std::uint32_t, std::uint32_t> children;
    std::string line;
    std::size_t bytes = 0;
    while (std::getline(input, line)) {
        bytes += line.size() + 1;
        if (bytes > max_bytes || entries.size() >= max_entries) return {MountState::unknown, E2BIG};
        std::istringstream row(line);
        std::string id_text, parent_text, device, root, point, options, separator;
        Entry entry{};
        if (!(row >> id_text >> parent_text >> device >> root >> point >> options) ||
            !number(id_text, entry.id) || !number(parent_text, entry.parent) || !decode(point, entry.path))
            return {MountState::unknown, EPROTO};
        while (row >> separator && separator != "-") {}
        std::string type, source, super_options;
        if (separator != "-" || !(row >> type >> source >> super_options) || !entries.emplace(entry.id, entry).second)
            return {MountState::unknown, EPROTO};
        children.emplace(entry.parent, entry.id);
    }
    if (input.bad()) return {MountState::unknown, EIO};
    const auto owned = entries.find(id);
    if (owned == entries.end()) return {MountState::detached, 0};
    if (owned->second.path != path) return {MountState::moved, 0};
    // Begin at the namespace root and follow the first covering child at each
    // step. A later ancestor mount can hide an older deeper mount even though
    // both still have their original textual mountpoints in mountinfo.
    std::uint32_t current = 0;
    for (const auto &[key, entry] : entries) {
        if (entry.path == "/" && (entry.parent == key || !entries.count(entry.parent))) {
            if (current) return {MountState::unknown, EPROTO};
            current = key;
        }
    }
    if (!current) return {MountState::unknown, EPROTO};
    for (std::size_t depth = 0; depth < entries.size(); ++depth) {
        const Entry *next = nullptr;
        const auto range = children.equal_range(current);
        for (auto it = range.first; it != range.second; ++it) {
            const auto &entry = entries.at(it->second);
            if (entry.id == current || !prefix(entry.path, path)) continue;
            if (!next || entry.path.size() < next->path.size()) next = &entry;
            else if (entry.path.size() == next->path.size()) return {MountState::unknown, EPROTO};
        }
        if (!next) return {current == id ? MountState::attached : MountState::covered, 0};
        current = next->id;
    }
    return {MountState::unknown, ELOOP};
}
MountSnapshot inspect_mount(std::uint64_t unique_id, const std::string &path) noexcept
{
    if (!unique_id) return {MountState::unknown, ENODATA};
    try {
        struct mnt_id_req request{};
        request.size = MNT_ID_REQ_SIZE_VER0; request.mnt_id = unique_id; request.param = STATMOUNT_MNT_BASIC;
        struct statmount result{};
        if (syscall(SYS_statmount, &request, &result, sizeof(result), 0))
            return {errno == ENOENT ? MountState::detached : MountState::unknown, errno == ENOENT ? 0 : errno};
        if (!(result.mask & STATMOUNT_MNT_BASIC) || result.mnt_id != unique_id || !result.mnt_id_old)
            return {MountState::unknown, EPROTO};
        // Bound memory even when proc contains an unexpectedly large topology.
        OwnedFd fd(open("/proc/self/mountinfo", O_RDONLY | O_CLOEXEC));
        if (fd.get() < 0) return {MountState::unknown, errno};
        std::string data;
        std::array<char, 8192> buffer{};
        int error = 0;
        for (;;) {
            const auto count = read(fd.get(), buffer.data(), buffer.size());
            if (count < 0 && errno == EINTR) continue;
            if (count < 0) { error = errno; break; }
            if (!count) break;
            if (data.size() + static_cast<std::size_t>(count) > max_bytes) { error = E2BIG; break; }
            data.append(buffer.data(), count);
        }
        if (error) return {MountState::unknown, error};
        std::istringstream input(data);
        const auto snapshot = inspect_mountinfo(input, result.mnt_id_old, path);
        // The old numeric ID may be reused if the mount disappears while proc
        // is being read. Recheck the non-reusable ID before trusting the table.
        struct statmount confirmed{};
        if (syscall(SYS_statmount, &request, &confirmed, sizeof(confirmed), 0))
            return {errno == ENOENT ? MountState::detached : MountState::unknown, errno == ENOENT ? 0 : errno};
        if (!(confirmed.mask & STATMOUNT_MNT_BASIC) || confirmed.mnt_id != unique_id ||
            confirmed.mnt_id_old != result.mnt_id_old) return {MountState::unknown, ESTALE};
        return snapshot;
    } catch (...) { return {MountState::unknown, ENOMEM}; }
}
}
