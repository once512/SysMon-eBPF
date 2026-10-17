// SPDX-License-Identifier: MIT
#include "policy_config.h"
#include "owned_fd.h"
#include <charconv>
#include <cerrno>
#include <fcntl.h>
#include <iomanip>
#include <set>
#include <sstream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

namespace {
constexpr std::size_t max_bytes = 65536;
[[noreturn]] void invalid() { throw std::runtime_error("Invalid policy: expected version 1, positive revision, and up to 256 quoted absolute protect paths"); }
}
PolicyConfig parse_policy(std::istream &input)
{
    PolicyConfig result;
    bool version = false;
    std::set<std::string> unique;
    std::size_t bytes = 0;
    std::string line;
    while (std::getline(input, line)) {
        bytes += line.size() + (input.eof() ? 0 : 1);
        if (bytes > max_bytes || line.find('\0') != std::string::npos) invalid();
        std::istringstream fields(line);
        std::string key, value, extra;
        if (!(fields >> key) || key.front() == '#') continue;
        if (key == "protect") {
            fields >> std::ws;
            if (fields.peek() != '"' || !(fields >> std::quoted(value)) ||
                value.empty() || value.front() != '/' || value.size() > 4095 ||
                !unique.insert(value).second || result.paths.size() == 256) invalid();
            result.paths.push_back(value);
        } else {
            if (!(fields >> value)) invalid();
            if (key == "version" && !version && value == "1") version = true;
            else if (key == "revision" && !result.revision) {
                const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result.revision);
                if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() || !result.revision) invalid();
            } else invalid();
        }
        if (fields >> extra) invalid();
    }
    if (input.bad() || !version || !result.revision) invalid();
    return result;
}
PolicyConfig load_policy(const std::string &path)
{
    if (path.empty() || path.front() != '/') throw std::runtime_error("Policy file must be absolute");
    OwnedFd fd(open(path.c_str(), O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC));
    struct stat before{}, after{};
    if (fd.get() < 0 || fstat(fd.get(), &before) || !S_ISREG(before.st_mode) ||
        before.st_uid != 0 || (before.st_mode & 022) || before.st_size > static_cast<off_t>(max_bytes))
        throw std::runtime_error("Policy must be a root-owned regular file, not writable by group/others, at most 64 KiB");
    std::string contents;
    char chunk[4096];
    for (;;) {
        const auto count = read(fd.get(), chunk, sizeof(chunk));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) throw std::runtime_error("Cannot read policy");
        if (!count) break;
        contents.append(chunk, static_cast<std::size_t>(count));
        if (contents.size() > max_bytes) throw std::runtime_error("Policy exceeds 64 KiB");
    }
    if (fstat(fd.get(), &after) || before.st_size != after.st_size ||
        before.st_mtim.tv_sec != after.st_mtim.tv_sec || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        before.st_ctim.tv_sec != after.st_ctim.tv_sec || before.st_ctim.tv_nsec != after.st_ctim.tv_nsec)
        throw std::runtime_error("Policy changed while reading; retry with an atomic file replacement");
    std::istringstream input(contents);
    return parse_policy(input);
}
