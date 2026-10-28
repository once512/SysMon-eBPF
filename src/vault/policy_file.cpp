// SPDX-License-Identifier: MIT
#include "policy_file.h"
#include <secmon/policy_limits.h>
#include <array>
#include <cerrno>
#include <cstring>
#include <cstdint>
#include <fcntl.h>
#include <stdexcept>
#include <system_error>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>
namespace vault {
namespace {
[[noreturn]] void failure(const char *what) { throw std::system_error(errno, std::generic_category(), what); }
void regular(int fd, struct stat &stat)
{
    if (fd < 0 || fstat(fd, &stat)) failure("inspect private policy file");
    if (!S_ISREG(stat.st_mode) || stat.st_uid || (stat.st_mode & 07777) != 0600 || stat.st_nlink != 1 ||
        stat.st_size < 0 || stat.st_size > SECMON_POLICY_MAX_BYTES)
        throw std::runtime_error("Vault policy/lock must be root-owned, mode 0600, regular, single-link and at most 64 KiB");
}
}
PolicyFile::PolicyFile(const std::string &path, bool exclusive)
{
    if (path.empty() || path.front() != '/' || path.back() == '/') throw std::runtime_error("Require absolute policy file path");
    directory_ = OwnedFd(open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (directory_.get() < 0) failure("open policy root");
    std::size_t begin = 1;
    while (begin < path.size()) {
        const auto end = path.find('/', begin);
        const auto part = path.substr(begin, end == std::string::npos ? end : end - begin);
        if (part.empty() || part == "." || part == "..") throw std::runtime_error("Require canonical policy path without dot components");
        if (end == std::string::npos) { name_ = part; break; }
        OwnedFd next(openat(directory_.get(), part.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
        struct stat stat{};
        if (next.get() < 0 || fstat(next.get(), &stat)) failure("open trusted policy directory");
        // Root-owned sticky shared ancestors (/tmp) cannot replace root-owned
        // child directories. The final policy directory itself must be private.
        if (stat.st_uid || ((stat.st_mode & 0022) && !(stat.st_mode & S_ISVTX)))
            throw std::runtime_error("Policy ancestors must be root-owned and non-writable, or root-owned sticky directories");
        directory_ = std::move(next); begin = end + 1;
    }
    struct stat parent{};
    if (fstat(directory_.get(), &parent)) failure("inspect policy directory");
    if (parent.st_uid || (parent.st_mode & 0022)) throw std::runtime_error("Policy directory must be root-owned without group/other write");
    if (exclusive) {
        const auto lock_name = "." + name_ + ".secmon-vault.lock";
        OwnedFd lock(openat(directory_.get(), lock_name.c_str(), O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600));
        if (lock.get() >= 0) {
            if (fchmod(lock.get(), 0600)) failure("set private policy lock mode");
        } else if (errno == EEXIST) {
            OwnedFd pinned(openat(directory_.get(), lock_name.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC));
            struct stat stat{}; regular(pinned.get(), stat);
            const auto reference = "/proc/self/fd/" + std::to_string(pinned.get());
            const int reopened = open(reference.c_str(), O_RDWR | O_CLOEXEC | O_NONBLOCK);
            if (reopened < 0) failure("reopen private policy lock");
            lock = OwnedFd(reopened);
        } else failure("create private policy lock");
        struct stat stat{}; regular(lock.get(), stat);
        lock_ = std::move(lock);
        if (flock(lock_.get(), LOCK_EX | LOCK_NB)) failure("vault policy is busy (lock)");
    }
}
std::string PolicyFile::read() const
{
    OwnedFd pinned(openat(directory_.get(), name_.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC));
    struct stat before{}, after{}; regular(pinned.get(), before);
    const auto reference = "/proc/self/fd/" + std::to_string(pinned.get());
    OwnedFd fd(open(reference.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK));
    if (fd.get() < 0) failure("open pinned private policy");
    std::string text;
    std::array<char, 4096> chunk{};
    for (;;) {
        const auto count = ::read(fd.get(), chunk.data(), chunk.size());
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) failure("read private policy");
        if (!count) break;
        text.append(chunk.data(), count);
        if (text.size() > SECMON_POLICY_MAX_BYTES) throw std::runtime_error("Policy exceeds 64 KiB");
    }
    regular(fd.get(), after);
    if (before.st_size != after.st_size || before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
        before.st_mtim.tv_nsec != after.st_mtim.tv_nsec || before.st_ctim.tv_sec != after.st_ctim.tv_sec ||
        before.st_ctim.tv_nsec != after.st_ctim.tv_nsec) throw std::runtime_error("Policy changed while reading");
    return text;
}
void PolicyFile::replace(const std::string &expected, const std::string &contents) const
{
    if (lock_.get() < 0) throw std::runtime_error("Policy replacement requires exclusive lock");
    if (contents.size() > SECMON_POLICY_MAX_BYTES) throw std::runtime_error("Candidate exceeds 64 KiB");
    if (read() != expected) throw std::runtime_error("Policy changed before replacement");
    OwnedFd original(openat(directory_.get(), name_.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK));
    struct stat metadata{}; regular(original.get(), metadata);
    std::array<char, 4096> label{};
    const auto label_size = fgetxattr(original.get(), "security.selinux", label.data(), label.size());
    if (label_size < 0 && errno != ENODATA && errno != ENOTSUP) failure("read policy SELinux label");
    std::uint64_t nonce = 0;
    if (getrandom(&nonce, sizeof(nonce), 0) != sizeof(nonce)) failure("policy staging randomness");
    const auto temporary = ".secmon-vault-" + std::to_string(nonce) + ".tmp";
    OwnedFd stage(openat(directory_.get(), temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
    if (stage.get() < 0) failure("create private policy staging file");
    bool published = false;
    try {
        if (fchown(stage.get(), 0, metadata.st_gid) || fchmod(stage.get(), 0600)) failure("set policy staging ownership");
        if (label_size >= 0 && fsetxattr(stage.get(), "security.selinux", label.data(), label_size, 0)) failure("preserve policy SELinux label");
        std::size_t written = 0;
        while (written < contents.size()) {
            const auto count = write(stage.get(), contents.data() + written, contents.size() - written);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) failure("write policy staging file");
            written += count;
        }
        if (fsync(stage.get())) failure("sync policy staging file");
        if (read() != expected) throw std::runtime_error("Policy changed during staging");
        if (renameat(directory_.get(), temporary.c_str(), directory_.get(), name_.c_str())) failure("publish private policy");
        published = true;
        if (fsync(directory_.get())) failure("sync policy directory after publication (file may already be replaced)");
    } catch (...) {
        if (!published) unlinkat(directory_.get(), temporary.c_str(), 0);
        throw;
    }
}
}
