// SPDX-License-Identifier: MIT
#include "gate.h"
#include <cerrno>
#include <fcntl.h>
#include <poll.h>
#include <stdexcept>
#include <system_error>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {
[[noreturn]] void fail(const char *operation)
{
    throw std::system_error(errno, std::generic_category(), operation);
}
int pin_file(const std::string &path)
{
    int fd = open(path.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) fail("pin fanotify target");
    struct stat st{};
    if (fstat(fd, &st)) {
        const int saved = errno;
        close(fd);
        errno = saved;
        fail("stat fanotify target");
    }
    if (!S_ISREG(st.st_mode)) {
        close(fd);
        throw std::runtime_error("fanotify target must be an existing regular file, not a symlink");
    }
    return fd;
}
int create_group()
{
    int fd = fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK,
                          O_RDONLY | O_LARGEFILE | O_CLOEXEC);
    if (fd < 0) fail("fanotify_init (requires CAP_SYS_ADMIN and permission-event support)");
    return fd;
}
}

PermissionGate::PermissionGate(const std::string &path, bool allow)
    : target_(pin_file(path)), group_(create_group()), allow_(allow)
{
    // Follow the pinned FD rather than resolving the user's path a second time.
    const auto pinned = "/proc/self/fd/" + std::to_string(target_.get());
    if (fanotify_mark(group_.get(), FAN_MARK_ADD, FAN_OPEN_PERM,
                      AT_FDCWD, pinned.c_str())) fail("fanotify_mark FAN_OPEN_PERM");
}

bool PermissionGate::poll_once(int timeout_ms)
{
    pollfd ready{group_.get(), POLLIN, 0};
    const int result = poll(&ready, 1, timeout_ms);
    if (result < 0) {
        if (errno == EINTR) return false;
        fail("fanotify poll");
    }
    if (!result) return false;
    if (ready.revents & (POLLERR | POLLHUP | POLLNVAL))
        throw std::runtime_error("fanotify poll reported an unusable group");
    // No FAN_REPORT_* flags: the kernel returns fixed-size metadata records.
    // Read one record so an exception cannot strand FDs from an unread batch.
    fanotify_event_metadata event{};
    const auto size = read(group_.get(), &event, sizeof(event));
    if (size < 0) {
        if (errno == EAGAIN || errno == EINTR) return false;
        fail("fanotify read");
    }
    if (size != sizeof(event)) throw std::runtime_error("Short fanotify metadata record");
    OwnedFd event_fd(event.fd);
    if (event.vers != FANOTIFY_METADATA_VERSION || event.event_len != sizeof(event) ||
        event.metadata_len != sizeof(event))
        throw std::runtime_error("Unexpected fanotify metadata ABI");
    if (event.mask & FAN_Q_OVERFLOW) {
        ++stats_.overflow;
        // Stop visibly rather than presenting incomplete coverage as healthy.
        throw std::runtime_error("fanotify queue overflow; closing group releases pending requests");
    }
    if (event.fd < 0 || event.mask != FAN_OPEN_PERM)
        throw std::runtime_error("Unexpected fanotify permission event");
    fanotify_response response{event.fd, static_cast<unsigned int>(allow_ ? FAN_ALLOW : FAN_DENY)};
    ssize_t written;
    do { written = write(group_.get(), &response, sizeof(response)); }
    while (written < 0 && errno == EINTR);
    if (written < 0) fail("fanotify permission response");
    if (written != sizeof(response)) throw std::runtime_error("Short fanotify response");
    if (allow_) ++stats_.allowed;
    else ++stats_.denied;
    return true;
}
