// SPDX-License-Identifier: MIT
#include "policy_pins.h"
#include "cached_inode.h"
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <stdexcept>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
namespace {
pid_t unreaped = -1;
struct Packet { unsigned index; int error; struct stat attributes; };
void reap_pending()
{
    if (unreaped < 0) return;
    int status;
    const pid_t result = waitpid(unreaped, &status, WNOHANG);
    if (result == unreaped || (result < 0 && errno == ECHILD)) unreaped = -1;
    else throw std::runtime_error("Previous policy pin worker has not exited; retry later");
}
// No allocation, streams, destructors or inherited application locks after
// fork. Close every inherited service FD before touching the filesystem.
[[noreturn]] void work(int channel, pid_t parent, const std::vector<std::string> &paths)
{
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent || dup2(channel, 3) < 0 ||
        syscall(SYS_close_range, 4U, ~0U, 0)) _exit(1);
    close(0); close(1); close(2);
    for (unsigned i = 0; i < paths.size(); ++i) {
        Packet packet{}; packet.index = i;
        const int fd = open(paths[i].c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) packet.error = errno;
        else if (fstat(fd, &packet.attributes)) packet.error = errno;
        else if (!S_ISREG(packet.attributes.st_mode)) packet.error = EINVAL;
        iovec data{&packet, sizeof(packet)};
        alignas(cmsghdr) char ancillary[CMSG_SPACE(sizeof(int))]{};
        msghdr message{}; message.msg_iov = &data; message.msg_iovlen = 1;
        if (!packet.error) {
            message.msg_control = ancillary; message.msg_controllen = sizeof(ancillary);
            auto *header = CMSG_FIRSTHDR(&message);
            header->cmsg_level = SOL_SOCKET; header->cmsg_type = SCM_RIGHTS; header->cmsg_len = CMSG_LEN(sizeof(int));
            std::memcpy(CMSG_DATA(header), &fd, sizeof(fd));
        }
        ssize_t sent;
        do { sent = sendmsg(3, &message, MSG_NOSIGNAL); } while (sent < 0 && errno == EINTR);
        if (fd >= 0) close(fd);
        if (sent != sizeof(packet) || packet.error) _exit(1);
    }
    close(3); _exit(0);
}
}
thread_local const PolicyPins *PolicyPins::active_ = nullptr;
void PolicyPins::reap() noexcept
{
    if (unreaped < 0) return;
    int status;
    const auto result = waitpid(unreaped, &status, WNOHANG);
    if (result == unreaped || (result < 0 && errno == ECHILD)) unreaped = -1;
}
PolicyPins::PolicyPins(const std::vector<std::string> &requested, const std::function<void()> &progress)
{
    if (active_) throw std::runtime_error("Nested policy pin preparation");
    reap_pending();
    auto paths = requested;
    std::sort(paths.begin(), paths.end());
    paths.erase(std::unique(paths.begin(), paths.end()), paths.end());
    // Caller-relative proc paths would name this forked worker instead of the
    // service. Fail closed rather than silently change the selected object.
    for (const auto &path : paths)
        if (path == "/proc/self" || path.rfind("/proc/self/", 0) == 0 ||
            path == "/proc/thread-self" || path.rfind("/proc/thread-self/", 0) == 0)
            throw std::runtime_error("Prepared policy paths require an explicit process coordinate, not proc/self");
    if (paths.size() > 400) throw std::runtime_error("Too many policy pin requests");
    if (paths.empty()) { active_ = this; return; }
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets))
        throw std::runtime_error("Cannot create policy pin channel");
    OwnedFd receiver(sockets[0]), sender(sockets[1]);
    const auto parent = getpid();
    const pid_t child = fork();
    if (!child) work(sender.get(), parent, paths);
    if (child < 0) throw std::runtime_error("Cannot create policy pin worker");
    sender = OwnedFd();
    bool reaped = false;
    try {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        std::size_t index = 0;
        for (;;) {
            progress();
            if (std::chrono::steady_clock::now() >= deadline)
                throw std::runtime_error("Policy pin preparation timed out after 2000ms");
            pollfd item{receiver.get(), POLLIN, 0};
            const int ready = poll(&item, 1, 5);
            if (ready < 0 && errno == EINTR) continue;
            if (ready < 0) throw std::runtime_error("Policy pin poll failed");
            if (ready && (item.revents & POLLIN)) {
                Packet packet{};
                iovec data{&packet, sizeof(packet)};
                alignas(cmsghdr) char ancillary[CMSG_SPACE(sizeof(int))]{};
                msghdr message{}; message.msg_iov = &data; message.msg_iovlen = 1;
                message.msg_control = ancillary; message.msg_controllen = sizeof(ancillary);
                const auto size = recvmsg(receiver.get(), &message, MSG_CMSG_CLOEXEC | MSG_DONTWAIT);
                OwnedFd received;
                bool bad = false;
                for (auto *header = CMSG_FIRSTHDR(&message); header; header = CMSG_NXTHDR(&message, header)) {
                    if (header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS ||
                        header->cmsg_len < CMSG_LEN(sizeof(int))) { bad = true; continue; }
                    const auto count = (header->cmsg_len - CMSG_LEN(0)) / sizeof(int);
                    for (std::size_t n = 0; n < count; ++n) {
                        int fd; std::memcpy(&fd, CMSG_DATA(header) + n * sizeof(int), sizeof(fd));
                        OwnedFd next(fd);
                        if (received.get() >= 0) bad = true;
                        else received = std::move(next);
                    }
                }
                if (!size) {
                    if (index != paths.size()) throw std::runtime_error("Policy pin worker closed early");
                } else {
                    if (size != sizeof(packet) || (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) || bad ||
                        index >= paths.size() || packet.index != index)
                        throw std::runtime_error("Invalid policy pin worker reply");
                    if (packet.error) throw std::runtime_error("Cannot pin " + paths[index] + ": " + std::strerror(packet.error));
                    if (received.get() < 0 || !S_ISREG(packet.attributes.st_mode))
                        throw std::runtime_error("Policy pin worker omitted a regular-file reference");
                    struct stat identity{};
                    if (cached_inode_stat(received.get(), &identity) || identity.st_dev != packet.attributes.st_dev ||
                        identity.st_ino != packet.attributes.st_ino || !S_ISREG(identity.st_mode))
                        throw std::runtime_error("Policy pin worker reference/identity mismatch");
                    files_.emplace(paths[index++], Entry{std::move(received), packet.attributes});
                }
            }
            if (!reaped) {
                int status;
                const auto result = waitpid(child, &status, WNOHANG);
                if (result == child) {
                    reaped = true;
                    if (!WIFEXITED(status) || WEXITSTATUS(status))
                        throw std::runtime_error("Policy pin worker failed");
                    // Successful exit can precede consumption of its queued
                    // replies; keep draining them without re-waiting the PID.
                } else if (result < 0 && errno != EINTR) {
                    throw std::runtime_error("Cannot reap policy pin worker");
                }
            }
            if (reaped && index == paths.size()) break;
        }
        active_ = this;
    } catch (...) {
        if (!reaped) {
            kill(child, SIGKILL);
            int status;
            if (waitpid(child, &status, WNOHANG) != child) unreaped = child;
        }
        throw;
    }
}
PolicyPins::~PolicyPins() { if (active_ == this) active_ = nullptr; }
bool PolicyPins::copy(const std::string &path, OwnedFd &fd, struct stat &attributes)
{
    if (!active_) return false;
    const auto found = active_->files_.find(path);
    if (found == active_->files_.end()) throw std::runtime_error("Unprepared policy path: " + path);
    const int duplicate = fcntl(found->second.fd.get(), F_DUPFD_CLOEXEC, 0);
    if (duplicate < 0) throw std::runtime_error("Cannot duplicate prepared policy reference");
    fd = OwnedFd(duplicate); attributes = found->second.attributes;
    return true;
}
