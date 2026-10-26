// SPDX-License-Identifier: MIT
#include "event_reader.h"
#include "analysis/transport.h"
#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <linux/fanotify.h>
#include <linux/magic.h>
#include <sys/vfs.h>
#include <poll.h>
#include <stdexcept>
#include <sys/eventfd.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
namespace {
constexpr std::size_t capacity = 4097;
struct Child { pid_t pid = -1; bool detached = false; };
std::array<Child, 16> children;
struct Command {
    struct { std::uint64_t sequence; int kernel_fd; } token;
    std::uint64_t request_id; // 0 releases the file, otherwise relay a scan.
};
struct Frame {
    std::uint64_t sequence, mask, dispatch_error;
    std::int32_t kernel_fd, requester_pid, pidfd;
    PermissionObject object;
};
struct Held { std::uint64_t sequence = 0; int fd = -1; };
// This forked child only uses fixed storage and syscalls. No service C++
// objects, allocation, logging, policy or BPF references survive here.
[[noreturn]] void run_reader(int channel, int group, pid_t parent, bool pidfd_mode, int analyzer)
{
    const int socket_copy = fcntl(channel, F_DUPFD_CLOEXEC, 6);
    const int group_copy = fcntl(group, F_DUPFD_CLOEXEC, 6);
    const int analyzer_copy = analyzer < 0 ? -1 : fcntl(analyzer, F_DUPFD_CLOEXEC, 6);
    if (socket_copy < 0 || group_copy < 0 || prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent ||
        dup2(socket_copy, 3) < 0 || dup2(group_copy, 4) < 0 ||
        (analyzer >= 0 && (analyzer_copy < 0 || dup2(analyzer_copy, 5) < 0)) ||
        syscall(SYS_close_range, 6U, ~0U, 0)) _exit(1);
    if (analyzer < 0) close(5);
    close(0); close(1); close(2);
    std::array<Held, capacity> held{};
    std::size_t count = 0;
    std::uint64_t sequence = 1;
    const Frame ready{};
    if (send(3, &ready, sizeof(ready), MSG_NOSIGNAL) != sizeof(ready)) _exit(1);
    for (;;) {
        // Release commands win over further reads. Closing a FUSE file may
        // itself wait for its provider; only this child is exposed to that wait.
        Command request{};
        const auto command = recv(3, &request, sizeof(request), MSG_DONTWAIT);
        if (!command) _exit(0);
        if (command > 0) {
            if (command != sizeof(request)) _exit(1);
            bool found = false;
            for (auto &entry : held) if (entry.sequence == request.token.sequence && entry.fd == request.token.kernel_fd) {
                found = true;
                if (!request.request_id) {
                    close(entry.fd); entry.fd = -1; entry.sequence = 0; --count;
                } else {
                    if (analyzer < 0) _exit(1);
                    analysis::Request scan; scan.id = request.request_id;
                    iovec data{&scan, sizeof(scan)};
                    alignas(cmsghdr) char ancillary[CMSG_SPACE(sizeof(int))]{};
                    msghdr message{}; message.msg_iov = &data; message.msg_iovlen = 1;
                    message.msg_control = ancillary; message.msg_controllen = sizeof(ancillary);
                    auto *header = CMSG_FIRSTHDR(&message);
                    header->cmsg_level = SOL_SOCKET; header->cmsg_type = SCM_RIGHTS;
                    header->cmsg_len = CMSG_LEN(sizeof(int));
                    std::memcpy(CMSG_DATA(header), &entry.fd, sizeof(int));
                    ssize_t sent;
                    do { sent = sendmsg(5, &message, MSG_DONTWAIT | MSG_NOSIGNAL); } while (sent < 0 && errno == EINTR);
                    if (sent != sizeof(scan)) {
                        Frame failure{}; failure.sequence = sequence++; failure.kernel_fd = -1;
                        failure.dispatch_error = request.request_id;
                        if (!failure.sequence || send(3, &failure, sizeof(failure), MSG_NOSIGNAL) != sizeof(failure)) _exit(1);
                    }
                }
                break;
            }
            if (!found) _exit(1);
            continue;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) _exit(1);
        pollfd inputs[] = {{3, POLLIN, 0}, {count < capacity ? 4 : -1, POLLIN, 0}};
        const int ready = poll(inputs, 2, -1);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0 || (inputs[0].revents & (POLLERR | POLLHUP | POLLNVAL))) _exit(1);
        if (inputs[0].revents & POLLIN) continue;
        if (!(inputs[1].revents & POLLIN)) continue;
        alignas(fanotify_event_metadata) char bytes[sizeof(fanotify_event_metadata) + sizeof(fanotify_event_info_pidfd)]{};
        const auto size = read(4, bytes, sizeof(bytes));
        if (size < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        const auto expected = sizeof(fanotify_event_metadata) + (pidfd_mode ? sizeof(fanotify_event_info_pidfd) : 0);
        if (size != static_cast<ssize_t>(expected)) _exit(1);
        fanotify_event_metadata metadata{};
        std::memcpy(&metadata, bytes, sizeof(metadata));
        if (metadata.vers != FANOTIFY_METADATA_VERSION || metadata.metadata_len != sizeof(metadata) || metadata.event_len != expected)
            _exit(1);
        Frame frame{};
        frame.sequence = sequence++; frame.mask = metadata.mask; frame.kernel_fd = metadata.fd;
        frame.requester_pid = metadata.pid; frame.pidfd = FAN_NOPIDFD;
        if (!frame.sequence) _exit(1);
        if (pidfd_mode) {
            fanotify_event_info_pidfd attachment{};
            std::memcpy(&attachment, bytes + sizeof(metadata), sizeof(attachment));
            if (attachment.hdr.info_type != FAN_EVENT_INFO_TYPE_PIDFD || attachment.hdr.len != sizeof(attachment) || attachment.hdr.pad)
                _exit(1);
            frame.pidfd = attachment.pidfd;
            if (frame.pidfd >= 0) {
                struct statfs filesystem{};
                if (frame.pidfd == metadata.fd || fstatfs(frame.pidfd, &filesystem) || filesystem.f_type != PID_FS_MAGIC) _exit(1);
            } else if (frame.pidfd != FAN_NOPIDFD && frame.pidfd != FAN_EPIDFD) _exit(1);
        }
        if (metadata.fd >= 0) {
            struct statx identity{};
            const unsigned mask = STATX_INO | STATX_TYPE;
            if (syscall(SYS_statx, metadata.fd, "", AT_EMPTY_PATH | AT_STATX_DONT_SYNC, mask, &identity) ||
                (identity.stx_mask & mask) != mask) _exit(1);
            frame.object = {identity.stx_dev_major, identity.stx_dev_minor, identity.stx_ino};
            for (auto &entry : held) if (entry.fd < 0) { entry = {frame.sequence, metadata.fd}; ++count; break; }
        }
        iovec data{&frame, sizeof(frame)};
        alignas(cmsghdr) char ancillary[CMSG_SPACE(sizeof(int))]{};
        msghdr message{}; message.msg_iov = &data; message.msg_iovlen = 1;
        if (pidfd_mode && frame.pidfd >= 0) {
            message.msg_control = ancillary; message.msg_controllen = sizeof(ancillary);
            auto *header = CMSG_FIRSTHDR(&message);
            header->cmsg_level = SOL_SOCKET; header->cmsg_type = SCM_RIGHTS; header->cmsg_len = CMSG_LEN(sizeof(int));
            std::memcpy(CMSG_DATA(header), &frame.pidfd, sizeof(int));
        }
        ssize_t sent;
        do { sent = sendmsg(3, &message, MSG_NOSIGNAL); } while (sent < 0 && errno == EINTR);
        if (pidfd_mode && frame.pidfd >= 0) close(frame.pidfd);
        if (sent != sizeof(frame)) _exit(1);
    }
}
}
void EventReader::reap() noexcept
{
    for (auto &child : children) if (child.pid > 0 && child.detached) {
        int status;
        const auto result = waitpid(child.pid, &status, WNOHANG);
        if (result == child.pid || (result < 0 && errno == ECHILD)) child = {};
    }
}
EventReader::EventReader(int group, bool pidfd_mode, int analyzer_channel) : pidfd_mode_(pidfd_mode)
{
    reap();
    for (std::size_t i = 0; i < children.size(); ++i) if (children[i].pid < 0) { slot_ = i; break; }
    if (slot_ < 0) throw std::runtime_error("Too many unreaped fanotify readers");
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair)) throw std::runtime_error("Cannot create fanotify reader channel");
    channel_ = OwnedFd(pair[0]); OwnedFd other(pair[1]);
    const pid_t parent = getpid();
    const pid_t child = fork();
    if (!child) run_reader(other.get(), group, parent, pidfd_mode, analyzer_channel);
    if (child < 0) { slot_ = -1; throw std::runtime_error("Cannot fork fanotify reader"); }
    children[slot_] = {child, false};
    try {
        pollfd ready{channel_.get(), POLLIN, 0};
        if (poll(&ready, 1, 500) <= 0) throw std::runtime_error("Fanotify reader bootstrap timed out");
        Frame frame{};
        auto packet = analysis::receive_packet(channel_.get(), &frame, sizeof(frame));
        if (packet.status != analysis::Io::ready || packet.size != sizeof(frame) ||
            frame.sequence || frame.mask || frame.dispatch_error || !packet.fds.empty())
            throw std::runtime_error("Invalid fanotify reader bootstrap");
    } catch (...) { stop(); throw; }
}
EventReader::~EventReader() { stop(); }
void EventReader::stop() noexcept
{
    if (slot_ < 0) return;
    auto &child = children[slot_];
    kill(child.pid, SIGKILL);
    child.detached = true;
    // Bounded cleanup; never join an uninterruptible remote-filesystem wait.
    for (int attempt = 0; attempt < 20 && child.pid > 0; ++attempt) {
        reap();
        if (child.pid > 0) poll(nullptr, 0, 1);
    }
    slot_ = -1;
    channel_ = OwnedFd(); tokens_.clear(); command_count_ = 0;
}
void EventReader::flush()
{
    reap();
    while (command_count_) {
        const auto &queued = commands_[command_head_];
        const Command message{{queued.token.sequence, queued.token.kernel_fd}, queued.request_id};
        if (!analysis::send_packet(channel_.get(), &message, sizeof(message))) break;
        command_head_ = (command_head_ + 1) % commands_.size(); --command_count_;
    }
}
std::optional<EventReader::Event> EventReader::receive()
{
    // Reserve the decision handle first. With only one free descriptor, lose
    // the optional requester reference rather than the permission verdict.
    OwnedFd handle(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK));
    if (handle.get() < 0) throw std::runtime_error("Cannot allocate permission handle");
    Frame frame{};
    auto packet = analysis::receive_packet(channel_.get(), &frame, sizeof(frame), true);
    if (packet.status == analysis::Io::would_block) return std::nullopt;
    if (packet.status != analysis::Io::ready || packet.size != sizeof(frame) || frame.sequence != next_sequence_++)
        throw std::runtime_error("Invalid or disconnected fanotify reader");
    Event result;
    if (frame.dispatch_error) {
        if (frame.mask || frame.kernel_fd != -1 || !packet.fds.empty() || packet.control_truncated)
            throw std::runtime_error("Invalid fanotify dispatch failure");
        result.dispatch_error = frame.dispatch_error;
        return result;
    }
    result.metadata.mask = frame.mask; result.metadata.pid = frame.requester_pid; result.object = frame.object;
    if (pidfd_mode_) {
        if (frame.pidfd >= 0) {
            if (packet.control_truncated && packet.fds.empty()) {
                result.metadata.requester.identity = {ProcessReferenceState::error, 0, 0};
            } else {
                if (packet.control_truncated || packet.fds.size() != 1)
                    throw std::runtime_error("Fanotify reader omitted requester reference");
                result.metadata.requester = process_reference(packet.fds.front().release());
            }
        } else {
            if (!packet.fds.empty()) throw std::runtime_error("Unexpected fanotify reader FD");
            result.metadata.requester = process_reference(frame.pidfd);
        }
    } else if (!packet.fds.empty()) throw std::runtime_error("Unexpected legacy fanotify reader FD");
    if (frame.kernel_fd >= 0) {
        tokens_.emplace(handle.get(), Token{frame.sequence, frame.kernel_fd});
        result.metadata.file = std::move(handle);
    }
    return result;
}
int EventReader::kernel_fd(int handle) const { return tokens_.at(handle).kernel_fd; }
void EventReader::release(int handle)
{
    if (command_count_ == commands_.size()) throw std::runtime_error("Fanotify reader command queue exhausted");
    commands_[(command_head_ + command_count_) % commands_.size()] = {tokens_.at(handle), 0};
    ++command_count_; tokens_.erase(handle);
    // Flush on the next poll, after the successful verdict is accounted.
}
void EventReader::dispatch(int handle, std::uint64_t request_id)
{
    if (!request_id || command_count_ == commands_.size())
        throw std::runtime_error("Cannot queue fanotify analysis dispatch");
    commands_[(command_head_ + command_count_) % commands_.size()] = {tokens_.at(handle), request_id};
    ++command_count_;
}
