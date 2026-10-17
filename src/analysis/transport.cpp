// SPDX-License-Identifier: MIT
#include "transport.h"
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <system_error>
#include <sys/socket.h>

namespace analysis {
Packet receive_packet(int channel, void *data, std::size_t capacity)
{
    alignas(cmsghdr) char control[CMSG_SPACE(sizeof(int) * 8)]{};
    iovec vector{data, capacity};
    msghdr message{};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    ssize_t count;
    do { count = recvmsg(channel, &message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC); }
    while (count < 0 && errno == EINTR);
    if (count < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return {Io::would_block, 0, {}};
        throw std::system_error(errno, std::generic_category(), "analysis recvmsg");
    }
    Packet packet{count ? Io::ready : Io::closed, static_cast<std::size_t>(count), {}};
    bool unexpected = false;
    for (auto *item = CMSG_FIRSTHDR(&message); item; item = CMSG_NXTHDR(&message, item)) {
        if (item->cmsg_level != SOL_SOCKET || item->cmsg_type != SCM_RIGHTS) {
            unexpected = true;
            continue;
        }
        const auto bytes = item->cmsg_len - CMSG_LEN(0);
        if (bytes % sizeof(int)) unexpected = true;
        for (std::size_t offset = 0; offset + sizeof(int) <= bytes; offset += sizeof(int)) {
            int fd;
            std::memcpy(&fd, CMSG_DATA(item) + offset, sizeof(fd));
            packet.fds.emplace_back(fd);
        }
    }
    if (unexpected || (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)))
        throw std::runtime_error("Truncated or unexpected analysis packet");
    return packet;
}

bool send_packet(int channel, const void *data, std::size_t size, int fd)
{
    iovec vector{const_cast<void *>(data), size};
    alignas(cmsghdr) char control[CMSG_SPACE(sizeof(int))]{};
    msghdr message{};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    if (fd >= 0) {
        message.msg_control = control;
        message.msg_controllen = sizeof(control);
        auto *item = CMSG_FIRSTHDR(&message);
        item->cmsg_level = SOL_SOCKET;
        item->cmsg_type = SCM_RIGHTS;
        item->cmsg_len = CMSG_LEN(sizeof(int));
        std::memcpy(CMSG_DATA(item), &fd, sizeof(fd));
    }
    ssize_t count;
    do { count = sendmsg(channel, &message, MSG_DONTWAIT | MSG_NOSIGNAL); }
    while (count < 0 && errno == EINTR);
    if (count < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return false;
        throw std::system_error(errno, std::generic_category(), "analysis sendmsg");
    }
    if (static_cast<std::size_t>(count) != size) throw std::runtime_error("Short analysis packet send");
    return true;
}
}
