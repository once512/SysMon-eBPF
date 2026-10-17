// SPDX-License-Identifier: MIT
// SCM_RIGHTS 传的是打开文件描述的引用，接收者得到自己的 FD 数字，不是直接使用发送者的整数。
// 错误报文也可能附带真实 FD，必须先接管再拒绝；MSG_CMSG_CLOEXEC 防止这些 FD 泄漏到后续 exec。
#include "transport.h"
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <system_error>
#include <sys/socket.h>

namespace analysis {
Packet receive_packet(int channel, void *data, std::size_t capacity)
{
    // Allocate ownership storage before recvmsg installs any FDs in this process.
    // Once descriptors arrive, taking ownership must not allocate/throw.
    Packet packet{Io::ready, 0, {}};
    // recvmsg 会在本进程安装新 FD；必须在它之前预留容器，安装后接管不能再因分配失败抛错。
    packet.fds.reserve(8);
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
    packet.status = count ? Io::ready : Io::closed;
    packet.size = static_cast<std::size_t>(count);
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
    // 即使正文或辅助数据被截断，也先让 packet 托管已经收到的所有 FD，异常析构时统一关闭。
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
        // 传递的是同一个打开文件描述的引用，因此文件偏移等状态可共享；发送端 FD 不会因此自动关闭。
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
