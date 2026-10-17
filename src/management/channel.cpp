// SPDX-License-Identifier: MIT
// SOCK_SEQPACKET 保留报文边界；recvmsg 同时检查正文与附件，任何异常连接都不能遗留 SCM_RIGHTS FD。
#include "channel.h"
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <sys/socket.h>
#include <unistd.h>

namespace management::channel {
sockaddr_un unix_address(const std::string &path)
{
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    if (path.empty() || path.size() >= sizeof(address.sun_path))
        throw std::runtime_error("Invalid control socket path length");
    std::memcpy(address.sun_path, path.c_str(), path.size() + 1);
    return address;
}
bool root_peer(int fd)
{
    // 对端身份取自内核 SO_PEERCRED，不能信任客户端在消息正文中自报 UID。
    ucred peer{};
    socklen_t size = sizeof(peer);
    return !getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &size) &&
           size == sizeof(peer) && peer.uid == 0;
}
// 不接受 FD 附件。即使报文畸形，也关闭内核已安装的所有 FD，避免只查询状态就产生句柄泄漏。
ssize_t receive_without_fds(int fd, void *data, std::size_t capacity)
{
    iovec payload{data, capacity};
    alignas(cmsghdr) char ancillary[CMSG_SPACE(sizeof(int) * 8)]{};
    msghdr message{};
    message.msg_iov = &payload;
    message.msg_iovlen = 1;
    message.msg_control = ancillary;
    message.msg_controllen = sizeof(ancillary);
    ssize_t count;
    do { count = recvmsg(fd, &message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC); }
    while (count < 0 && errno == EINTR);
    if (count < 0) throw std::runtime_error("Management receive failed");
    bool attached = false;
    for (auto *item = CMSG_FIRSTHDR(&message); item; item = CMSG_NXTHDR(&message, item)) {
        attached = true;
        if (item->cmsg_level == SOL_SOCKET && item->cmsg_type == SCM_RIGHTS)
            for (std::size_t offset = 0; offset + sizeof(int) <= item->cmsg_len - CMSG_LEN(0); offset += sizeof(int)) {
                int received;
                std::memcpy(&received, CMSG_DATA(item) + offset, sizeof(received));
                close(received);
            }
    }
    if (attached || (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)))
        throw std::runtime_error("Invalid or truncated management message");
    return count;
}
} // namespace management::channel
