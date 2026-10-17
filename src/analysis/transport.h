// SPDX-License-Identifier: MIT
// 非阻塞 SEQPACKET 传输封装：保留报文边界，并把所有收到的 SCM_RIGHTS FD 纳入 RAII 所有权。
// would_block 是暂时无数据，closed 是对端关闭，ready 仍需上层检查协议与 FD 数量。
#pragma once
#include "owned_fd.h"
#include <cstddef>
#include <vector>

namespace analysis {
enum class Io { ready, would_block, closed };
struct Packet {
    Io status;
    std::size_t size = 0;
    std::vector<OwnedFd> fds;
};
// Nonblocking SOCK_SEQPACKET messages. Received FDs are always CLOEXEC/owned,
// including malformed packets, so rejecting a message cannot leak an FD.
Packet receive_packet(int channel, void *data, std::size_t capacity);
bool send_packet(int channel, const void *data, std::size_t size, int fd = -1);
}
