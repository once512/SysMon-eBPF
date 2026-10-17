// SPDX-License-Identifier: MIT
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
