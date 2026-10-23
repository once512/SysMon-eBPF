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
    bool control_truncated = false;
};
// Nonblocking SOCK_SEQPACKET messages. Received FDs are always CLOEXEC/owned,
// including malformed packets, so rejecting a message cannot leak an FD.
// data 指向调用者的正文缓冲，capacity 是字节容量；
// 返回的 Packet 只拥有附件 FD，不拥有 data。
// ready 只表示收到了报文，绝不代表协议合法；
// 上层仍必须验证 packet.size 和附件数量。
Packet receive_packet(int channel, void *data, std::size_t capacity, bool allow_control_truncation = false);
// 函数借用 fd，成功发送也不会关闭它；
// 返回 false 代表暂时未发送，异常代表传输错误。
bool send_packet(int channel, const void *data, std::size_t size, int fd = -1);
}
