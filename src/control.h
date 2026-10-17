// SPDX-License-Identifier: MIT
// 两个宿主共用的 root 管理通道：私有目录中的 UNIX SEQPACKET socket，一条完整消息对应一次命令。
// SO_PEERCRED 验证连接方 UID；这只识别 root 身份，不等于可信应用身份或跨后端事务。
#pragma once
#include "owned_fd.h"
#include "management/protocol.h"
#include <string>
#include <functional>
#include <chrono>

using ControlCommand = management::Command;

// Root-only SOCK_SEQPACKET endpoint. The directory FD anchors bind and cleanup.
class ControlServer {
    OwnedFd directory_;
    OwnedFd socket_;
    OwnedFd pending_; // 最多保留一个未交付命令的连接，不在业务循环里等待其发送。
    // 这里只是待发送连接的软截止时间，下一次 dispatch 才回收；
    // 不能把它当作严格的墙钟超时保证。
    std::chrono::steady_clock::time_point expires_{};
    std::string name_;
    bool bound_ = false;
    static int open_directory(const std::string &path);
public:
    explicit ControlServer(const std::string &path);
    ~ControlServer();
    ControlServer(const ControlServer &) = delete;
    ControlServer &operator=(const ControlServer &) = delete;
    // Nonblocking dispatch: idle clients expire without delaying permission decisions.
    // Acknowledge only after the handler completes.
    // 每次最多推进一个 root 连接，调用本身不等待命令到达；
    // handler 可以执行重载，因此须由宿主串行调用。
    void dispatch(const std::function<management::Reply(ControlCommand)> &handler);
};
