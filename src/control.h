// SPDX-License-Identifier: MIT
// 两个宿主共用的 root 管理通道：私有目录中的 UNIX SEQPACKET socket，一条完整消息对应一次命令。
// SO_PEERCRED 验证连接方 UID；这只识别 root 身份，不等于可信应用身份或跨后端事务。
#pragma once
#include "owned_fd.h"
#include "management/protocol.h"
#include <string>
#include <functional>

using ControlCommand = management::Command;

// Root-only SOCK_SEQPACKET endpoint. The directory FD anchors bind and cleanup.
class ControlServer {
    OwnedFd directory_;
    OwnedFd socket_;
    std::string name_;
    bool bound_ = false;
    static int open_directory(const std::string &path);
public:
    explicit ControlServer(const std::string &path);
    ~ControlServer();
    // Dispatches one bounded request and acknowledges only after the handler completes.
    void dispatch(const std::function<management::Reply(ControlCommand)> &handler);
};
void request_stop(const std::string &path);
void request_reload(const std::string &path);
void request_status(const std::string &path);
