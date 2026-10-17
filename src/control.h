// SPDX-License-Identifier: MIT
#pragma once
#include "owned_fd.h"
#include <string>

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
    bool stop_requested();
};
void request_stop(const std::string &path);
