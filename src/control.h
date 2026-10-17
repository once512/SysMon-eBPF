// SPDX-License-Identifier: MIT
#pragma once
#include "owned_fd.h"
#include <string>
#include <functional>

enum class ControlCommand { none, stop, reload };

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
    void dispatch(const std::function<void(ControlCommand)> &handler);
};
void request_stop(const std::string &path);
void request_reload(const std::string &path);
