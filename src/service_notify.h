// SPDX-License-Identifier: MIT
#pragma once
#include "owned_fd.h"
#include <string>
#include <string_view>
// Optional systemd-compatible datagrams. Capture before starting threads or
// helpers so NOTIFY_SOCKET is not inherited; no libsystemd dependency.
class ServiceNotify {
    OwnedFd socket_;
    std::string address_;
    bool send(std::string_view message) const noexcept;
public:
    ServiceNotify();
    void ready() const;
    bool stopping() const noexcept;
};
