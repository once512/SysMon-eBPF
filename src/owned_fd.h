// SPDX-License-Identifier: MIT
#pragma once
#include <unistd.h>

class OwnedFd {
    int value_ = -1;
public:
    explicit OwnedFd(int fd = -1) : value_(fd) {}
    ~OwnedFd() { if (value_ >= 0) close(value_); }
    OwnedFd(const OwnedFd &) = delete;
    OwnedFd &operator=(const OwnedFd &) = delete;
    int get() const { return value_; }
};
