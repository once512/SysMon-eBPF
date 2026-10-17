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
    OwnedFd(OwnedFd &&other) noexcept : value_(other.release()) {}
    OwnedFd &operator=(OwnedFd &&other) noexcept
    {
        if (this != &other) {
            if (value_ >= 0) close(value_);
            value_ = other.release();
        }
        return *this;
    }
    int release() noexcept { const int fd = value_; value_ = -1; return fd; }
    int get() const { return value_; }
};
