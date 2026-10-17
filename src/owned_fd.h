// SPDX-License-Identifier: MIT
// 可移动、不可复制的 FD 所有权包装：析构 close，移动转交所有权；get 只借用，release 放弃托管。
// 项目大量使用异常和提前返回，RAII 让错误路径也能关闭 FD，避免把每条分支写成手工清理。
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
