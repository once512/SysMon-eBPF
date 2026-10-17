// SPDX-License-Identifier: MIT
// 可移动、不可复制的 FD 所有权包装：析构 close，移动转交所有权；get 只借用，release 放弃托管。
// 项目大量使用异常和提前返回，RAII 让错误路径也能关闭 FD，避免把每条分支写成手工清理。
#pragma once
#include <unistd.h>

class OwnedFd {
    int value_ = -1;
public:
    // 构造接管一个已打开的 FD，-1 表示没有资源；
    // 它不会替调用者执行 open 或 dup。
    explicit OwnedFd(int fd = -1) : value_(fd) {}
    ~OwnedFd() { if (value_ >= 0) close(value_); }
    OwnedFd(const OwnedFd &) = delete;
    OwnedFd &operator=(const OwnedFd &) = delete;
    // 移动只转交同一个 FD 的关闭责任，不创建新文件引用；
    // 原对象随后析构不会再 close。
    OwnedFd(OwnedFd &&other) noexcept : value_(other.release()) {}
    OwnedFd &operator=(OwnedFd &&other) noexcept
    {
        // 移动赋值先释放本对象原资源，再接管来源；
        // 自我移动不应把唯一句柄提前关闭。
        if (this != &other) {
            if (value_ >= 0) close(value_);
            value_ = other.release();
        }
        return *this;
    }
    // release 是交出所有权，不是释放内核文件；
    // 接收方必须马上建立新的生命周期管理。
    int release() noexcept { const int fd = value_; value_ = -1; return fd; }
    // get 只借用整数供系统调用使用；
    // 不能把借用值再交给另一个会 close 的所有者。
    int get() const { return value_; }
};
