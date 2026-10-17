// SPDX-License-Identifier: MIT
// 管理传输的底层约定：地址构造、内核对端身份检查和严格无 FD 接收；不执行策略命令。
// 所有 fd 参数都是借用，调用者保留所有权；拒收时关闭收到的附件 FD，不关闭连接本身。
#pragma once
#include <cstddef>
#include <string>
#include <sys/types.h>
#include <sys/un.h>

namespace management::channel {
sockaddr_un unix_address(const std::string &path);
bool root_peer(int fd);
ssize_t receive_without_fds(int fd, void *data, std::size_t capacity);
}
