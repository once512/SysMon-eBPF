// SPDX-License-Identifier: MIT
// 管理客户端：连接 root 服务、发送命令、验证响应后再渲染 JSON；不持有服务端或后端策略资源。
// stop 保留旧报文，status/reload 使用当前结构化协议；两者共用严格的附件/截断检查。
#include "control_client.h"
#include "owned_fd.h"
#include "management/channel.h"
#include <cstring>
#include <iostream>
#include <poll.h>
#include <stdexcept>
#include <sys/socket.h>
#include <unistd.h>

static void request_command(const std::string &path, const char *command)
{
    if (geteuid() != 0) throw std::runtime_error("Control command requires root");
    OwnedFd connection(socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
    const auto address = management::channel::unix_address(path);
    if (connection.get() < 0 ||
        connect(connection.get(), reinterpret_cast<const sockaddr *>(&address), sizeof(address)) ||
        !management::channel::root_peer(connection.get())) throw std::runtime_error("Cannot connect to root control service");
    if (send(connection.get(), command, std::strlen(command), MSG_NOSIGNAL) != static_cast<ssize_t>(std::strlen(command)))
        throw std::runtime_error("Cannot send control request");
    pollfd response{connection.get(), POLLIN, 0};
    char result[8]{};
    if (poll(&response, 1, 3000) <= 0 || management::channel::receive_without_fds(connection.get(), result, sizeof(result)) != 2 ||
        std::memcmp(result, "ok", 2)) throw std::runtime_error("Control request rejected or not acknowledged");
}

void request_stop(const std::string &path) { request_command(path, "stop"); }
static management::Reply query(const std::string &path, management::Command command)
{
    if (geteuid() != 0) throw std::runtime_error("Control command requires root");
    OwnedFd connection(socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
    const auto address = management::channel::unix_address(path);
    if (connection.get() < 0 || connect(connection.get(), reinterpret_cast<const sockaddr *>(&address), sizeof(address)) ||
        !management::channel::root_peer(connection.get())) throw std::runtime_error("Cannot connect to root control service");
    // 版本放在请求文本中，服务据此选择响应长度；
    // 新客户端要求当前版本，不把旧响应静默当作完整状态。
    const std::string message = std::string(management::command_name(command)) + "-v3";
    if (send(connection.get(), message.data(), message.size(), MSG_NOSIGNAL) != static_cast<ssize_t>(message.size()))
        throw std::runtime_error("Cannot send management request");
    pollfd incoming{connection.get(), POLLIN, 0};
    if (poll(&incoming, 1, 3000) <= 0) throw std::runtime_error("Management response deadline exceeded");
    management::Reply reply;
    if (management::channel::receive_without_fds(connection.get(), &reply, sizeof(reply)) != sizeof(reply))
        throw std::runtime_error("Unexpected management response size");
    // 先验证长度、魔数、枚举和计数关系，再允许 JSON 渲染索引枚举数组或解释字段。
    management::validate_reply(reply, command);
    ucred peer{};
    socklen_t size = sizeof(peer);
    // SO_PEERCRED 给出连接的真实服务进程；
    // 校验报文 pid，防止把其他实例自报的状态当作本端响应。
    if (getsockopt(connection.get(), SOL_SOCKET, SO_PEERCRED, &peer, &size) ||
        reply.pid != static_cast<std::uint32_t>(peer.pid)) throw std::runtime_error("Management peer PID mismatch");
    return reply;
}
void request_reload(const std::string &path)
{
    const auto reply = query(path, management::Command::reload);
    std::cout << management::reply_json(reply) << '\n';
    if (reply.code != management::Code::ok)
        throw management::Error(reply.code, std::string("Policy reload rejected: ") + management::code_name(reply.code));
}
management::Reply query_status(const std::string &path) { return query(path, management::Command::status); }
void request_status(const std::string &path)
{
    const auto reply = query_status(path);
    std::cout << management::reply_json(reply) << '\n';
    if (reply.code != management::Code::ok)
        throw management::Error(reply.code, std::string("Status request rejected: ") + management::code_name(reply.code));
}
