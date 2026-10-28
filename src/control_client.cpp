// SPDX-License-Identifier: MIT
// 管理客户端：连接 root 服务、发送命令、验证响应后再渲染 JSON；不持有服务端或后端策略资源。
// 三种命令使用同一请求/响应路径，共用布局、对端身份、附件及截断检查。
#include "control_client.h"
#include "owned_fd.h"
#include "management/channel.h"
#include <iostream>
#include <poll.h>
#include <stdexcept>
#include <sys/socket.h>
#include <unistd.h>

static management::Reply query(const std::string &path, management::Command command)
{
    if (geteuid() != 0) throw std::runtime_error("Control command requires root");
    OwnedFd connection(socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
    const auto address = management::channel::unix_address(path);
    if (connection.get() < 0 || connect(connection.get(), reinterpret_cast<const sockaddr *>(&address), sizeof(address)) ||
        !management::channel::root_peer(connection.get())) throw std::runtime_error("Cannot connect to root control service");
    // 请求只有明确命令名，响应必须符合本包当前布局；没有协商或转换分支。
    const std::string message = management::command_name(command);
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
namespace {
void print_result(const management::Reply &reply)
{
    std::cout << management::reply_json(reply) << '\n';
    if (reply.code != management::Code::ok)
        throw management::Error(reply.code, std::string(management::command_name(reply.command)) +
                                " rejected: " + management::code_name(reply.code));
}
}
void request_stop(const std::string &path) { print_result(query(path, management::Command::stop)); }
management::Reply reload_policy(const std::string &path) { return query(path, management::Command::reload); }
void request_reload(const std::string &path) { print_result(reload_policy(path)); }
management::Reply query_status(const std::string &path) { return query(path, management::Command::status); }
void request_status(const std::string &path) { print_result(query_status(path)); }
