// SPDX-License-Identifier: MIT
// 管理 socket 用目录 FD 锚定创建与清理位置；不删除不明来源的已有 socket。
// 命令处理在宿主事件循环内串行完成，回调成功后才确认；客户端超时不保证服务没有执行命令。
#include <cerrno>
#include <iostream>
#include <optional>
#include <string_view>
#include <utility>
#include <cstring>
#include <filesystem>
#include <poll.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <fcntl.h>
#include <unistd.h>

#include "control.h"

namespace {
sockaddr_un unix_address(const std::string &path)
{
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    if (path.empty() || path.size() >= sizeof(address.sun_path))
        throw std::runtime_error("Invalid control socket path length");
    std::memcpy(address.sun_path, path.c_str(), path.size() + 1);
    return address;
}
bool root_peer(int fd)
{
    // 对端身份取自内核 SO_PEERCRED，不能信任客户端在消息正文中自报 UID。
    ucred peer{};
    socklen_t size = sizeof(peer);
    return !getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &size) &&
           size == sizeof(peer) && peer.uid == 0;
}
// 不接受 FD 附件。即使报文畸形，也关闭内核已安装的所有 FD，避免只查询状态就产生句柄泄漏。
ssize_t receive_message(int fd, void *data, std::size_t capacity)
{
    iovec payload{data, capacity};
    alignas(cmsghdr) char ancillary[CMSG_SPACE(sizeof(int) * 8)]{};
    msghdr message{};
    message.msg_iov = &payload;
    message.msg_iovlen = 1;
    message.msg_control = ancillary;
    message.msg_controllen = sizeof(ancillary);
    ssize_t count;
    do { count = recvmsg(fd, &message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC); }
    while (count < 0 && errno == EINTR);
    if (count < 0) throw std::runtime_error("Management receive failed");
    bool attached = false;
    for (auto *item = CMSG_FIRSTHDR(&message); item; item = CMSG_NXTHDR(&message, item)) {
        attached = true;
        if (item->cmsg_level == SOL_SOCKET && item->cmsg_type == SCM_RIGHTS)
            for (std::size_t offset = 0; offset + sizeof(int) <= item->cmsg_len - CMSG_LEN(0); offset += sizeof(int)) {
                int received;
                std::memcpy(&received, CMSG_DATA(item) + offset, sizeof(received));
                close(received);
            }
    }
    if (attached || (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)))
        throw std::runtime_error("Invalid or truncated management message");
    return count;
}
} // namespace

int ControlServer::open_directory(const std::string &path)
{
    if (geteuid() != 0 || !std::filesystem::path(path).is_absolute())
        throw std::runtime_error("Control service requires root and an absolute socket path");
    const auto parent = std::filesystem::path(path).parent_path().string();
    int fd = open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) throw std::runtime_error("Cannot open control directory");
    struct stat st{};
    if (fstat(fd, &st) || st.st_uid != 0 || (st.st_mode & 077)) {
        close(fd);
        throw std::runtime_error("Control directory must be root owned with mode 0700");
    }
    return fd;
}

ControlServer::ControlServer(const std::string &path)
        : directory_(open_directory(path)),
          socket_(socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)),
          name_(std::filesystem::path(path).filename().string())
{
    if (name_.empty() || name_ == "." || name_ == ".." || socket_.get() < 0)
        throw std::runtime_error("Cannot create control socket");
    // 通过已验证目录 FD 的 proc 引用绑定，避免验证目录后又按原路径解析到另一处。
    const auto address = unix_address("/proc/self/fd/" + std::to_string(directory_.get()) + "/" + name_);
    if (bind(socket_.get(), reinterpret_cast<const sockaddr *>(&address), sizeof(address)))
        throw std::runtime_error("Cannot bind control socket (existing sockets are not removed)");
    // Do all remaining fallible setup with cleanup: a throwing constructor has no destructor.
    if (fchmodat(directory_.get(), name_.c_str(), 0600, 0) || listen(socket_.get(), 8)) {
        unlinkat(directory_.get(), name_.c_str(), 0);
        throw std::runtime_error("Cannot configure control socket");
    }
    bound_ = true;
}

ControlServer::~ControlServer() { if (bound_) unlinkat(directory_.get(), name_.c_str(), 0); }

void ControlServer::dispatch(const std::function<management::Reply(ControlCommand)> &handler)
{
    if (pending_.get() < 0) {
        OwnedFd accepted(accept4(socket_.get(), nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC));
        if (accepted.get() < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return;
            throw std::runtime_error("Control accept failed");
        }
        if (!root_peer(accepted.get())) return;
        pending_ = std::move(accepted);
        expires_ = std::chrono::steady_clock::now() + std::chrono::milliseconds(100);
    }
    // 管理客户端可能只 connect 而不发送。保留有限状态并立即返回，避免原先 poll(100ms) 挡住裁决截止时间。
    pollfd request{pending_.get(), POLLIN, 0};
    const int ready = poll(&request, 1, 0);
    if (ready < 0 && errno == EINTR) return;
    if (ready <= 0) {
        if (ready < 0 || std::chrono::steady_clock::now() >= expires_) pending_ = OwnedFd();
        return;
    }
    OwnedFd client(std::move(pending_));
    if (!(request.revents & POLLIN)) return;
    char message[16]{};
    ssize_t count;
    try { count = receive_message(client.get(), message, sizeof(message)); }
    catch (const std::exception &) { return; } // 单个异常连接不能终止监控服务。
    const std::string_view text(message, static_cast<std::size_t>(count));
    std::optional<ControlCommand> command;
    const bool v1 = text == "stop-v1" || text == "reload-v1" || text == "status-v1";
    const bool v2 = text == "stop-v2" || text == "reload-v2" || text == "status-v2";
    const bool structured = v1 || v2;
    if (text == "stop" || text == "stop-v1" || text == "stop-v2") command = ControlCommand::stop;
    if (text == "reload" || text == "reload-v1" || text == "reload-v2") command = ControlCommand::reload;
    if (text == "status-v1" || text == "status-v2") command = ControlCommand::status;
    if (!command) return;
    try {
        auto reply = handler(*command);
        reply.command = *command;
        management::validate_reply(reply, *command);
        if (structured) {
            if (v1) { reply.abi = 1; reply.size = 200; }
            send(client.get(), &reply, reply.size, MSG_NOSIGNAL | MSG_DONTWAIT);
        }
        else if (reply.code == management::Code::ok) send(client.get(), "ok", 2, MSG_NOSIGNAL);
        else send(client.get(), "error", 5, MSG_NOSIGNAL);
    } catch (const std::exception &) {
        // 未预期的服务内部异常不能伪装成成功；结构化客户端会拒绝这个非协议响应。
        send(client.get(), "error", 5, MSG_NOSIGNAL);
    }
}

static void request_command(const std::string &path, const char *command)
{
    if (geteuid() != 0) throw std::runtime_error("Control command requires root");
    OwnedFd connection(socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
    const auto address = unix_address(path);
    if (connection.get() < 0 ||
        connect(connection.get(), reinterpret_cast<const sockaddr *>(&address), sizeof(address)) ||
        !root_peer(connection.get())) throw std::runtime_error("Cannot connect to root control service");
    if (send(connection.get(), command, std::strlen(command), MSG_NOSIGNAL) != static_cast<ssize_t>(std::strlen(command)))
        throw std::runtime_error("Cannot send control request");
    pollfd response{connection.get(), POLLIN, 0};
    char result[8]{};
    if (poll(&response, 1, 3000) <= 0 || recv(connection.get(), result, sizeof(result), 0) != 2 ||
        std::memcmp(result, "ok", 2)) throw std::runtime_error("Control request rejected or not acknowledged");
}

void request_stop(const std::string &path) { request_command(path, "stop"); }
static management::Reply query(const std::string &path, management::Command command)
{
    if (geteuid() != 0) throw std::runtime_error("Control command requires root");
    OwnedFd connection(socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
    const auto address = unix_address(path);
    if (connection.get() < 0 || connect(connection.get(), reinterpret_cast<const sockaddr *>(&address), sizeof(address)) ||
        !root_peer(connection.get())) throw std::runtime_error("Cannot connect to root control service");
    const std::string message = std::string(management::command_name(command)) + "-v2";
    if (send(connection.get(), message.data(), message.size(), MSG_NOSIGNAL) != static_cast<ssize_t>(message.size()))
        throw std::runtime_error("Cannot send management request");
    pollfd incoming{connection.get(), POLLIN, 0};
    if (poll(&incoming, 1, 3000) <= 0) throw std::runtime_error("Management response deadline exceeded");
    management::Reply reply;
    if (receive_message(connection.get(), &reply, sizeof(reply)) != sizeof(reply))
        throw std::runtime_error("Unexpected management response size");
    management::validate_reply(reply, command);
    ucred peer{};
    socklen_t size = sizeof(peer);
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
