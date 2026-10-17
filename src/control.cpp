// SPDX-License-Identifier: MIT
// 管理 socket 用目录 FD 锚定创建与清理位置；不删除不明来源的已有 socket。
// 命令处理在宿主事件循环内串行完成，回调成功后才确认；客户端超时不保证服务没有执行命令。
#include <cerrno>
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
} // namespace

int ControlServer::open_directory(const std::string &path)
{
    if (geteuid() != 0 || !std::filesystem::path(path).is_absolute())
        throw std::runtime_error("Self protection requires root and an absolute control socket path");
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

void ControlServer::dispatch(const std::function<void(ControlCommand)> &handler)
{
    OwnedFd client(accept4(socket_.get(), nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC));
    if (client.get() < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return;
        throw std::runtime_error("Control accept failed");
    }
    if (!root_peer(client.get())) return;
    pollfd request{client.get(), POLLIN, 0};
    if (poll(&request, 1, 100) <= 0) return;
    char message[16]{};
    // SEQPACKET 保留消息边界；MSG_TRUNC 让超长报文按原长度被拒绝，不把被截断前缀误认成有效命令。
    const auto count = recv(client.get(), message, sizeof(message), MSG_DONTWAIT | MSG_TRUNC);
    ControlCommand command = ControlCommand::none;
    if (count == 4 && !std::memcmp(message, "stop", 4)) command = ControlCommand::stop;
    if (count == 6 && !std::memcmp(message, "reload", 6)) command = ControlCommand::reload;
    if (command == ControlCommand::none) return;
    try {
        // 处理成功才发 ok；若重载准备失败，调用方抛异常，服务发 error 且继续运行。
        handler(command);
        send(client.get(), "ok", 2, MSG_NOSIGNAL);
    } catch (const std::exception &) {
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
void request_reload(const std::string &path) { request_command(path, "reload"); }
