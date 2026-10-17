// SPDX-License-Identifier: MIT
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

bool ControlServer::stop_requested()
{
    OwnedFd client(accept4(socket_.get(), nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC));
    if (client.get() < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return false;
        throw std::runtime_error("Control accept failed");
    }
    if (!root_peer(client.get())) return false;
    pollfd request{client.get(), POLLIN, 0};
    if (poll(&request, 1, 100) <= 0) return false;
    char message[16]{};
    const auto count = recv(client.get(), message, sizeof(message), MSG_DONTWAIT | MSG_TRUNC);
    if (count != 4 || std::memcmp(message, "stop", 4)) return false;
    send(client.get(), "ok", 2, MSG_NOSIGNAL);
    return true;
}

void request_stop(const std::string &path)
{
    if (geteuid() != 0) throw std::runtime_error("Stop command requires root");
    OwnedFd connection(socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
    const auto address = unix_address(path);
    if (connection.get() < 0 ||
        connect(connection.get(), reinterpret_cast<const sockaddr *>(&address), sizeof(address)) ||
        !root_peer(connection.get())) throw std::runtime_error("Cannot connect to root control service");
    if (send(connection.get(), "stop", 4, MSG_NOSIGNAL) != 4)
        throw std::runtime_error("Cannot send stop request");
    pollfd response{connection.get(), POLLIN, 0};
    char result[8]{};
    if (poll(&response, 1, 3000) <= 0 || recv(connection.get(), result, sizeof(result), 0) != 2 ||
        std::memcmp(result, "ok", 2)) throw std::runtime_error("Stop request not acknowledged");
}
