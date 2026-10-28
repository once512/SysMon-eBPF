// SPDX-License-Identifier: MIT
#include "service_notify.h"
#include <cerrno>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <system_error>
#include <sys/socket.h>
#include <sys/un.h>
ServiceNotify::ServiceNotify()
{
    const char *value = getenv("NOTIFY_SOCKET");
    if (!value) return;
    address_ = value;
    if (unsetenv("NOTIFY_SOCKET")) throw std::system_error(errno, std::generic_category(), "clear NOTIFY_SOCKET");
    if (address_.empty()) return;
    sockaddr_un target{};
    if ((address_.front() != '/' && address_.front() != '@') || address_.size() >= sizeof(target.sun_path) || address_.size() < 2)
        throw std::runtime_error("Invalid NOTIFY_SOCKET address");
    socket_ = OwnedFd(socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
    if (socket_.get() < 0) throw std::system_error(errno, std::generic_category(), "service notification socket");
}
bool ServiceNotify::send(std::string_view message) const noexcept
{
    if (socket_.get() < 0) return true;
    sockaddr_un target{}; target.sun_family = AF_UNIX;
    std::memcpy(target.sun_path, address_.data(), address_.size());
    const bool abstract = address_.front() == '@';
    if (abstract) target.sun_path[0] = '\0';
    const auto size = offsetof(sockaddr_un, sun_path) + address_.size() + (abstract ? 0 : 1);
    const auto count = sendto(socket_.get(), message.data(), message.size(), MSG_DONTWAIT | MSG_NOSIGNAL,
                              reinterpret_cast<const sockaddr *>(&target), size);
    if (count == static_cast<ssize_t>(message.size())) return true;
    if (count >= 0) errno = EIO;
    return false;
}
void ServiceNotify::ready() const
{
    if (!send("READY=1\nSTATUS=SecMon policy and control initialized\n"))
        throw std::system_error(errno, std::generic_category(), "send service readiness (initialization rolled back)");
}
bool ServiceNotify::stopping() const noexcept
{
    return send("STOPPING=1\nSTATUS=SecMon releasing policy resources\n");
}
