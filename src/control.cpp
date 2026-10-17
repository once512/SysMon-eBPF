// SPDX-License-Identifier: MIT
// 管理服务端：用目录 FD 锚定 socket 生命周期，在宿主事件循环中无阻塞地推进一个待命令连接。
// 客户端见 control_client.cpp，共用的报文接收与身份校验见 management/channel.cpp。
#include "control.h"
#include "management/channel.h"
#include <cerrno>
#include <filesystem>
#include <optional>
#include <poll.h>
#include <stdexcept>
#include <string_view>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <utility>

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
    const auto address = management::channel::unix_address("/proc/self/fd/" + std::to_string(directory_.get()) + "/" + name_);
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
        if (!management::channel::root_peer(accepted.get())) return;
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
    // 命令开始处理时把连接从 pending 转为本次局部所有权；
    // 正常返回或异常都会关闭它，不阻塞下一连接。
    OwnedFd client(std::move(pending_));
    if (!(request.revents & POLLIN)) return;
    char message[16]{};
    ssize_t count;
    try { count = management::channel::receive_without_fds(client.get(), message, sizeof(message)); }
    catch (const std::exception &) { return; } // 单个异常连接不能终止监控服务。
    const std::string_view text(message, static_cast<std::size_t>(count));
    std::optional<ControlCommand> command;
    // 同包部署只识别一套命令，不协商历史版本；所有命令都返回当前完整结构。
    if (text == "stop") command = ControlCommand::stop;
    else if (text == "reload") command = ControlCommand::reload;
    else if (text == "status") command = ControlCommand::status;
    if (!command) return;
    try {
        // 回调与后端事件循环串行执行；
        // 回复发生在回调提交完成之后，但客户端断线不保证提交未发生。
        auto reply = handler(*command);
        reply.command = *command;
        management::validate_reply(reply, *command);
        send(client.get(), &reply, sizeof(reply), MSG_NOSIGNAL | MSG_DONTWAIT);
    } catch (const std::exception &) {
        // 非预期异常关闭连接，客户端报告传输/校验失败；不伪造成功，也不切回另一种响应格式。
    }
}
