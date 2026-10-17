// SPDX-License-Identifier: MIT
// 独立分析器在创建 fanotify mark 前完成降权并回复 Ready，避免业务请求进入后才发现后端无法启动。
// 宿主只传事件 FD，不传 fanotify group/BPF Map；启动、请求、故障和回收分别维护清晰的所有权。
#include "client.h"
#include "transport.h"
#include <cerrno>
#include <chrono>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdexcept>
#include <system_error>
#include <sys/socket.h>
#include <sys/wait.h>
#include <poll.h>
#include <sys/syscall.h>
#include <utility>
extern char **environ;

namespace {
// spawn 文件动作和 FD 一样有明确的释放 API；用对象封装，字符串分配等异常也会销毁动作表。
class SpawnActions {
    posix_spawn_file_actions_t actions_;
public:
    SpawnActions()
    {
        const int error = posix_spawn_file_actions_init(&actions_);
        if (error) throw std::system_error(error, std::generic_category(), "spawn actions init");
    }
    ~SpawnActions() { posix_spawn_file_actions_destroy(&actions_); }
    SpawnActions(const SpawnActions &) = delete;
    SpawnActions &operator=(const SpawnActions &) = delete;
    posix_spawn_file_actions_t *get() { return &actions_; }
};
} // namespace

AnalysisClient::AnalysisClient(const AnalyzerConfig &config)
{
    scan_limit_ = config.scan_limit;
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, pair))
        throw std::system_error(errno, std::generic_category(), "analysis socketpair");
    channel_ = OwnedFd(pair[0]);
    OwnedFd worker(pair[1]);
    {
        SpawnActions actions;
        int error = 0;
        // 保留第一个系统调用错误，动作表由作用域对象统一清理。
        auto action = [&](int result) { if (!error) error = result; };
        // 子进程只保留约定的 IPC FD 3；关闭其余高位 FD，不能让降权进程继承 group/Map/控制 socket 权限。
        action(posix_spawn_file_actions_adddup2(actions.get(), worker.get(), 3));
        action(posix_spawn_file_actions_addclosefrom_np(actions.get(), 4));
        action(posix_spawn_file_actions_addopen(actions.get(), 0, "/dev/null", O_RDONLY, 0));
        action(posix_spawn_file_actions_addopen(actions.get(), 1, "/dev/null", O_WRONLY, 0));
        const auto limit = std::to_string(config.scan_limit);
        const auto parent = std::to_string(getpid());
        char *arguments[] = {const_cast<char *>(config.executable.c_str()), const_cast<char *>("--fd"),
            const_cast<char *>("3"), const_cast<char *>("--deny-marker"),
            const_cast<char *>(config.marker.c_str()), const_cast<char *>("--scan-limit-bytes"),
            const_cast<char *>(limit.c_str()), const_cast<char *>("--parent-pid"),
            const_cast<char *>(parent.c_str()), nullptr};
        if (!error) error = posix_spawn(&pid_, config.executable.c_str(), actions.get(), nullptr, arguments, environ);
        if (error) { pid_ = -1; throw std::system_error(error, std::generic_category(), "spawn analysis worker"); }
    }
    try {
        process_ = OwnedFd(static_cast<int>(syscall(SYS_pidfd_open, pid_, 0)));
        if (process_.get() < 0) throw std::system_error(errno, std::generic_category(), "analysis pidfd_open");
        // 启动握手有 1 秒期限，校验 Ready 必须无 FD、id=0，确认降权完成后才允许宿主建立 mark。
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
        while (true) {
            analysis::Response ready;
            auto packet = analysis::receive_packet(channel_.get(), &ready, sizeof(ready));
            if (packet.status != analysis::Io::would_block) {
                if (packet.status != analysis::Io::ready || packet.size != sizeof(ready) || !packet.fds.empty() ||
                    ready.magic_value != analysis::magic || ready.abi != analysis::version ||
                    ready.size != sizeof(ready) || ready.id || ready.result != analysis::Result::ready ||
                    ready.bytes_scanned || ready.error != analysis::ScanError::none || ready.system_errno)
                    throw std::runtime_error("Invalid analysis worker readiness handshake");
                break;
            }
            const auto now = std::chrono::steady_clock::now();
            if (now >= deadline) throw std::runtime_error("Analysis worker startup deadline exceeded");
            pollfd incoming{channel_.get(), POLLIN, 0};
            const int timeout = static_cast<int>(std::chrono::ceil<std::chrono::milliseconds>(deadline - now).count());
            if (poll(&incoming, 1, timeout) < 0 && errno != EINTR)
                throw std::system_error(errno, std::generic_category(), "analysis startup poll");
        }
    } catch (...) {
        // A throwing constructor has no destructor: terminate/reap explicitly.
        // 构造函数抛异常时对象析构函数不会执行，已启动的子进程必须在这里显式终止并尝试回收。
        stop();
        wait_for_exit();
        throw;
    }
}

void AnalysisClient::reap()
{
    if (pid_ < 0) return;
    int status;
    // WNOHANG 只回收已退出子进程，不让权限事件循环等待子进程结束；数字 PID 仅用于回收自己的子进程。
    const auto result = waitpid(pid_, &status, WNOHANG);
    if (result == pid_ || (result < 0 && errno == ECHILD)) pid_ = -1;
}

void AnalysisClient::stop()
{
    channel_ = OwnedFd();
    active_ = 0;
    // PID cannot be reused while our child has not been reaped.
    // 用 pidfd 发信号定位本次创建的进程对象，避免把复用后的同号进程误杀。
    if (process_.get() >= 0) syscall(SYS_pidfd_send_signal, process_.get(), SIGKILL, nullptr, 0);
    reap();
}
void AnalysisClient::wait_for_exit()
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(200);
    while (pid_ >= 0 && std::chrono::steady_clock::now() < deadline) {
        reap();
        if (pid_ >= 0) poll(nullptr, 0, 1);
    }
}
AnalysisClient::~AnalysisClient()
{
    stop();
    // Group closure precedes this bounded cleanup (see gate member ordering).
    wait_for_exit();
}

void AnalysisClient::submit(std::uint64_t id, int event_fd)
{
    if (!online() || active_ || !id) throw std::runtime_error("Analysis worker not ready for request");
    analysis::Request request;
    request.id = id;
    if (!analysis::send_packet(channel_.get(), &request, sizeof(request), event_fd))
        throw std::runtime_error("Analysis request channel full");
    active_ = id;
}
std::optional<analysis::Response> AnalysisClient::receive()
{
    if (!online()) { reap(); return std::nullopt; }
    analysis::Response response;
    auto packet = analysis::receive_packet(channel_.get(), &response, sizeof(response));
    if (packet.status == analysis::Io::would_block) return std::nullopt;
    if (packet.status == analysis::Io::closed) throw std::runtime_error("Analysis worker disconnected");
    // 把分析后端视作可能故障的协议对端：检查 ID、ABI、长度、结果和无附加 FD，迟到/重复回复均拒绝。
    if (packet.size != sizeof(response) || !packet.fds.empty() || !active_ || response.id != active_ ||
        response.magic_value != analysis::magic || response.abi != analysis::version ||
        response.size != sizeof(response) || response.bytes_scanned > scan_limit_ + 1 ||
        !analysis::valid_scan_error(response.error, response.system_errno) ||
        (response.result == analysis::Result::error ? response.error == analysis::ScanError::none : response.error != analysis::ScanError::none) ||
        (response.result != analysis::Result::allow && response.result != analysis::Result::deny &&
         response.result != analysis::Result::error))
        throw std::runtime_error("Invalid or stale analysis response");
    active_ = 0;
    return response;
}
