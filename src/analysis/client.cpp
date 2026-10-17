// SPDX-License-Identifier: MIT
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

AnalysisClient::AnalysisClient(const AnalyzerConfig &config)
{
    scan_limit_ = config.scan_limit;
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, pair))
        throw std::system_error(errno, std::generic_category(), "analysis socketpair");
    channel_ = OwnedFd(pair[0]);
    OwnedFd worker(pair[1]);
    posix_spawn_file_actions_t actions;
    int error = posix_spawn_file_actions_init(&actions);
    if (error) throw std::system_error(error, std::generic_category(), "spawn actions init");
    // Errors are accumulated; actions are destroyed even when setup fails.
    auto action = [&](int result) { if (!error) error = result; };
    action(posix_spawn_file_actions_adddup2(&actions, worker.get(), 3));
    action(posix_spawn_file_actions_addclosefrom_np(&actions, 4));
    action(posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0));
    action(posix_spawn_file_actions_addopen(&actions, 1, "/dev/null", O_WRONLY, 0));
    const auto limit = std::to_string(config.scan_limit);
    const auto parent = std::to_string(getpid());
    char *arguments[] = {const_cast<char *>(config.executable.c_str()), const_cast<char *>("--fd"),
        const_cast<char *>("3"), const_cast<char *>("--deny-marker"),
        const_cast<char *>(config.marker.c_str()), const_cast<char *>("--scan-limit-bytes"),
        const_cast<char *>(limit.c_str()), const_cast<char *>("--parent-pid"),
        const_cast<char *>(parent.c_str()), nullptr};
    if (!error) error = posix_spawn(&pid_, config.executable.c_str(), &actions, nullptr, arguments, environ);
    posix_spawn_file_actions_destroy(&actions);
    if (error) { pid_ = -1; throw std::system_error(error, std::generic_category(), "spawn analysis worker"); }
    try {
        process_ = OwnedFd(static_cast<int>(syscall(SYS_pidfd_open, pid_, 0)));
        if (process_.get() < 0) throw std::system_error(errno, std::generic_category(), "analysis pidfd_open");
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
        while (true) {
            analysis::Response ready;
            auto packet = analysis::receive_packet(channel_.get(), &ready, sizeof(ready));
            if (packet.status != analysis::Io::would_block) {
                if (packet.status != analysis::Io::ready || packet.size != sizeof(ready) || !packet.fds.empty() ||
                    ready.magic_value != analysis::magic || ready.abi != analysis::version ||
                    ready.size != sizeof(ready) || ready.id || ready.result != analysis::Result::ready ||
                    ready.bytes_scanned)
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
        stop();
        wait_for_exit();
        throw;
    }
}

void AnalysisClient::reap()
{
    if (pid_ < 0) return;
    int status;
    const auto result = waitpid(pid_, &status, WNOHANG);
    if (result == pid_ || (result < 0 && errno == ECHILD)) pid_ = -1;
}

void AnalysisClient::stop()
{
    channel_ = OwnedFd();
    active_ = 0;
    // PID cannot be reused while our child has not been reaped.
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
    if (packet.size != sizeof(response) || !packet.fds.empty() || !active_ || response.id != active_ ||
        response.magic_value != analysis::magic || response.abi != analysis::version ||
        response.size != sizeof(response) || response.bytes_scanned > scan_limit_ + 1 ||
        (response.result != analysis::Result::allow && response.result != analysis::Result::deny &&
         response.result != analysis::Result::error))
        throw std::runtime_error("Invalid or stale analysis response");
    active_ = 0;
    return response;
}
