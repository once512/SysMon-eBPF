// SPDX-License-Identifier: MIT
#include "provider.h"
#include "protocol.h"
#include "analysis/transport.h"
#include <cerrno>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdexcept>
#include <system_error>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
extern char **environ;
DecoyProvider::DecoyProvider(const DecoyConfig &config) : files_(config.files.size()), mountpoint_(config.mountpoint)
{
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, pair))
        throw std::system_error(errno, std::generic_category(), "decoy provider socketpair");
    channel_ = OwnedFd(pair[0]); OwnedFd child(pair[1]);
    std::vector<std::string> arguments{config.executable, "--mountpoint", config.mountpoint,
        "--managed-fd", "3", "--parent-pid", std::to_string(getpid())};
    for (const auto &file : config.files) { arguments.emplace_back("--file"); arguments.push_back(file); }
    if (config.allow_other) arguments.emplace_back("--allow-other");
    std::vector<char *> argv;
    for (auto &argument : arguments) argv.push_back(argument.data());
    argv.push_back(nullptr);
    posix_spawn_file_actions_t actions;
    int error = posix_spawn_file_actions_init(&actions);
    if (error) throw std::system_error(error, std::generic_category(), "decoy spawn actions");
    auto action = [&](int result) { if (!error) error = result; };
    action(posix_spawn_file_actions_adddup2(&actions, child.get(), 3));
    action(posix_spawn_file_actions_addclosefrom_np(&actions, 4));
    action(posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0));
    action(posix_spawn_file_actions_addopen(&actions, 1, "/dev/null", O_WRONLY, 0));
    action(posix_spawn_file_actions_addopen(&actions, 2, "/dev/null", O_WRONLY, 0));
    if (!error) error = posix_spawn(&pid_, config.executable.c_str(), &actions, nullptr, argv.data(), environ);
    posix_spawn_file_actions_destroy(&actions);
    if (error) { pid_ = -1; throw std::system_error(error, std::generic_category(), "spawn decoy provider"); }
    child = OwnedFd();
    try {
        process_ = OwnedFd(static_cast<int>(syscall(SYS_pidfd_open, pid_, 0)));
        if (process_.get() < 0) throw std::system_error(errno, std::generic_category(), "decoy pidfd_open");
        const auto deadline = Clock::now() + std::chrono::seconds(2);
        for (;;) {
            decoy::Frame ready;
            const auto packet = analysis::receive_plain_packet(channel_.get(), &ready, sizeof(ready));
            if (packet.status == analysis::Io::closed)
                throw std::runtime_error("Decoy provider exited before readiness; check mountpoint and FUSE access");
            if (packet.status != analysis::Io::would_block) {
                if (packet.status != analysis::Io::ready || packet.size != sizeof(ready) ||
                    !decoy::valid(ready, decoy::Kind::ready) || ready.sequence)
                    throw std::runtime_error("Invalid decoy provider readiness");
                mount_id_ = ready.mount_id;
                mount_ = decoy::inspect_mount(mount_id_, mountpoint_);
                mount_sample_ = Clock::now(); next_mount_sample_ = mount_sample_ + std::chrono::milliseconds(250);
                break;
            }
            const auto now = Clock::now();
            if (now >= deadline) throw std::runtime_error("Decoy provider startup timed out");
            pollfd input{channel_.get(), POLLIN, 0};
            const int wait = std::chrono::ceil<std::chrono::milliseconds>(deadline - now).count();
            if (poll(&input, 1, wait) < 0 && errno != EINTR)
                throw std::system_error(errno, std::generic_category(), "decoy startup poll");
        }
        progress_ = Clock::now(); next_probe_ = progress_ + std::chrono::milliseconds(250);
    } catch (...) { stop(); throw; }
}
void DecoyProvider::reap() noexcept
{
    if (pid_ < 0) return;
    int status;
    const auto result = waitpid(pid_, &status, WNOHANG);
    if (result == pid_ || (result < 0 && errno == ECHILD)) pid_ = -1;
}
void DecoyProvider::fail() noexcept
{
    if (error_ == management::ProviderError::none) error_ = management::ProviderError::transport;
    failed_ = true; pending_ = false; channel_ = OwnedFd();
    if (process_.get() >= 0) syscall(SYS_pidfd_send_signal, process_.get(), SIGKILL, nullptr, 0);
    else if (pid_ > 0) kill(pid_, SIGKILL); // Only our unreaped constructor child.
    reap();
}
void DecoyProvider::stop() noexcept
{
    channel_ = OwnedFd();
    if (process_.get() >= 0) syscall(SYS_pidfd_send_signal, process_.get(), SIGTERM, nullptr, 0);
    else if (pid_ > 0) kill(pid_, SIGTERM);
    const auto deadline = Clock::now() + std::chrono::milliseconds(200);
    while (pid_ > 0 && Clock::now() < deadline) { reap(); if (pid_ > 0) poll(nullptr, 0, 1); }
    if (pid_ > 0) fail();
    for (int attempt = 0; pid_ > 0 && attempt < 20; ++attempt) { reap(); if (pid_ > 0) poll(nullptr, 0, 1); }
}
DecoyProvider::~DecoyProvider() { stop(); }
void DecoyProvider::poll_once() noexcept
{
    if (Clock::now() >= next_mount_sample_) {
        mount_ = decoy::inspect_mount(mount_id_, mountpoint_);
        mount_sample_ = Clock::now(); next_mount_sample_ = mount_sample_ + std::chrono::milliseconds(250);
    }
    if (failed_) { reap(); return; }
    try {
        decoy::Frame frame;
        const auto packet = analysis::receive_plain_packet(channel_.get(), &frame, sizeof(frame));
        if (packet.status == analysis::Io::closed) {
            error_ = management::ProviderError::disconnected; fail(); return;
        }
        if (packet.status != analysis::Io::would_block) {
            if (packet.status != analysis::Io::ready || packet.size != sizeof(frame) ||
                !decoy::valid(frame, decoy::Kind::progress) || !pending_ || frame.sequence != sequence_)
                { error_ = management::ProviderError::protocol; fail(); return; }
            pending_ = false; progress_ = Clock::now(); next_probe_ = progress_ + std::chrono::milliseconds(250);
        }
        if (!pending_ && Clock::now() >= next_probe_) {
            if (!++sequence_) { error_ = management::ProviderError::sequence; fail(); return; }
            frame = {}; frame.kind = decoy::Kind::probe; frame.sequence = sequence_;
            if (analysis::send_packet(channel_.get(), &frame, sizeof(frame))) pending_ = true;
            else --sequence_; // No probe queued; retry without accumulating requests.
        }
    } catch (const std::system_error &) { error_ = management::ProviderError::transport; fail(); }
      catch (const std::runtime_error &) { error_ = management::ProviderError::protocol; fail(); }
      catch (...) { error_ = management::ProviderError::transport; fail(); }
}
void DecoyProvider::snapshot(management::Reply &reply) const
{
    reply.decoy_mount_id = mount_id_;
    reply.decoy_mount_state = mount_.state;
    reply.decoy_mount_errno = mount_.error;
    reply.decoy_mount_sample_age_ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - mount_sample_).count();
    reply.decoy_provider_error = error_;
    reply.decoy_provider_pid = pid_; reply.decoy_files = files_;
    reply.decoy_provider_progress_age_ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - progress_).count();
    reply.decoy_provider_state = failed_ ? management::ProviderState::offline :
        (reply.decoy_provider_progress_age_ms < management::reader_stall_ms ?
         management::ProviderState::responsive : management::ProviderState::unresponsive);
}
