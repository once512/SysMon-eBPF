// SPDX-License-Identifier: MIT
// Force pidfd_open failure after successful spawn; no privileged operations.
#include "analysis/client.h"
#include "decoy/provider.h"
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <spawn.h>
#include <stdexcept>
#include <system_error>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
namespace {
pid_t spawned = -1;
int sent_signal = 0;
}
extern "C" int __real_posix_spawn(pid_t *, const char *, const posix_spawn_file_actions_t *,
                                  const posix_spawnattr_t *, char *const [], char *const []);
extern "C" int __wrap_posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *actions,
                                  const posix_spawnattr_t *attributes, char *const arguments[], char *const environment[])
{
    const int error = __real_posix_spawn(pid, path, actions, attributes, arguments, environment);
    if (!error) spawned = *pid;
    return error;
}
extern "C" long __wrap_syscall(long number, ...)
{
    if (number != SYS_pidfd_open) std::abort();
    errno = EMFILE;
    return -1;
}
extern "C" int __real_kill(pid_t, int);
extern "C" int __wrap_kill(pid_t pid, int signal)
{
    if (pid != spawned || spawned <= 0) std::abort();
    sent_signal = signal;
    return __real_kill(pid, signal);
}
template<class Construct> void verify(Construct construct, int expected_signal)
{
    spawned = -1; sent_signal = 0;
    const auto started = std::chrono::steady_clock::now();
    bool rejected = false;
    try { construct(); }
    catch (const std::system_error &error) { rejected = error.code().value() == EMFILE; }
    int status;
    const auto result = spawned > 0 ? waitpid(spawned, &status, WNOHANG) : 0;
    const bool reaped = result < 0 && errno == ECHILD;
    if (result == 0 && spawned > 0) { __real_kill(spawned, SIGKILL); waitpid(spawned, &status, 0); }
    if (!rejected || !reaped || sent_signal != expected_signal ||
        std::chrono::steady_clock::now() - started > std::chrono::seconds(1))
        throw std::runtime_error("Spawned child was not terminated and reaped after pidfd allocation failure");
}
int main(int argc, char **argv)
{
    // The child deliberately never reads its socket, so closing the parent
    // endpoint alone cannot make it exit and satisfy this test accidentally.
    if (argc > 1) { for (;;) pause(); }
    try {
        verify([&] { AnalysisClient client({argv[0], "unused", 64}); }, SIGKILL);
        verify([&] { DecoyConfig config; config.executable = argv[0]; config.mountpoint = "/unused";
                      config.files = {"test"}; DecoyProvider provider(config); }, SIGTERM);
        std::cout << "PASS pidfd EMFILE after spawn terminates/reaps only the owned analysis/provider child\n";
    } catch (const std::exception &error) { std::cerr << error.what() << '\n'; return 1; }
}
