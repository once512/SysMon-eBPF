// SPDX-License-Identifier: MIT
// 可交互的线程、凭证和 exec 场景发生器；由 Python 控制每个阶段，以便在任务存活时核验 Map。
// An interactive scenario: keep identities alive long enough to inspect the Map.
#include <cerrno>
#include <condition_variable>
#include <cstdio>
#include <iostream>
#include <grp.h>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <sys/syscall.h>
#include <unistd.h>

namespace {
long tid() { return syscall(SYS_gettid); }
void emit_hold()
{
    std::cout << "{\"phase\":\"exec_complete\",\"pid\":" << getpid()
              << ",\"tid\":" << tid() << "}" << std::endl;
}
[[noreturn]] void exec_hold(const char *executable, const char *phase)
{
    std::cout << "{\"phase\":\"" << phase << "\",\"pid\":" << getpid()
              << ",\"tid\":" << tid() << "}" << std::endl;
    execl(executable, executable, "hold", static_cast<char *>(nullptr));
    std::perror("exec lifecycle hold");
    _exit(1);
}
// 命令按原始输入逐字节读取，避免 iostream 预读后在 exec 时丢掉尚未处理的后续命令。
bool read_command(std::string &value)
{
    // Do not buffer future commands: exec would discard a userspace input buffer.
    value.clear();
    while (value.size() < 64) {
        char byte;
        ssize_t count;
        do { count = read(STDIN_FILENO, &byte, 1); } while (count < 0 && errno == EINTR);
        if (count != 1) return false;
        if (byte == '\n') return true;
        value += byte;
    }
    return false;
}
bool command(const char *expected)
{
    std::string value;
    return read_command(value) && value == expected;
}
}

int main(int argc, char **argv)
{
    if (argc == 2 && std::string(argv[1]) == "hold") {
        emit_hold();
        return command("exit") ? 0 : 2;
    }
    if (argc != 1) return 2;
    std::mutex mutex;
    std::condition_variable changed;
    bool release = false;
    std::vector<long> tids;
    std::vector<std::thread> workers;
    for (int i = 0; i < 4; ++i) {
        workers.emplace_back([&] {
            std::unique_lock<std::mutex> lock(mutex);
            tids.push_back(tid());
            changed.notify_all();
            changed.wait(lock, [&] { return release; });
        });
    }
    {
        std::unique_lock<std::mutex> lock(mutex);
        changed.wait(lock, [&] { return tids.size() == 4; });
        std::cout << "{\"phase\":\"threads_ready\",\"pid\":" << getpid() << ",\"tids\":[";
        for (std::size_t i = 0; i < tids.size(); ++i)
            std::cout << (i ? "," : "") << tids[i];
        std::cout << "]}" << std::endl;
    }
    const bool joined = command("join");
    {
        std::lock_guard<std::mutex> lock(mutex);
        release = true;
    }
    changed.notify_all();
    for (auto &worker : workers) worker.join();
    if (!joined) return 2;
    std::cout << "{\"phase\":\"threads_joined\",\"pid\":" << getpid() << "}" << std::endl;
    std::string next;
    if (!read_command(next)) return 2;
    if (next == "drop") {
        if (setgroups(0, nullptr) || setresgid(65534, 65534, 65534) ||
            setresuid(65534, 65534, 65534)) {
            std::perror("drop lifecycle credentials");
            return 1;
        }
        std::cout << "{\"phase\":\"credentials_dropped\",\"pid\":" << getpid()
                  << ",\"uid\":" << getuid() << ",\"euid\":" << geteuid() << "}" << std::endl;
        if (!command("exec")) return 2;
    } else if (next == "exec-leader") exec_hold(argv[0], "exec_leader");
    else if (next != "exec") return 2;
    std::thread executor([&] { exec_hold(argv[0], "exec_worker"); });
    executor.join();
    return 1;
}
