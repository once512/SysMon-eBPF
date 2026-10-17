// SPDX-License-Identifier: MIT
// 产生受控 exec、线程及文件操作，供真实 BPF 测试观测；场景成功/失败应与审计事件分开核对。
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <grp.h>
#include <string_view>
#include <thread>
#include <vector>
#include <unistd.h>

static void exec_true()
{
    execl("/usr/bin/true", "true", static_cast<char *>(nullptr));
    std::perror("exec true");
    _exit(1);
}
int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    const std::string_view mode(argv[1]);
    if (mode == "exec") exec_true();
    if (mode == "thread-exec") {
        std::thread worker(exec_true);
        worker.join();
        return 1;
    }
    if (mode == "threads") {
        for (int round = 0; round < 16; ++round) {
            std::vector<std::thread> workers;
            for (int i = 0; i < 8; ++i) workers.emplace_back([] {});
            for (auto &worker : workers) worker.join();
        }
        exec_true();
    }
    if (mode == "drop-exec") {
        // Only this short-lived test process drops its own privileges.
        if (geteuid() != 0) return 77;
        if (setgroups(0, nullptr) || setresgid(65534, 65534, 65534) ||
            setresuid(65534, 65534, 65534)) {
            std::perror("drop credentials");
            return 1;
        }
        exec_true();
    }
    std::fprintf(stderr, "Usage: secmon-scenarios exec|thread-exec|threads|drop-exec\n");
    return 2;
}
