// SPDX-License-Identifier: MIT
// Cooperative actor; inherited target FD survives exec, while caller thread identities can change.
#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <iostream>
#include <string>
#include <thread>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
namespace {
std::string executable, target, held_text;
int held;
long tid() { return syscall(SYS_gettid); }
bool command(std::string &line)
{
    line.clear();
    char value;
    while (line.size() < 64) {
        ssize_t count;
        do { count = read(STDIN_FILENO, &value, 1); } while (count < 0 && errno == EINTR);
        if (count != 1) return false;
        if (value == '\n') return true;
        line += value;
    }
    return false;
}
unsigned long long inode()
{
    const int pidfd = static_cast<int>(syscall(SYS_pidfd_open, getpid(), 0));
    struct stat metadata{};
    if (pidfd < 0 || fstat(pidfd, &metadata)) std::exit(3);
    close(pidfd);
    return metadata.st_ino;
}
void emit(const char *phase, int result = 0)
{
    std::cout << "{\"phase\":\"" << phase << "\",\"pid\":" << getpid() << ",\"tid\":" << tid()
              << ",\"process_inode\":" << inode() << ",\"errno\":" << result << "}" << std::endl;
}
void probe()
{
    const int fd = open(target.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) std::exit(4);
    char byte;
    if (read(fd, &byte, 1) != 1 || byte != 's') std::exit(5);
    close(fd);
    const int result = pwrite(held, "X", 1, 0) == 1 ? 0 : errno;
    emit("probe", result);
}
[[noreturn]] void exec_hold()
{
    execl(executable.c_str(), executable.c_str(), target.c_str(), held_text.c_str(), nullptr);
    std::exit(6);
}
[[noreturn]] void serve()
{
    std::string line;
    while (command(line)) {
        if (line == "probe") probe();
        else if (line == "thread-probe") { std::thread worker(probe); worker.join(); }
        else if (line == "exec-leader") exec_hold();
        else if (line == "exec-worker") { std::thread worker(exec_hold); worker.join(); std::exit(7); }
        else if (line == "leader-exit") {
            std::thread worker([] { emit("worker_ready"); serve(); });
            worker.detach();
            pthread_exit(nullptr);
        }
        else if (line == "exit") std::exit(0);
        else std::exit(8);
    }
    std::exit(0);
}
}
int main(int argc, char **argv)
{
    if (argc != 3) return 2;
    executable = argv[0]; target = argv[1]; held_text = argv[2];
    held = std::stoi(held_text);
    if (fcntl(held, F_GETFD) < 0) return 3;
    emit("ready");
    serve();
}
