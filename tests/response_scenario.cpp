// SPDX-License-Identifier: MIT
// Two pre-existing threads and two held regular-file FDs. Commands may run on
// either thread; after L the original group leader exits while the worker lives.
#include <cerrno>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
namespace {
int trap_fd, victim_fd;
const char *victim_path, *trap_path;
bool late_mode = false;
std::mutex mutex;
std::condition_variable cv;
char pending = 0;
int result = 0;
bool done = false, leader_gone = false, quit = false;
void *mapping = MAP_FAILED;
int action(char command)
{
    if (command == 'c') {
        if (!late_mode) return pwrite(trap_fd, "C", 1, 0) == 1 ? 0 : errno;
        const int fd = open(trap_path, O_WRONLY | O_CLOEXEC);
        if (fd < 0) return errno;
        const int error = pwrite(fd, "C", 1, 0) == 1 ? 0 : errno;
        close(fd); return error;
    }
    if (command == 'i') return getpid();
    if (command == 's') {
        for (int i = 0; i < 10000; ++i)
            if (pwrite(victim_fd, "V", 1, 0) != -1 || errno != EACCES) return EIO;
        return 0;
    }
    if (command == 'w') return pwrite(victim_fd, "V", 1, 0) == 1 ? 0 : errno;
    if (command == 'r' || command == 'h') {
        char byte;
        return pread(command == 'r' ? trap_fd : victim_fd, &byte, 1, 0) == 1 ? 0 : errno;
    }
    if (command == 'o') {
        const int fd = open(victim_path, O_WRONLY | O_CLOEXEC);
        if (fd < 0) return errno;
        close(fd); return 0;
    }
    if (command == 't') return ftruncate(victim_fd, 8192) ? errno : 0;
    if (command == 'm' || command == 'a') {
        void *address = mmap(nullptr, 4096, PROT_READ | PROT_WRITE,
                            command == 'm' ? MAP_SHARED : MAP_PRIVATE, victim_fd, 0);
        if (address == MAP_FAILED) return errno;
        munmap(address, 4096); return 0;
    }
    if (command == 'b') {
        mapping = mmap(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, victim_fd, 0);
        return mapping == MAP_FAILED ? errno : 0;
    }
    if (command == 'd' && mapping != MAP_FAILED) {
        *static_cast<volatile char *>(mapping) = 'M'; return 0;
    }
    if (command == 'f') {
        const auto pid = fork();
        if (pid < 0) return errno;
        if (!pid) _exit(0);
        int status;
        return waitpid(pid, &status, 0) == pid && WIFEXITED(status) ? WEXITSTATUS(status) : ECHILD;
    }
    if (command == 'j') {
        pthread_t thread;
        const int error = pthread_create(&thread, nullptr, [](void *) -> void * { return nullptr; }, nullptr);
        if (error) return error;
        return pthread_join(thread, nullptr);
    }
    if (command == 'x') { execl("/usr/bin/true", "true", nullptr); return errno; }
    return EINVAL;
}
void reply(int value) { std::printf("%d\n", value); std::fflush(stdout); }
void command_loop(bool worker)
{
    char line[32];
    while (std::fgets(line, sizeof(line), stdin)) {
        const char command = line[0];
        if (command == 'q') break;
        if (command == 'g' && !worker) {
            std::lock_guard<std::mutex> lock(mutex);
            done = false; pending = 'o'; cv.notify_one(); reply(0); continue;
        }
        if (command == 'v' && !worker) {
            std::unique_lock<std::mutex> lock(mutex);
            cv.wait(lock, [] { return done; }); reply(result); continue;
        }
        if (command == 'k' && !worker) {
            std::unique_lock<std::mutex> lock(mutex);
            done = false; pending = 'c'; cv.notify_one();
            lock.unlock(); const int main_result = action('c'); lock.lock();
            cv.wait(lock, [] { return done; });
            reply(result == EACCES && main_result == EACCES ? EACCES : EIO);
            continue;
        }
        if (command == 'L' && !worker) {
            { std::lock_guard<std::mutex> lock(mutex); leader_gone = true; }
            reply(0); cv.notify_one(); pthread_exit(nullptr);
        }
        if (std::isupper(static_cast<unsigned char>(command)) && !worker) {
            std::unique_lock<std::mutex> lock(mutex);
            done = false; pending = std::tolower(static_cast<unsigned char>(command));
            cv.notify_one(); cv.wait(lock, [] { return done; }); reply(result);
        } else reply(action(std::tolower(static_cast<unsigned char>(command))));
    }
}
}
int main(int argc, char **argv)
{
    if (argc != 3 && argc != 4) return 2;
    late_mode = argc == 4 && !std::strcmp(argv[3], "late");
    trap_path = argv[1];
    trap_fd = open(argv[1], (late_mode ? O_RDONLY : O_RDWR) | O_CLOEXEC);
    victim_fd = open(argv[2], O_RDWR | O_CLOEXEC);
    victim_path = argv[2];
    if (trap_fd < 0 || victim_fd < 0) return errno;
    std::thread worker([] {
        std::unique_lock<std::mutex> lock(mutex);
        for (;;) {
            cv.wait(lock, [] { return pending || leader_gone || quit; });
            if (quit) return;
            if (leader_gone) { lock.unlock(); command_loop(true); _exit(0); }
            const char command = pending; pending = 0;
            lock.unlock(); const int value = action(command); lock.lock();
            result = value; done = true; cv.notify_one();
        }
    });
    // Detach allows the leader to exit independently, retaining the worker.
    worker.detach();
    std::puts("ready"); std::fflush(stdout);
    command_loop(false);
    { std::lock_guard<std::mutex> lock(mutex); quit = true; }
    cv.notify_one();
    _exit(0);
}
