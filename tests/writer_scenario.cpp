// SPDX-License-Identifier: MIT
// 专用原生程序：让真实 mm->exe_file 保持可控，避免把 Python/解释器本身加入授权列表。
// 返回 13 表示内核 EACCES；fork 保留程序，exec 切换程序，setuid 只改变授权 UID 维度。
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int write_file(const char *path)
{
    const int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return errno;
    const int result = pwrite(fd, "W", 1, 0) == 1 ? 0 : errno;
    close(fd);
    return result;
}
int main(int argc, char **argv)
{
    if (argc < 3) return 2;
    if (!std::strcmp(argv[1], "serve")) {
        // 在启用策略前保留写 FD；同一进程不 exec，以排除“重启后碰巧换身份”的假阳性。
        const int held = open(argv[2], O_RDWR | O_CLOEXEC);
        if (held < 0) return errno;
        if (argc == 4 && (setgid(65534) || setuid(static_cast<uid_t>(std::strtoul(argv[3], nullptr, 10))))) {
            close(held);
            return errno;
        }
        std::puts("ready");
        std::fflush(stdout);
        char line[16];
        while (std::fgets(line, sizeof(line), stdin)) {
            if (line[0] == 'q') break;
            int result = EINVAL;
            if (line[0] == 'w') result = pwrite(held, "W", 1, 0) == 1 ? 0 : errno;
            if (line[0] == 'o') result = write_file(argv[2]);
            if (line[0] == 'r') {
                const int fd = open(argv[2], O_RDONLY | O_CLOEXEC);
                if (fd < 0) result = errno;
                else { char byte; result = read(fd, &byte, 1) == 1 ? 0 : errno; close(fd); }
            }
            if (line[0] == 'h') {
                char byte;
                const auto count = pread(held, &byte, 1, 0);
                result = count == 1 ? 0 : count < 0 ? errno : EIO;
            }
            if (line[0] == 'a' || line[0] == 'b') {
                void *mapped = mmap(nullptr, 4096, line[0] == 'a' ? PROT_READ : PROT_NONE, MAP_PRIVATE, held, 0);
                result = mapped == MAP_FAILED ? errno : 0;
                if (mapped != MAP_FAILED) {
                    if (line[0] == 'b') result = mprotect(mapped, 4096, PROT_READ) ? errno : 0;
                    munmap(mapped, 4096);
                }
            }
            if (line[0] == 'u') result = unlink(argv[2]) ? errno : 0;
            if (line[0] == 'n' || line[0] == 'l') {
                char destination[4096];
                std::snprintf(destination, sizeof(destination), "%s.alias", argv[2]);
                result = (line[0] == 'n' ? rename(argv[2], destination) : link(argv[2], destination)) ? errno : 0;
            }
            if (line[0] == 't') result = ftruncate(held, 4) ? errno : 0;
            if (line[0] == 'm' || line[0] == 'p' || line[0] == 'v') {
                const int protection = line[0] == 'p' ? PROT_READ : PROT_READ | PROT_WRITE;
                void *mapped = mmap(nullptr, 4096, protection, line[0] == 'v' ? MAP_PRIVATE : MAP_SHARED, held, 0);
                result = mapped == MAP_FAILED ? errno : 0;
                if (mapped != MAP_FAILED) {
                    if (line[0] == 'p') result = mprotect(mapped, 4096, PROT_READ | PROT_WRITE) ? errno : 0;
                    munmap(mapped, 4096);
                }
            }
            std::printf("%d\n", result);
            if (std::fflush(stdout)) { close(held); return 3; }
        }
        close(held);
        return 0;
    }
    if (!std::strcmp(argv[1], "read")) {
        const int fd = open(argv[2], O_RDONLY | O_CLOEXEC);
        if (fd < 0) return errno;
        char byte;
        const auto count = read(fd, &byte, 1);
        const int result = count == 1 ? 0 : count < 0 ? errno : EIO;
        close(fd);
        return result;
    }
    if (!std::strcmp(argv[1], "write")) return write_file(argv[2]);
    if (!std::strcmp(argv[1], "open-write")) {
        const int fd = open(argv[2], O_WRONLY | O_CLOEXEC);
        if (fd < 0) return errno;
        close(fd);
        return 0;
    }
    if (!std::strcmp(argv[1], "uid-write") && argc == 4) {
        if (setgid(65534) || setuid(static_cast<uid_t>(std::strtoul(argv[3], nullptr, 10)))) return errno;
        return write_file(argv[2]);
    }
    if (!std::strcmp(argv[1], "fork-write")) {
        const auto pid = fork();
        if (pid < 0) return errno;
        if (!pid) _exit(write_file(argv[2]));
        int status = 0;
        if (waitpid(pid, &status, 0) != pid) return errno;
        return WIFEXITED(status) ? WEXITSTATUS(status) : 3;
    }
    if (!std::strcmp(argv[1], "exec-write") && argc == 4) {
        execl(argv[3], argv[3], "write", argv[2], nullptr);
        return errno;
    }
    if (!std::strcmp(argv[1], "chmod")) return chmod(argv[2], 0600) ? errno : 0;
    if (!std::strcmp(argv[1], "unlink")) return unlink(argv[2]) ? errno : 0;
    if (!std::strcmp(argv[1], "rename") && argc == 4) return rename(argv[2], argv[3]) ? errno : 0;
    if (!std::strcmp(argv[1], "link") && argc == 4) return link(argv[2], argv[3]) ? errno : 0;
    if (!std::strcmp(argv[1], "utime")) return utimensat(AT_FDCWD, argv[2], nullptr, 0) ? errno : 0;
    if (!std::strcmp(argv[1], "truncate")) return truncate(argv[2], 0) ? errno : 0;
    if (!std::strcmp(argv[1], "mmap")) {
        int fd = open(argv[2], O_RDWR | O_CLOEXEC);
        if (fd < 0) return errno;
        void *mapped = mmap(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        const int result = mapped == MAP_FAILED ? errno : 0;
        if (mapped != MAP_FAILED) munmap(mapped, 4096);
        close(fd);
        return result;
    }
    return 2;
}
