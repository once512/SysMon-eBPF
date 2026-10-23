// SPDX-License-Identifier: MIT
// A stable requester, holding read-only synthetic and read-write real FDs.
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>
int main(int argc, char **argv)
{
    if (argc != 3) return 2;
    const std::string trap(argv[1]), victim(argv[2]), alias = trap + ".alias";
    const int source = open(trap.c_str(), O_RDONLY | O_CLOEXEC);
    const int output = open(victim.c_str(), O_RDWR | O_CLOEXEC);
    if (source < 0 || output < 0) return 3;
    std::puts("ready"); std::fflush(stdout);
    char line[32];
    while (std::fgets(line, sizeof(line), stdin) && line[0] != 'q') {
        int error = 0, result = 0;
        switch (line[0]) {
        case 'r': { char byte; result = pread(source, &byte, 1, 0) == 1 ? 0 : -1; break; }
        case 'w': result = pwrite(output, "V", 1, 0) == 1 ? 0 : -1; break;
        case 'c': { const int fd = open(trap.c_str(), O_WRONLY | O_CLOEXEC);
                    result = fd < 0 ? -1 : 0; if (fd >= 0) close(fd); break; }
        case 't': result = truncate(trap.c_str(), 0); break;
        case 'u': result = unlink(trap.c_str()); break;
        case 'n': result = rename(trap.c_str(), alias.c_str()); break;
        case 'l': result = link(trap.c_str(), alias.c_str()); break;
        case 'a': result = setxattr(trap.c_str(), "user.test", "X", 1, 0); break;
        case 'd': result = removexattr(trap.c_str(), "user.test"); break;
        case 'm': result = chmod(trap.c_str(), 0600); break;
        case 'i': result = ioctl(source, 0xdeadbeefU, nullptr); break;
        case 'k': { unsigned long flags = 0; result = ioctl(source, 0x40086602U, &flags); break; }
        case 's': { struct stat stat{}; result = fstat(source, &stat); break; }
        case 'f': { const pid_t child = fork();
                    if (child < 0) result = -1;
                    else if (!child) _exit(0);
                    else { int status; result = waitpid(child, &status, 0) == child && WIFEXITED(status) ? 0 : -1; }
                    break; }
        case 'x': execl("/usr/bin/true", "true", nullptr); result = -1; break;
        default: error = EINVAL;
        }
        if (result < 0) error = errno;
        std::printf("%d\n", error); std::fflush(stdout);
    }
    close(source); close(output);
    return 0;
}
