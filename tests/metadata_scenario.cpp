// SPDX-License-Identifier: MIT
// Hold FDs across policy changes. Every command executes in this same process;
// no helper exec can accidentally substitute its identity for the requester.
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/aio_abi.h>
#include <sys/syscall.h>
#include <sys/sendfile.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/xattr.h>
#include <termios.h>
#include <unistd.h>
namespace {
std::array<int, 3> files, direct_files;
aio_context_t aio = 0;
void *aio_buffer = nullptr;
// Linux POSIX ACL xattr v2, with a named uid to avoid trivial-mode folding.
const unsigned char acl[] = {
    2,0,0,0, 1,0,6,0,255,255,255,255, 2,0,4,0,254,255,0,0,
    4,0,4,0,255,255,255,255, 16,0,4,0,255,255,255,255, 32,0,0,0,255,255,255,255
};
int action(char op, unsigned index)
{
    if (index >= files.size()) return EINVAL;
    const int fd = files[index];
    long flags = 0;
    fsxattr attributes{};
    switch (op) {
    case 'x': return fsetxattr(fd, "user.secmon", "changed", 7, 0) ? errno : 0;
    case 'd': return fremovexattr(fd, "user.secmon") ? errno : 0;
    case 'a': return fsetxattr(fd, "system.posix_acl_access", acl, sizeof(acl), 0) ? errno : 0;
    case 'r': return fremovexattr(fd, "system.posix_acl_access") ? errno : 0;
    case 'z': {
        termios terminal{};
        return ioctl(fd, TCGETS, &terminal) ? errno : 0;
    }
    case 'g': return ioctl(fd, FS_IOC_GETFLAGS, &flags) ? errno : 0;
    case 'h': return ioctl(fd, FS_IOC_FSGETXATTR, &attributes) ? errno : 0;
    case 'i':
        if (ioctl(fd, FS_IOC_GETFLAGS, &flags)) return errno;
        flags ^= FS_NODUMP_FL;
        return ioctl(fd, FS_IOC_SETFLAGS, &flags) ? errno : 0;
    case 's':
        if (ioctl(fd, FS_IOC_FSGETXATTR, &attributes)) return errno;
        attributes.fsx_xflags ^= FS_XFLAG_NODUMP;
        return ioctl(fd, FS_IOC_FSSETXATTR, &attributes) ? errno : 0;
    case 'c': return ioctl(fd, FICLONE, files[2]) ? errno : 0;
    case 'l': {
        file_clone_range range{};
        range.src_fd = files[2]; range.src_length = 4096;
        return ioctl(fd, FICLONERANGE, &range) ? errno : 0;
    }
    case 'e': {
        // The ioctl is issued on the source: destination lives in the vector.
        alignas(file_dedupe_range) unsigned char storage[sizeof(file_dedupe_range) + sizeof(file_dedupe_range_info)]{};
        auto *range = reinterpret_cast<file_dedupe_range *>(storage);
        range->src_length = 4096; range->dest_count = 1;
        range->info[0].dest_fd = fd;
        if (ioctl(files[2], FIDEDUPERANGE, range)) return errno;
        return range->info[0].status < 0 ? -range->info[0].status : 0;
    }
    case 'w': return pwrite(fd, "W", 1, 0) == 1 ? 0 : errno;
    case 'v': {
        char byte = 'V'; iovec vector{&byte, 1};
        return pwritev(fd, &vector, 1, 0) == 1 ? 0 : errno;
    }
    case 'f': return fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, 4096) ? errno : 0;
    case 'b': {
        off_t source = 0, destination = 0;
        return copy_file_range(files[2], &source, fd, &destination, 4096, 0) == 4096 ? 0 : errno;
    }
    case 'n': {
        iocb request{};
        request.aio_lio_opcode = IOCB_CMD_PWRITE;
        request.aio_fildes = direct_files[index];
        request.aio_buf = reinterpret_cast<unsigned long>(aio_buffer);
        request.aio_nbytes = 4096;
        iocb *requests[] = {&request};
        if (syscall(SYS_io_submit, aio, 1, requests) < 0) return errno;
        io_event event{}; timespec timeout{2, 0};
        if (syscall(SYS_io_getevents, aio, 1, 1, &event, &timeout) != 1) return ETIMEDOUT;
        return event.res < 0 ? -event.res : event.res == 4096 ? 0 : EIO;
    }
    case 't': {
        off_t source = 0;
        if (lseek(fd, 0, SEEK_SET) < 0) return errno;
        return sendfile(fd, files[2], &source, 4096) == 4096 ? 0 : errno;
    }
    case 'p': {
        int pipe_fds[2];
        if (pipe2(pipe_fds, O_CLOEXEC)) return errno;
        int error = 0; char content[4096]{};
        if (write(pipe_fds[1], content, sizeof(content)) != sizeof(content)) error = errno;
        off_t destination = 0;
        if (!error && splice(pipe_fds[0], nullptr, fd, &destination, 4096, 0) != 4096) error = errno;
        close(pipe_fds[0]); close(pipe_fds[1]); return error;
    }
    case 'u': return ioctl(fd, 0xdeadbeefUL, 0) ? errno : 0;
    default: return EINVAL;
    }
}
}
int main(int argc, char **argv)
{
    if (argc != 4) return EINVAL;
    for (unsigned i = 0; i < files.size(); ++i) {
        files[i] = open(argv[i + 1], O_RDWR | O_CLOEXEC);
        if (files[i] < 0) return errno;
        direct_files[i] = open(argv[i + 1], O_RDWR | O_DIRECT | O_CLOEXEC);
        if (direct_files[i] < 0) return errno;
    }
    if (posix_memalign(&aio_buffer, 4096, 4096)) return ENOMEM;
    memset(aio_buffer, 'A', 4096);
    if (syscall(SYS_io_setup, 8, &aio)) return errno;
    puts("ready"); fflush(stdout);
    char *line = nullptr; size_t length = 0;
    while (getline(&line, &length, stdin) > 0) {
        if (line[0] == 'q') break;
        printf("%d\n", action(line[0], line[1] >= '0' && line[1] <= '2' ? line[1] - '0' : 0));
        fflush(stdout);
    }
    free(line);
    syscall(SYS_io_destroy, aio); free(aio_buffer);
    for (int fd : files) close(fd);
    for (int fd : direct_files) close(fd);
}
