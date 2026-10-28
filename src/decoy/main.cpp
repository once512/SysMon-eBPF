// SPDX-License-Identifier: MIT
// Synthetic, immutable view only. Security decisions remain in secmon's inode
// policy; a FUSE request PID is deliberately never used to restrict a process.
#define FUSE_USE_VERSION 35
#include <fuse_lowlevel.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <exception>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>
#include <vector>
#include <charconv>
#include <poll.h>
#include <csignal>
#include <sys/prctl.h>
#include <sys/socket.h>
#include "config.h"
#include "protocol.h"
#include "mount_identity.h"
#include "owned_fd.h"

namespace {
constexpr size_t max_files = 64, file_size = 4096;
struct File { std::string name; std::array<char, file_size> bytes{}; };
struct View {
    std::vector<File> files;
    uid_t uid = getuid();
    gid_t gid = getgid();
    time_t created = time(nullptr);
    int managed_fd = -1;
    fuse_session *session = nullptr;
    bool ready = false, management_error = false;
    std::uint64_t mount_id = 0;
};
View &view(fuse_req_t req) { return *static_cast<View *>(fuse_req_userdata(req)); }
bool exists(View &v, fuse_ino_t ino) { return ino >= 1 && ino <= v.files.size() + 1; }
struct stat attributes(View &v, fuse_ino_t ino)
{
    struct stat result{};
    result.st_ino = ino;
    // Writable DAC permissions let mutation attempts reach LSM. Every mutation
    // is still rejected by this filesystem, even with no BPF policy attached.
    result.st_mode = ino == 1 ? S_IFDIR | 0777 : S_IFREG | 0666;
    result.st_nlink = ino == 1 ? 2 : 1;
    result.st_uid = v.uid; result.st_gid = v.gid;
    result.st_size = ino == 1 ? 0 : file_size;
    result.st_blksize = 4096;
    result.st_atime = result.st_mtime = result.st_ctime = v.created;
    return result;
}
void lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    auto &v = view(req);
    if (parent != 1) { fuse_reply_err(req, ENOTDIR); return; }
    for (size_t i = 0; i < v.files.size(); ++i) {
        if (v.files[i].name == name) {
            struct fuse_entry_param entry{};
            entry.ino = i + 2; entry.generation = 1;
            entry.attr = attributes(v, entry.ino);
            // No negative cache or inode recycling. The complete namespace and
            // bytes remain fixed until this connection is unmounted.
            fuse_reply_entry(req, &entry); return;
        }
    }
    fuse_reply_err(req, ENOENT);
}
void forget(fuse_req_t req, fuse_ino_t, uint64_t) { fuse_reply_none(req); }
void getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *)
{
    auto &v = view(req);
    if (!exists(v, ino)) { fuse_reply_err(req, ENOENT); return; }
    auto attr = attributes(v, ino);
    fuse_reply_attr(req, &attr, 0);
}
void open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    auto &v = view(req);
    if (!exists(v, ino)) { fuse_reply_err(req, ENOENT); return; }
    if (ino == 1) { fuse_reply_err(req, EISDIR); return; }
    if ((fi->flags & O_ACCMODE) != O_RDONLY || (fi->flags & O_TRUNC)) {
        fuse_reply_err(req, EACCES); return;
    }
    fi->fh = ino;
    fi->keep_cache = 1; // Immutable content, no read-time writes or backing FD.
    fuse_reply_open(req, fi);
}
void read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *)
{
    auto &v = view(req);
    if (!exists(v, ino) || ino == 1) { fuse_reply_err(req, EINVAL); return; }
    if (off < 0) { fuse_reply_err(req, EINVAL); return; }
    if (static_cast<uint64_t>(off) >= file_size) { fuse_reply_buf(req, nullptr, 0); return; }
    size = std::min(size, file_size - static_cast<size_t>(off));
    fuse_reply_buf(req, v.files[ino - 2].bytes.data() + off, size);
}
void opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    if (ino != 1) { fuse_reply_err(req, ENOTDIR); return; }
    fuse_reply_open(req, fi);
}
void readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *)
{
    if (ino != 1 || off < 0) { fuse_reply_err(req, EINVAL); return; }
    // Each Linux request is bounded; large user buffers cannot allocate in the
    // callback. Offsets are stable indices, including . and .. .
    std::array<char, 16384> buffer{};
    size = std::min(size, buffer.size());
    size_t used = 0;
    auto &v = view(req);
    for (size_t i = static_cast<size_t>(off); i < v.files.size() + 2; ++i) {
        const char *name = i == 0 ? "." : i == 1 ? ".." : v.files[i - 2].name.c_str();
        auto attr = attributes(v, i < 2 ? 1 : i);
        const size_t needed = fuse_add_direntry(req, buffer.data() + used, size - used, name, &attr, i + 1);
        if (needed > size - used) break;
        used += needed;
    }
    fuse_reply_buf(req, buffer.data(), used);
}
void release(fuse_req_t req, fuse_ino_t, struct fuse_file_info *) { fuse_reply_err(req, 0); }
void flush(fuse_req_t req, fuse_ino_t, struct fuse_file_info *) { fuse_reply_err(req, 0); }
void statfs(fuse_req_t req, fuse_ino_t)
{
    struct statvfs stat{};
    stat.f_bsize = stat.f_frsize = 4096;
    stat.f_files = view(req).files.size() + 1;
    stat.f_namemax = 255;
    fuse_reply_statfs(req, &stat);
}
void setattr(fuse_req_t req, fuse_ino_t, struct stat *, int, struct fuse_file_info *) { fuse_reply_err(req, EACCES); }
void write(fuse_req_t req, fuse_ino_t, const char *, size_t, off_t, struct fuse_file_info *) { fuse_reply_err(req, EACCES); }
void unlink(fuse_req_t req, fuse_ino_t, const char *) { fuse_reply_err(req, EACCES); }
void rename(fuse_req_t req, fuse_ino_t, const char *, fuse_ino_t, const char *, unsigned int) { fuse_reply_err(req, EACCES); }
void link(fuse_req_t req, fuse_ino_t, fuse_ino_t, const char *) { fuse_reply_err(req, EACCES); }
void create(fuse_req_t req, fuse_ino_t, const char *, mode_t, struct fuse_file_info *) { fuse_reply_err(req, EACCES); }
void mkdir(fuse_req_t req, fuse_ino_t, const char *, mode_t) { fuse_reply_err(req, EACCES); }
void mknod(fuse_req_t req, fuse_ino_t, const char *, mode_t, dev_t) { fuse_reply_err(req, EACCES); }
void symlink(fuse_req_t req, const char *, fuse_ino_t, const char *) { fuse_reply_err(req, EACCES); }
void setxattr(fuse_req_t req, fuse_ino_t, const char *, const char *, size_t, int) { fuse_reply_err(req, EACCES); }
void removexattr(fuse_req_t req, fuse_ino_t, const char *) { fuse_reply_err(req, EACCES); }
void getxattr(fuse_req_t req, fuse_ino_t, const char *, size_t) { fuse_reply_err(req, ENODATA); }
void listxattr(fuse_req_t req, fuse_ino_t, size_t size)
{
    if (!size) fuse_reply_xattr(req, 0);
    else fuse_reply_buf(req, nullptr, 0);
}
void fallocate(fuse_req_t req, fuse_ino_t, int, off_t, off_t, struct fuse_file_info *) { fuse_reply_err(req, EACCES); }
void ioctl(fuse_req_t req, fuse_ino_t, unsigned int, void *, struct fuse_file_info *, unsigned int,
           const void *, size_t, size_t) { fuse_reply_err(req, ENOTTY); }

void initialized(void *userdata, fuse_conn_info *)
{
    auto &v = *static_cast<View *>(userdata);
    if (v.managed_fd < 0) return;
    decoy::Frame ready; ready.mount_id = v.mount_id;
    v.ready = send(v.managed_fd, &ready, sizeof(ready), MSG_DONTWAIT | MSG_NOSIGNAL) == sizeof(ready);
    if (!v.ready) { v.management_error = true; fuse_session_exit(v.session); }
}
int managed_loop(View &v)
{
    const int fd = fuse_session_fd(v.session);
    const int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK)) return -errno;
    fuse_buf buffer{};
    int result = 0;
    while (!fuse_session_exited(v.session)) {
        pollfd inputs[] = {{v.managed_fd, POLLIN, 0}, {fuse_session_fd(v.session), POLLIN, 0}};
        const int polled = poll(inputs, 2, -1);
        if (polled < 0 && errno == EINTR) continue;
        if (polled < 0) { result = -errno; break; }
        if (inputs[0].revents & (POLLHUP | POLLERR | POLLNVAL)) break;
        if (inputs[0].revents & POLLIN) {
            decoy::Frame probe;
            iovec data{&probe, sizeof(probe)};
            msghdr message{}; message.msg_iov = &data; message.msg_iovlen = 1;
            const auto size = recvmsg(v.managed_fd, &message, MSG_DONTWAIT);
            if (size < 0 && (errno == EAGAIN || errno == EINTR)) continue;
            if (!size) break;
            if (size != sizeof(probe) || (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
                !v.ready || !decoy::valid(probe, decoy::Kind::probe) || !probe.sequence) { result = -EPROTO; break; }
            probe.kind = decoy::Kind::progress;
            if (send(v.managed_fd, &probe, sizeof(probe), MSG_DONTWAIT | MSG_NOSIGNAL) != sizeof(probe)) { result = -EPIPE; break; }
        }
        if (inputs[1].revents & (POLLIN | POLLHUP | POLLERR)) {
            result = fuse_session_receive_buf(v.session, &buffer);
            if (result == -EINTR || result == -EAGAIN) continue;
            if (result <= 0) break;
            fuse_session_process_buf(v.session, &buffer);
            result = 0;
        }
        if (inputs[1].revents & POLLNVAL) { result = -EBADF; break; }
    }
    std::free(buffer.mem);
    return v.management_error ? -EPROTO : result;
}
void usage()
{
    std::puts("Usage: secmon-decoyfs --mountpoint ABSOLUTE_EMPTY_DIRECTORY --file NAME [--file NAME ...] [--allow-other]\n"
              "Foreground immutable synthetic view, max 64 files of 4096 bytes.\n"
              "Mount first, then select each mounted file with secmon's canary policy.\n"
              "--allow-other requires root and explicitly exposes the view to other users.\n"
              "Stop secmon before unmounting; restart/reload policy after a new mount.");
}
bool empty_mountpoint(const std::string &path)
{
    if (path.empty() || path[0] != '/' || path == "/" || path.back() == '/') return false;
    char *resolved = realpath(path.c_str(), nullptr);
    const bool canonical = resolved && path == resolved;
    std::free(resolved);
    if (!canonical) return false;
    const int fd = ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return false;
    struct stat stat{};
    if (fstat(fd, &stat) || stat.st_uid != geteuid() || (stat.st_mode & 0022)) { close(fd); return false; }
    // Refuse covering an existing mount, including an empty FUSE view.
    struct statx here{}, parent{};
    const auto parent_path = path.substr(0, path.rfind('/')) + "/";
    if (statx(fd, "", AT_EMPTY_PATH, STATX_MNT_ID, &here) ||
        statx(AT_FDCWD, parent_path.c_str(), 0, STATX_MNT_ID, &parent) ||
        !(here.stx_mask & parent.stx_mask & STATX_MNT_ID) || here.stx_mnt_id != parent.stx_mnt_id) {
        close(fd); return false;
    }
    DIR *dir = fdopendir(fd);
    if (!dir) { close(fd); return false; }
    bool empty = true;
    errno = 0;
    while (auto *entry = readdir(dir)) {
        if (std::strcmp(entry->d_name, ".") && std::strcmp(entry->d_name, "..")) { empty = false; break; }
    }
    if (errno) empty = false;
    closedir(dir);
    return empty;
}
} // namespace

int main(int argc, char **argv)
{
    try {
        View v;
        std::string mountpoint;
        bool allow_other = false;
        unsigned parent = 0;
        for (int i = 1; i < argc; ++i) {
            const std::string arg(argv[i]);
            if (arg == "--help" && argc == 2) { usage(); return 0; }
            if (arg == "--allow-other" && !allow_other) { allow_other = true; continue; }
            if ((arg == "--managed-fd" || arg == "--parent-pid") && i + 1 < argc) {
                const std::string value(argv[++i]); unsigned number = 0;
                const auto parsed = std::from_chars(value.data(), value.data() + value.size(), number);
                if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() || !number || number > 2147483647U) return 2;
                if (arg == "--managed-fd" && number == 3 && v.managed_fd < 0) { v.managed_fd = number; continue; }
                if (arg == "--parent-pid" && !parent) { parent = number; continue; }
                return 2;
            }
            if ((arg == "--mountpoint" || arg == "--file") && i + 1 < argc) {
                const std::string value(argv[++i]);
                if (arg == "--mountpoint" && mountpoint.empty()) { mountpoint = value; continue; }
                if (arg == "--file" && valid_decoy_name(value) && v.files.size() < max_files &&
                    std::none_of(v.files.begin(), v.files.end(), [&](const File &f) { return f.name == value; })) {
                    File f; f.name = value;
                    const std::string seed = "SecMon synthetic decoy: " + value + "\n";
                    for (size_t j = 0; j < f.bytes.size(); ++j) f.bytes[j] = seed[j % seed.size()];
                    v.files.push_back(std::move(f)); continue;
                }
            }
            std::fprintf(stderr, "Invalid or duplicate option/file name\n"); return 2;
        }
        if ((v.managed_fd >= 0) != (parent > 0)) return 2;
        if (v.files.empty() || !empty_mountpoint(mountpoint) || (allow_other && geteuid() != 0)) {
            std::fprintf(stderr, "Require files and an absolute, empty, owned, non-symlink mountpoint without group/other write; allow-other requires root\n");
            return 2;
        }
        if (v.managed_fd >= 0) {
            int type = 0; socklen_t size = sizeof(type);
            ucred peer{}; socklen_t peer_size = sizeof(peer);
            if (getsockopt(v.managed_fd, SOL_SOCKET, SO_TYPE, &type, &size) || type != SOCK_SEQPACKET ||
                getsockopt(v.managed_fd, SOL_SOCKET, SO_PEERCRED, &peer, &peer_size) ||
                peer.pid != static_cast<pid_t>(parent) || peer.uid != geteuid()) return 2;
        }
        struct fuse_lowlevel_ops ops{};
        ops.init = initialized;
        ops.lookup = lookup; ops.forget = forget; ops.getattr = getattr; ops.setattr = setattr;
        ops.open = open; ops.read = read; ops.write = write; ops.flush = flush; ops.release = release;
        ops.opendir = opendir; ops.readdir = readdir; ops.releasedir = release; ops.statfs = statfs;
        ops.unlink = unlink; ops.rmdir = unlink; ops.rename = rename; ops.link = link;
        ops.create = create; ops.mkdir = mkdir; ops.mknod = mknod; ops.symlink = symlink;
        ops.setxattr = setxattr; ops.removexattr = removexattr; ops.getxattr = getxattr;
        ops.listxattr = listxattr; ops.fallocate = fallocate; ops.ioctl = ioctl;
        struct fuse_args args = FUSE_ARGS_INIT(0, nullptr);
        const std::string mount_options = std::string("default_permissions,nodev,nosuid,noexec,fsname=secmon-decoy,subtype=secmon-decoy") +
            (allow_other ? ",allow_other" : "");
        if (fuse_opt_add_arg(&args, argv[0]) || fuse_opt_add_arg(&args, "-o") ||
            fuse_opt_add_arg(&args, mount_options.c_str())) {
            fuse_opt_free_args(&args); return 1;
        }
        auto *session = fuse_session_new(&args, &ops, sizeof(ops), &v);
        fuse_opt_free_args(&args);
        if (!session) return 1;
        v.session = session;
        if (fuse_set_signal_handlers(session)) { fuse_session_destroy(session); return 1; }
        if (v.managed_fd >= 0 && (prctl(PR_SET_PDEATHSIG, SIGTERM) || prctl(PR_SET_DUMPABLE, 0) ||
                                   getppid() != static_cast<pid_t>(parent))) {
            fuse_remove_signal_handlers(session); fuse_session_destroy(session); return 1;
        }
        int result = fuse_session_mount(session, mountpoint.c_str());
        if (!result) {
            OwnedFd root(::open(mountpoint.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
            try {
                if (root.get() < 0) throw std::system_error(errno, std::generic_category(), "open decoy mount root");
                v.mount_id = decoy::unique_mount_id(root.get());
            } catch (const std::exception &error) {
                std::fprintf(stderr, "decoyfs: %s; mount identity unknown, leaving mount for explicit cleanup\n", error.what());
                fuse_remove_signal_handlers(session); fuse_session_destroy(session); return 1;
            }
            // No per-request logging and no user-space security decisions: a
            // stalled output consumer cannot stall the view's request loop.
            result = v.managed_fd < 0 ? fuse_session_loop(session) : managed_loop(v);
            if (decoy::inspect_mount(v.mount_id, mountpoint).state == decoy::MountState::attached)
                fuse_session_unmount(session);
            else
                std::fprintf(stderr, "decoyfs: mount moved, covered, detached or unknown; skipping pathname unmount\n");
        }
        fuse_remove_signal_handlers(session);
        fuse_session_destroy(session);
        return result < 0 ? 1 : 0;
    } catch (const std::exception &error) {
        std::fprintf(stderr, "decoyfs: %s\n", error.what()); return 1;
    }
}
