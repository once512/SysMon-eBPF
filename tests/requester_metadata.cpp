// SPDX-License-Identifier: MIT
#include "fanotify/metadata.h"
#include "fanotify/decisions.h"
#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <linux/fanotify.h>
#include <stdexcept>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
using namespace std::chrono_literals;
void require(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
int descriptor() { int fd = open("/dev/null", O_RDONLY | O_CLOEXEC); require(fd >= 0, "test fd"); return fd; }
bool closed(int fd) { return fcntl(fd, F_GETFD) == -1 && errno == EBADF; }
struct Packet {
    fanotify_event_metadata event{};
    fanotify_event_info_pidfd process{};
    Packet(int file, int pidfd) {
        event.event_len = sizeof(Packet); event.vers = FANOTIFY_METADATA_VERSION;
        event.metadata_len = sizeof(event); event.mask = FAN_OPEN_PERM;
        event.fd = file; event.pid = getpid();
        process.hdr.info_type = FAN_EVENT_INFO_TYPE_PIDFD; process.hdr.len = sizeof(process); process.pidfd = pidfd;
    }
};
static_assert(sizeof(Packet) == sizeof(fanotify_event_metadata) + sizeof(fanotify_event_info_pidfd));
int main()
{
    const int self = static_cast<int>(syscall(SYS_pidfd_open, getpid(), 0));
    require(self >= 0, "kernel pidfd required for unprivileged tests");
    struct stat self_stat{}; require(!fstat(self, &self_stat), "pidfd stat"); close(self);
    {
        int file = descriptor(); int pid = static_cast<int>(syscall(SYS_pidfd_open, getpid(), 0));
        Packet packet(file, pid);
        std::array<char, sizeof(Packet) + 1> unaligned{};
        std::memcpy(unaligned.data() + 1, &packet, sizeof(packet));
        {
            auto decoded = decode_permission_metadata(unaligned.data() + 1, sizeof(packet), true);
            require(decoded.file.get() == file && decoded.requester.fd.get() == pid, "adopt both descriptors");
            require(decoded.requester.identity.state == ProcessReferenceState::present &&
                    decoded.requester.identity.inode == self_stat.st_ino && decoded.requester.identity.error == 0, "pidfs identity");
        }
        require(closed(file) && closed(pid), "decoded descriptors released");
    }
    for (int sentinel : {FAN_NOPIDFD, FAN_EPIDFD}) {
        Packet packet(descriptor(), sentinel);
        auto decoded = decode_permission_metadata(&packet, sizeof(packet), true);
        require(decoded.requester.fd.get() < 0 && !decoded.requester.identity.inode && !decoded.requester.identity.error, "kernel sentinel");
        require(decoded.requester.identity.state == (sentinel == FAN_NOPIDFD ? ProcessReferenceState::unavailable : ProcessReferenceState::error), "sentinel states differ");
    }
    auto reject = [](auto mutate) {
        int file = descriptor(), pid = descriptor();
        Packet packet(file, pid); mutate(packet);
        bool failed = false;
        try { auto result = decode_permission_metadata(&packet, sizeof(packet), true); }
        catch (const std::runtime_error &) { failed = true; }
        require(failed && closed(file) && closed(pid), "invalid metadata closes all delivered handles");
    };
    reject([](auto &p) { p.event.vers = 255; });
    reject([](auto &p) { p.event.event_len = 24; });
    reject([](auto &p) { p.event.metadata_len = 0; });
    reject([](auto &p) { p.process.hdr.info_type = FAN_EVENT_INFO_TYPE_FID; });
    reject([](auto &p) { p.process.hdr.len = 0; });
    reject([](auto &p) { p.process.hdr.pad = 1; });
    {
        Packet packet(descriptor(), descriptor());
        auto result = decode_permission_metadata(&packet, sizeof(packet), true);
        require(result.requester.identity.state == ProcessReferenceState::present &&
                !result.requester.identity.inode && result.requester.identity.error == EOPNOTSUPP, "non-pidfs fd never gets a process cookie");
    }
    {
        Packet packet(descriptor(), FAN_NOPIDFD);
        packet.event.event_len = sizeof(packet.event);
        auto result = decode_permission_metadata(&packet, sizeof(packet.event), false);
        require(result.requester.identity.state == ProcessReferenceState::disabled && result.requester.fd.get() == -1, "legacy mode");
    }
    DecisionConfig config; config.allow = true; config.delay = 10ms; config.timeout = 20ms; config.max_pending = 1;
    auto start = PendingDecisions::Clock::time_point{};
    for (int completion = 0; completion < 7; ++completion) {
        int pid = static_cast<int>(syscall(SYS_pidfd_open, getpid(), 0));
        int file = descriptor();
        int replies = 0;
        {
            PendingDecisions pending(config, [&](int delivered, const PermissionRequest &request, Verdict) {
                require(delivered == file && !closed(pid), "pidfd pinned through callback");
                require(request.process.inode == self_stat.st_ino && request.process.state == ProcessReferenceState::present, "context identity retained");
                ++replies;
                if (completion == 5) throw std::runtime_error("injected reply failure");
            });
            auto handle = process_reference(pid);
            if (completion == 3) {
                // Occupy the queue; capacity fallback for our request must close both handles.
                pending.submit(OwnedFd(descriptor()), start);
            }
            try {
                pending.submit(OwnedFd(file), start, getpid(), 7, std::move(handle));
                if (completion == 0 || completion == 5) pending.process_due(start + 10ms);
                if (completion == 1) pending.process_due(start + 20ms);
                if (completion == 2) pending.shutdown();
                if (completion == 6) pending.fail_analysis();
                if (completion == 4) { /* Destructor closes without fabricating a reply. */ }
            } catch (const std::runtime_error &) { require(completion == 5, "only injected error"); }
            require(handle.fd.get() == -1, "submit transfers process reference");
            if (completion != 3 && completion != 4 && completion != 5) require(closed(pid) && closed(file), "completed request closes handles");
        }
        require(closed(pid) && closed(file), "all completion/destruction paths close handles");
        require(replies == (completion == 4 ? 0 : 1), "exactly one callback or abandoned request");
    }
    std::cout << "PASS metadata ownership, pidfs identity, malformed attachments, sentinels and pending lifecycle\n";
}
