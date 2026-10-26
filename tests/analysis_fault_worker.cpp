// SPDX-License-Identifier: MIT
// 故意违反协议的测试后端，用于验证宿主拒绝错误/重复/截断响应，不应当作正式扫描器部署。
// Test-only peer that deliberately violates the analyzer reply protocol.
#include "analysis/protocol.h"
#include "analysis/transport.h"
#include <cstring>
#include <cerrno>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 9) return 2;
    const std::string mode(argv[4]);
    if (mode == "no-ready") { poll(nullptr, 0, 5000); return 0; }
    if (mode == "refuse-requests" && shutdown(3, SHUT_RD)) return 8;
    analysis::Response initialized;
    initialized.result = analysis::Result::ready;
    if (mode == "ready-error") initialized.error = analysis::ScanError::changed;
    if (mode == "bad-ready") initialized.id = 42;
    analysis::send_packet(3, &initialized, sizeof(initialized), mode == "ready-fds" ? 0 : -1);
    if (mode == "refuse-requests") { poll(nullptr, 0, 5000); return 0; }
    unsigned requests = 0;
    while (true) {
        pollfd ready{3, POLLIN, 0};
        if (poll(&ready, 1, 5000) <= 0) return 3;
        analysis::Request request;
        auto packet = analysis::receive_packet(3, &request, sizeof(request));
        if (packet.status != analysis::Io::ready || packet.fds.size() != 1) return 4;
        analysis::Response reply;
        reply.id = request.id;
        reply.result = analysis::Result::allow;
        if (mode == "fuse-reply-fds" && !requests++) {
            analysis::send_packet(3, &reply, sizeof(reply));
            continue;
        }
        if (mode == "delay") {
            usleep(200000);
            analysis::send_packet(3, &reply, sizeof(reply));
            continue;
        }
        if (mode == "wrong-id") ++reply.id;
        else if (mode == "wrong-version") ++reply.abi;
        else if (mode == "wrong-size") ++reply.size;
        else if (mode == "wrong-bytes") reply.bytes_scanned = 2 * 1024 * 1024;
        else if (mode == "wrong-verdict") reply.result = static_cast<analysis::Result>(99);
        else if (mode == "wrong-error") reply.error = static_cast<analysis::ScanError>(99);
        else if (mode == "allow-error") reply.error = analysis::ScanError::changed;
        else if (mode == "error-without-reason") reply.result = analysis::Result::error;
        else if (mode == "wrong-errno") reply.system_errno = -1;
        else if (mode == "metadata-no-errno") { reply.result = analysis::Result::error; reply.error = analysis::ScanError::metadata_failed; }
        else if (mode == "resource-error") {
            reply.result = analysis::Result::error;
            reply.error = analysis::ScanError::resource_exhausted;
            reply.system_errno = ENOMEM;
            analysis::send_packet(3, &reply, sizeof(reply));
            continue;
        }
        else if (mode == "exit") return 7;
        else if (mode == "late") usleep(300000);
        else if (mode == "short") {
            analysis::send_packet(3, &reply, 1);
            poll(nullptr, 0, 5000);
            return 0;
        } else if ((mode == "extra-fds" || mode == "fuse-reply-fds")) {
            // Nine copies exceed the receiver's eight-FD ancillary budget.
            alignas(cmsghdr) char control[CMSG_SPACE(sizeof(int) * 9)]{};
            iovec vector{&reply, sizeof(reply)};
            msghdr message{};
            message.msg_iov = &vector;
            message.msg_iovlen = 1;
            message.msg_control = control;
            message.msg_controllen = sizeof(control);
            auto *item = CMSG_FIRSTHDR(&message);
            item->cmsg_level = SOL_SOCKET;
            item->cmsg_type = SCM_RIGHTS;
            item->cmsg_len = CMSG_LEN(sizeof(int) * 9);
            int fds[9];
            for (int &fd : fds) fd = packet.fds[0].get();
            std::memcpy(CMSG_DATA(item), fds, sizeof(fds));
            sendmsg(3, &message, MSG_NOSIGNAL);
            poll(nullptr, 0, 5000);
            return 0;
        }
        analysis::send_packet(3, &reply, sizeof(reply));
        if (mode == "duplicate") analysis::send_packet(3, &reply, sizeof(reply));
        poll(nullptr, 0, 5000); // Supervisor must stop/reap the bad peer.
        return 0;
    }
}
