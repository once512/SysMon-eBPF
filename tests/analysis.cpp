// SPDX-License-Identifier: MIT
#include "analysis/scanner.h"
#include "analysis/transport.h"
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

namespace {
void require(bool value, const char *message) { if (!value) throw std::runtime_error(message); }
struct TestFile {
    std::string path;
    OwnedFd writer;
    explicit TestFile(const std::string &contents)
    {
        char name[] = "/tmp/secmon-analysis-unit-XXXXXX";
        writer = OwnedFd(mkstemp(name));
        require(writer.get() >= 0, "mkstemp");
        path = name;
        if (write(writer.get(), contents.data(), contents.size()) != static_cast<ssize_t>(contents.size())) {
            unlink(path.c_str());
            throw std::runtime_error("write fixture");
        }
    }
    ~TestFile() { unlink(path.c_str()); }
    OwnedFd reader() { return OwnedFd(open(path.c_str(), O_RDONLY | O_CLOEXEC)); }
};
}
int main()
{
    try {
        TestFile clean("normal bytes");
        auto fd = clean.reader();
        auto result = analysis::scan(fd.get(), 1, "DENY", 64);
        require(result.result == analysis::Result::allow && result.bytes_scanned == 12 && result.id == 1,
                "Clean content should be allowed");
        require(lseek(fd.get(), 0, SEEK_CUR) == 0, "Scanner must not change shared FD offset");
        require(analysis::scan(clean.writer.get(), 2, "DENY", 64).result == analysis::Result::error,
                "Reject writable transferred FD");
        require(analysis::scan(fd.get(), 2, "DENY", 4).result == analysis::Result::error,
                "Oversized content cannot be declared clean");
        require(analysis::scan(fd.get(), 2, "", 64).result == analysis::Result::error, "Reject empty marker");
        TestFile boundary(std::string(4094, 'a') + "DENY" + "rest");
        auto marked = boundary.reader();
        require(analysis::scan(marked.get(), 3, "DENY", 8192).result == analysis::Result::deny,
                "Match must cross read-chunk boundary");
        TestFile empty("");
        auto empty_fd = empty.reader();
        require(analysis::scan(empty_fd.get(), 4, "DENY", 1).result == analysis::Result::allow,
                "Empty regular file should be allowed");
        OwnedFd directory(open("/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
        require(analysis::scan(directory.get(), 4, "DENY", 64).result == analysis::Result::error,
                "Reject non-regular descriptors");
        int pair[2];
        require(!socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair), "socketpair");
        OwnedFd left(pair[0]), right(pair[1]);
        analysis::Request request;
        request.id = 42;
        require(analysis::send_packet(left.get(), &request, sizeof(request), fd.get()), "Send request");
        analysis::Request received;
        int transferred = -1;
        {
            auto packet = analysis::receive_packet(right.get(), &received, sizeof(received));
            require(packet.status == analysis::Io::ready && packet.size == sizeof(request) &&
                    packet.fds.size() == 1 && received.id == 42, "Receive one owned FD");
            transferred = packet.fds[0].get();
            require((fcntl(transferred, F_GETFD) & FD_CLOEXEC) != 0, "Received FD must be CLOEXEC");
            require(analysis::scan(transferred, 42, "DENY", 64).result == analysis::Result::allow,
                    "Transferred FD names the original file");
        }
        require(fcntl(transferred, F_GETFD) < 0 && errno == EBADF, "Packet destruction closes FD");
        require(analysis::receive_packet(right.get(), &received, sizeof(received)).status ==
                analysis::Io::would_block, "Empty queue is nonblocking");
        std::string oversized(256, 'x');
        require(analysis::send_packet(left.get(), oversized.data(), oversized.size(), fd.get()), "Send oversized packet");
        bool rejected = false;
        try { analysis::receive_packet(right.get(), &received, sizeof(received)); }
        catch (const std::runtime_error &) { rejected = true; }
        require(rejected, "Truncated payload must be rejected");
        left = OwnedFd();
        require(analysis::receive_packet(right.get(), &received, sizeof(received)).status ==
                analysis::Io::closed, "Peer close is observable");
        std::cout << "PASS bounded content scanning and FD-passing transport\n";
    } catch (const std::exception &error) { std::cerr << error.what() << '\n'; return 1; }
    return 0;
}
