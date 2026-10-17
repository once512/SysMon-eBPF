// SPDX-License-Identifier: MIT
// Isolated allocation fault injection: recvmsg must not install an unowned FD.
#include "analysis/protocol.h"
#include "analysis/transport.h"
#include <cstdlib>
#include <fcntl.h>
#include <iostream>
#include <new>
#include <sys/socket.h>
#include <unistd.h>

namespace { bool fail_next = false; }
void *operator new(std::size_t size)
{
    if (fail_next) { fail_next = false; throw std::bad_alloc(); }
    if (auto *memory = std::malloc(size ? size : 1)) return memory;
    throw std::bad_alloc();
}
void operator delete(void *memory) noexcept { std::free(memory); }
void operator delete(void *memory, std::size_t) noexcept { std::free(memory); }

int main()
{
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair)) return 1;
    OwnedFd parent(pair[0]), child(pair[1]);
    OwnedFd file(open("/dev/null", O_RDONLY | O_CLOEXEC));
    if (file.get() < 0) return 1;
    analysis::Request sent;
    sent.id = 42;
    if (!analysis::send_packet(parent.get(), &sent, sizeof(sent), file.get())) return 1;
    analysis::Request received;
    bool failed = false;
    fail_next = true;
    try { analysis::receive_packet(child.get(), &received, sizeof(received)); }
    catch (const std::bad_alloc &) { failed = true; }
    fail_next = false;
    if (!failed) return 1;
    // The message (and its SCM_RIGHTS reference) must still be in the socket,
    // not already consumed by an allocation that failed after FD installation.
    auto packet = analysis::receive_packet(child.get(), &received, sizeof(received));
    if (packet.status != analysis::Io::ready || received.id != 42 || packet.fds.size() != 1) return 1;
    if (fcntl(packet.fds[0].get(), F_GETFD) < 0) return 1;
    std::cout << "PASS allocation failure precedes FD installation and preserves queued message\n";
    return 0;
}
