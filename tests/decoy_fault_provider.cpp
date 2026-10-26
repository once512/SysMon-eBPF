// SPDX-License-Identifier: MIT
// Test-only protocol peer. Does not mount a filesystem or certify any inode.
#include "decoy/protocol.h"
#include "analysis/transport.h"
#include <poll.h>
#include <string>
#include <unistd.h>
int main(int argc, char **argv)
{
    std::string mode;
    for (int i = 1; i + 1 < argc; ++i) if (std::string(argv[i]) == "--file") mode = argv[++i];
    if (mode == "no-ready") { poll(nullptr, 0, 5000); return 0; }
    if (mode == "exit-before-ready") return 4;
    decoy::Frame ready;
    if (mode == "bad-ready") ++ready.version;
    analysis::send_packet(3, &ready, sizeof(ready), mode == "ready-fds" ? 0 : -1);
    pollfd incoming{3, POLLIN, 0};
    if (poll(&incoming, 1, 5000) <= 0) return 3;
    decoy::Frame progress;
    const auto packet = analysis::receive_plain_packet(3, &progress, sizeof(progress));
    if (packet.status != analysis::Io::ready || packet.size != sizeof(progress)) return 2;
    if (mode == "exit-on-probe") return 5;
    progress.kind = decoy::Kind::progress;
    if (mode == "wrong-progress") ++progress.sequence;
    analysis::send_packet(3, &progress, sizeof(progress), mode == "progress-fds" ? 0 : -1);
    poll(nullptr, 0, 5000);
    return 0;
}
