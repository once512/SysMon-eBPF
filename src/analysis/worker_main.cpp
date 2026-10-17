// SPDX-License-Identifier: MIT
#include "scanner.h"
#include "transport.h"
#include <charconv>
#include <grp.h>
#include <linux/capability.h>
#include <sys/syscall.h>
#include <iostream>
#include <poll.h>
#include <climits>
#include <csignal>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/prctl.h>
#include <unistd.h>

namespace {
unsigned int number(std::string_view text)
{
    unsigned int value = 0;
    auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size())
        throw std::invalid_argument("Invalid analysis worker number");
    return value;
}
}
int main(int argc, char **argv)
{
    if (argc == 2 && std::string_view(argv[1]) == "--help") {
        std::cout << "Internal worker: secmon-analyzer --fd N --deny-marker TEXT --scan-limit-bytes N --parent-pid PID\n"
                     "Bounded literal-marker scanner over inherited SOCK_SEQPACKET; no public endpoint.\n";
        return 0;
    }
    try {
        if (argc != 9 || std::string_view(argv[1]) != "--fd" || (number(argv[2]) < 3 || number(argv[2]) > INT_MAX) ||
            std::string_view(argv[3]) != "--deny-marker" ||
            std::string_view(argv[5]) != "--scan-limit-bytes" ||
            std::string_view(argv[7]) != "--parent-pid" || number(argv[8]) < 2 || number(argv[8]) > INT_MAX)
            throw std::invalid_argument("Invalid internal analysis worker invocation");
        const std::string marker(argv[4]);
        const auto limit = number(argv[6]);
        if (marker.empty() || marker.size() > 256 || !limit || limit > 1024 * 1024)
            throw std::invalid_argument("Invalid marker or scan limit");
        if (geteuid() == 0 && (setgroups(0, nullptr) || setresgid(65534, 65534, 65534) ||
                               setresuid(65534, 65534, 65534)))
            throw std::runtime_error("Cannot drop analysis worker credentials");
        __user_cap_header_struct header{};
        __user_cap_data_struct capabilities[2]{};
        header.version = _LINUX_CAPABILITY_VERSION_3;
        if (syscall(SYS_capset, &header, capabilities) ||
            prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0))
            throw std::runtime_error("Cannot clear worker capabilities");
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) throw std::runtime_error("Cannot set no_new_privs");
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != static_cast<pid_t>(number(argv[8])))
            throw std::runtime_error("Analysis parent disappeared or death signal setup failed");
        if (prctl(PR_SET_DUMPABLE, 0)) throw std::runtime_error("Cannot disable worker dumpability");
        OwnedFd channel(static_cast<int>(number(argv[2])));
        analysis::Response initialized;
        initialized.result = analysis::Result::ready;
        if (!analysis::send_packet(channel.get(), &initialized, sizeof(initialized)))
            throw std::runtime_error("Cannot send worker readiness");
        while (true) {
            pollfd ready{channel.get(), POLLIN, 0};
            const int status = poll(&ready, 1, -1);
            if (status < 0) { if (errno == EINTR) continue; throw std::runtime_error("Worker poll failed"); }
            analysis::Request request;
            auto packet = analysis::receive_packet(channel.get(), &request, sizeof(request));
            if (packet.status == analysis::Io::closed) break;
            if (packet.status == analysis::Io::would_block) continue;
            if (packet.size != sizeof(request) || packet.fds.size() != 1 ||
                request.magic_value != analysis::magic || request.abi != analysis::version ||
                request.size != sizeof(request) || !request.id)
                throw std::runtime_error("Invalid analysis request");
            const auto response = analysis::scan(packet.fds[0].get(), request.id, marker, limit);
            if (!analysis::send_packet(channel.get(), &response, sizeof(response)))
                throw std::runtime_error("Worker response channel full");
        }
    } catch (const std::exception &error) {
        std::cerr << "secmon-analyzer: " << error.what() << '\n';
        return 1;
    }
    return 0;
}
