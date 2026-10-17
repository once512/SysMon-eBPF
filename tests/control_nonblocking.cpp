// SPDX-License-Identifier: MIT
// 管理循环回归：连接后不发命令时 dispatch 应立即返回，正常命令也必须在业务循环外部可逐步推进。
#include "control.h"
#include <algorithm>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int main()
{
    if (geteuid() != 0) return 2;
    char directory[] = "/tmp/secmon-control-loop-XXXXXX";
    if (!mkdtemp(directory)) return 2;
    const std::string path = std::string(directory) + "/control";
    try {
        std::chrono::microseconds times[3];
        {
            ControlServer server(path);
            auto handler = [](ControlCommand) {
                management::Reply reply;
                reply.pid = getpid();
                reply.instance_ns = 1;
                return reply;
            };
            for (auto &elapsed : times) {
                OwnedFd client(socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0));
                sockaddr_un address{};
                address.sun_family = AF_UNIX;
                std::memcpy(address.sun_path, path.c_str(), path.size() + 1);
                if (connect(client.get(), reinterpret_cast<sockaddr *>(&address), sizeof(address)))
                    throw std::runtime_error("connect failed");
                const auto before = std::chrono::steady_clock::now();
                server.dispatch(handler);
                elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - before);
                // 同一连接稍后发送；服务器不得因为第一次无数据就提前丢弃合法客户端。
                if (send(client.get(), "status-v2", 9, MSG_NOSIGNAL) != 9) throw std::runtime_error("send failed");
                server.dispatch(handler);
                management::Reply reply;
                if (recv(client.get(), &reply, sizeof(reply), MSG_DONTWAIT) != sizeof(reply))
                    throw std::runtime_error("reply failed");
                management::validate_reply(reply, ControlCommand::status);
            }
        }
        std::sort(std::begin(times), std::end(times));
        // 仅是本机回归阈值，非调度/SLA 保证；中位数排除一次调度暂停，原阻塞实现每次约 100ms。
        if (times[1] >= std::chrono::milliseconds(50)) throw std::runtime_error("dispatch blocked on a silent client");
        std::cout << "PASS nonblocking management dispatch; median_us=" << times[1].count() << '\n';
    } catch (...) {
        std::filesystem::remove_all(directory);
        throw;
    }
    std::filesystem::remove_all(directory);
}
