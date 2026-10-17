// SPDX-License-Identifier: MIT
// 从程序自身读取并报告实际 UID/EUID/capabilities，作为权限转换测试的对照，而非猜测执行结果。
// Observe only this short-lived test process; no privileged action is performed.
#include <cstdio>
#include <linux/capability.h>
#include <sys/syscall.h>
#include <unistd.h>

int main()
{
    __user_cap_header_struct header{};
    __user_cap_data_struct data[2]{};
    header.version = _LINUX_CAPABILITY_VERSION_3;
    if (syscall(SYS_capget, &header, data)) {
        std::perror("capget");
        return 1;
    }
    const auto caps = (static_cast<unsigned long long>(data[1].effective) << 32) | data[0].effective;
    std::printf("{\"pid\":%d,\"uid\":%d,\"euid\":%d,\"caps\":%llu}\n",
                getpid(), getuid(), geteuid(), caps);
    return 0;
}
