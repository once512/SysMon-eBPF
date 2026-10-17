// SPDX-License-Identifier: MIT
// 事件格式边界：无 I/O 地拒绝错误 ABI/长度/种类，复制未对齐记录，限制最坏转义后的单行长度。
#include "events.h"
#include "secmon.h"
#include <secmon/audit_limits.h>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <vector>
void require(bool value) { if (!value) throw std::runtime_error("event format assertion"); }
int main()
{
    exec_event event{};
    event.version = SECMON_ABI_VERSION;
    event.size = sizeof(event);
    require(!format_event(nullptr, sizeof(event)));
    require(!format_event(&event, sizeof(event) - 1));
    require(!format_event(&event, sizeof(event)));
    for (unsigned kind : {SECMON_EXEC_CHECK, SECMON_EXEC_SUCCESS, SECMON_FILE_DENIED, SECMON_SELF_DENIED_EVENT}) {
        event.kind = kind;
        const auto line = format_event(&event, sizeof(event));
        require(line && line->back() == '\n');
        require(line->find("\"event\":") != std::string::npos);
    }
    event.version = 999;
    require(!format_event(&event, sizeof(event)));
    // 内核缓冲地址不应被假定为符合 C++ 对齐要求，编码器使用 memcpy 建立本地副本。
    std::memset(&event, 255, sizeof(event));
    event.version = SECMON_ABI_VERSION;
    event.size = sizeof(event);
    event.kind = SECMON_EXEC_CHECK;
    std::vector<unsigned char> bytes(sizeof(event) + 1);
    std::memcpy(bytes.data() + 1, &event, sizeof(event));
    const auto maximum = format_event(bytes.data() + 1, sizeof(event));
    require(maximum && maximum->size() <= SECMON_AUDIT_MAX_LINE_BYTES);
    require(maximum->find("\\u00ff") != std::string::npos);
    require(maximum->find("18446744073709551615") != std::string::npos);
    event.comm[0] = '"'; event.comm[1] = '\\'; event.comm[2] = '\n'; event.comm[3] = 0;
    const auto escaped = format_event(&event, sizeof(event));
    require(escaped && escaped->find("\\\"\\\\\\u000a") != std::string::npos);
    std::cout << "PASS event ABI, aligned copies, maximum encoded size and JSON string escaping\n";
}
