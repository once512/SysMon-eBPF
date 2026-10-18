// SPDX-License-Identifier: MIT
// 纯事件校验/JSONL 编码，不访问任何输出 FD；调用者决定如何入队和记录非法事件。
#include "events.h"
#include "secmon.h"
#include <cstring>
#include <sstream>

namespace {
// comm/filename 来自内核记录，按容量限制读取并转义，避免控制字符破坏 JSONL 的记录边界。
std::string json_string(const char *data, std::size_t capacity)
{
    constexpr char hex[] = "0123456789abcdef";
    std::string out = "\"";
    for (std::size_t i = 0; i < capacity && data[i]; ++i) {
        const auto c = static_cast<unsigned char>(data[i]);
        if (c == '"' || c == '\\') { out += '\\'; out += static_cast<char>(c); }
        else if (c < 0x20 || c >= 0x7f) {
            out += "\\u00"; out += hex[c >> 4]; out += hex[c & 15];
        } else out += static_cast<char>(c);
    }
    return out + '"';
}
} // namespace

std::optional<std::string> format_event(const void *data, std::size_t size)
{
    if (size != sizeof(exec_event)) {
        return std::nullopt;
    }
    // 将回调缓冲复制到本地结构再读取，不假设传入地址满足宿主 C++ 结构的对齐要求。
    if (!data) return std::nullopt;
    exec_event e{};
    std::ostringstream out;
    // 回调中的 data 只在消费期间借用；
    // 复制出完整事件后再按 kind 解释，不把缓冲区地址长期保存。
    std::memcpy(&e, data, sizeof(e));
    if (e.version != SECMON_ABI_VERSION || e.size != sizeof(e)) {
        return std::nullopt;
    }
    if (e.kind == SECMON_SELF_DENIED_EVENT) {
        out << "{\"event\":\"self_denied\",\"timestamp_ns\":" << e.timestamp_ns
                  << ",\"pid\":" << e.pid << ",\"tid\":" << e.tid
                  << ",\"start_ns\":" << e.start_ns << ",\"process_inode\":" << e.process_inode
                  << ",\"target_pid\":" << e.target_pid << ",\"signal\":" << e.signal
                  << ",\"operation\":" << e.operation << ",\"errno\":1"
                  << ",\"uid\":" << e.caller_uid << ",\"euid\":" << e.caller_euid
                  << ",\"comm\":" << json_string(e.comm, sizeof(e.comm)) << "}\n";
        return out.str();
    }
    // 文件身份输出设备号/inode 而不是猜测完整路径；
    // 事件丢失影响审计完整性，但不会撤销已经作出的内核拒绝。
    if (e.kind == SECMON_FILE_DENIED) {
        out << "{\"event\":\"file_denied\",\"timestamp_ns\":" << e.timestamp_ns
                  << ",\"pid\":" << e.pid << ",\"tid\":" << e.tid
                  << ",\"start_ns\":" << e.start_ns << ",\"process_inode\":" << e.process_inode
                  << ",\"uid\":" << e.caller_uid << ",\"euid\":" << e.caller_euid
                  << ",\"dev_major\":" << e.file.major << ",\"dev_minor\":" << e.file.minor
                  << ",\"ino\":" << e.file.ino << ",\"operation\":" << e.operation
                  << ",\"errno\":13,\"comm\":" << json_string(e.comm, sizeof(e.comm)) << "}\n";
        return out.str();
    }
    // 检查事件与完成事件不是一一对应：失败 exec 没有完成事件，解释器链也可能产生多次安全检查。
    const char *kind = e.kind == SECMON_EXEC_CHECK ? "exec_check" :
                       e.kind == SECMON_EXEC_SUCCESS ? "exec_success" : nullptr;
    if (!kind) {
        return std::nullopt;
    }
    out << "{\"event\":\"" << kind << "\",\"timestamp_ns\":" << e.timestamp_ns
              << ",\"old_tid\":" << e.old_tid
              << ",\"start_ns\":" << e.start_ns << ",\"process_inode\":" << e.process_inode << ",\"pid\":" << e.pid
              << ",\"tid\":" << e.tid << ",\"ppid\":" << e.ppid
              << ",\"uid\":" << e.caller_uid << ",\"euid\":" << e.caller_euid
              << ",\"target_euid\":" << e.target_euid << ",\"caps\":" << e.caps
              << ",\"mode\":" << e.file_mode << ",\"flags\":" << e.flags
              << ",\"comm\":" << json_string(e.comm, sizeof(e.comm))
              << ",\"filename\":" << json_string(e.filename, sizeof(e.filename)) << "}\n";
    return out.str();
}
