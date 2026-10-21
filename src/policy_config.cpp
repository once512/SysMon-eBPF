// SPDX-License-Identifier: MIT
// 纯语法解析：读取有界行，分派字段，再做整体约束；不读取目标文件、不固定 inode、不更新 Map。
// 配置来源的权限/身份/摘要处理在 policy/source.cpp，fanotify 字段组合在 policy/fanotify_fields.cpp。
#include "policy_config.h"
#include "policy/fields.h"
#include "policy/fanotify_fields.h"
#include "policy/writer_fields.h"
#include <set>
#include <sstream>

PolicyConfig parse_policy(std::istream &input)
{
    using namespace policy_fields;
    PolicyConfig result;
    FanotifyFields fanotify;
    std::set<std::string> paths;
    std::set<std::pair<std::string, std::string>> writers;
    std::size_t bytes = 0, line_number = 0;
    std::string line;
    while (std::getline(input, line)) {
        ++line_number;
        try {
            bytes += line.size() + (input.eof() ? 0 : 1);
            if (bytes > SECMON_POLICY_MAX_BYTES || line.find('\0') != std::string::npos)
                invalid("policy exceeds byte limit or contains NUL");
            std::istringstream fields(line);
            std::string key;
            if (!(fields >> key) || key.front() == '#') continue;
            if (key == "protect") {
                auto value = path(fields);
                if (!paths.insert(value).second || result.paths.size() == SECMON_MAX_PROTECTED_PATHS)
                    invalid("duplicate protect path or too many protected files");
                result.paths.push_back(std::move(value));
            } else if (key == "allow-writer") {
                auto value = path(fields);
                if (result.writers.size() == SECMON_MAX_WRITER_RULES) invalid("too many writer grants");
                // (uid_t)-1 是无效 UID；此处只验证文本，同 inode 别名冲突在候选 Map 准备时验证。
                const auto uid = number<std::uint32_t>(word(fields), 0, UINT32_MAX - 1);
                auto target = path(fields);
                const auto operations = parse_writer_operations(word(fields));
                // 规则按程序路径/目标路径去重；相同 inode 的别名冲突仍交给固定对象阶段判断。
                if (!writers.emplace(value, target).second) invalid("duplicate writer/target grant");
                result.writers.push_back({std::move(value), uid, std::move(target), operations});
            } else if (key == "writer-lease-ms" && !result.writer_lease_ms) {
                result.writer_lease_ms = number<unsigned int>(word(fields), 100, 3600000);
            } else if (key.compare(0, 9, "fanotify-") == 0) fanotify.parse(key, fields);
            else if (key == "revision" && !result.revision)
                result.revision = number<std::uint64_t>(word(fields), 1, UINT64_MAX);
            else invalid("unknown or duplicate field: " + key);
            std::string extra;
            // 一行只允许契约中的字段；不接受行尾注释，避免不同读取者产生不同解释。
            if (fields >> extra) invalid("unexpected trailing field");
        } catch (const std::runtime_error &error) {
            throw std::runtime_error("Invalid policy at line " + std::to_string(line_number) + ": " + error.what());
        }
    }
    if (input.bad() || !result.revision) invalid("Invalid policy: missing positive revision or input failure");
    for (const auto &writer : result.writers)
        if (!paths.count(writer.target)) invalid("writer target must be an explicit protect path: " + writer.target);
    if (result.writer_lease_ms && result.writers.empty())
        invalid("writer-lease-ms requires at least one allow-writer grant");
    result.fanotify = fanotify.finish();
    return result;
}
