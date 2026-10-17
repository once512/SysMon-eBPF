// SPDX-License-Identifier: MIT
// 仅构建 fanotify 配置值：单行字段读取与最终模式约束分开，不依赖 group/mark 或运行对象。
#pragma once
#include "policy_config.h"
#include <set>
namespace policy_fields {
class FanotifyFields {
    FanotifyPolicy value_;
    std::set<std::string> seen_;
public:
    void parse(const std::string &key, std::istream &fields);
    std::optional<FanotifyPolicy> finish();
};
}
