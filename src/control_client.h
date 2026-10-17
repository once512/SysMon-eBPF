// SPDX-License-Identifier: MIT
// CLI/核对工具使用的管理客户端接口：没有 ControlServer、待连接状态或目录资源依赖。
#pragma once
#include "management/protocol.h"
#include <string>

void request_stop(const std::string &path);
void request_reload(const std::string &path);
// 供只读核对工具使用，返回已校验响应，不写 stdout、不发送变更命令。
// 失败会抛异常；
// 成功值已验证当前 ABI 与服务 PID，但它是采样状态，不锁住之后的后端变化。
management::Reply query_status(const std::string &path);
void request_status(const std::string &path);
