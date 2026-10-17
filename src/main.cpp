// SPDX-License-Identifier: MIT
// 唯一监控服务入口：参数/管理动作在前，模块资源由 MonitorService 内的两个对象统一管理。
#include "options.h"
#include "service.h"
#include "bpf/monitor.h"
#include "control_client.h"
#include <iostream>
#include <stdexcept>
int main(int argc, char **argv)
{
    Options options;
    CliAction action;
    try { action = parse_options(argc, argv, options); }
    catch (const std::invalid_argument &error) { std::cerr << "secmon: " << error.what() << '\n'; return 2; }
    if (action == CliAction::help) return 0;
    try {
        if (action == CliAction::stop) { request_stop(options.control_path); return 0; }
        if (action == CliAction::reload) { request_reload(options.control_path); return 0; }
        if (action == CliAction::status) { request_status(options.control_path); return 0; }
        if (options.check) { BpfMonitor::check_environment(); return 0; }
        MonitorService service(std::move(options));
        service.run();
    } catch (const std::exception &error) { std::cerr << "secmon: " << error.what() << '\n'; return 1; }
    return 0;
}
