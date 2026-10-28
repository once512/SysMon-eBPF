// SPDX-License-Identifier: MIT
// 唯一监控服务入口：参数/管理动作在前，模块资源由 MonitorService 内的两个对象统一管理。
#include "options.h"
#include "service.h"
#include "service_notify.h"
#include "diagnostic_output.h"
#include <bpf/libbpf.h>
#include <cstdio>
#include <memory>
#include "bpf/monitor.h"
#include "control_client.h"
#include <iostream>
#include <stdexcept>
#include <csignal>
#include <cerrno>
#include <system_error>
namespace {
int libbpf_diagnostic(enum libbpf_print_level level, const char *format, va_list arguments)
{
    if (level == LIBBPF_DEBUG) return 0;
    char message[SECMON_DIAGNOSTIC_MAX_LINE_BYTES];
    const int count = vsnprintf(message, sizeof(message), format, arguments);
    if (count < 0) return count;
    if (static_cast<std::size_t>(count) >= sizeof(message)) {
        // 过长的库诊断也走相同整行丢弃口径，不让 verifier 日志直接同步写 stderr。
        std::cerr.write(message, sizeof(message) - 1);
        std::cerr << " [truncated]\n";
    } else std::cerr.write(message, count);
    return count;
}
struct LibbpfDiagnostics {
    libbpf_print_fn_t previous = libbpf_set_print(libbpf_diagnostic);
    ~LibbpfDiagnostics() { libbpf_set_print(previous); }
};
}
int main(int argc, char **argv)
{
    Options options;
    CliAction action;
    try { action = parse_options(argc, argv, options); }
    catch (const std::invalid_argument &error) { std::cerr << "secmon: " << error.what() << '\n'; return 2; }
    if (action == CliAction::help) return 0;
    std::unique_ptr<DiagnosticOutput> diagnostics;
    try {
        if (action == CliAction::stop) { request_stop(options.control_path); return 0; }
        if (action == CliAction::reload) { request_reload(options.control_path); return 0; }
        if (action == CliAction::status) { request_status(options.control_path); return 0; }
        if (options.check) { BpfMonitor::check_environment(); return 0; }
        // Reserve numeric child PIDs until their explicit waitpid. An inherited
        // SIG_IGN/SA_NOCLDWAIT would auto-reap them and invalidate that ownership
        // assumption before pidfd allocation or in the fork-only readers.
        struct sigaction child_status{};
        child_status.sa_handler = SIG_DFL;
        if (sigemptyset(&child_status.sa_mask) || sigaction(SIGCHLD, &child_status, nullptr))
            throw std::system_error(errno, std::generic_category(), "reset child status disposition");
        ServiceNotify notification; // Capture/unset environment before threads and helper spawn.
        diagnostics = std::make_unique<DiagnosticOutput>();
        LibbpfDiagnostics libbpf_diagnostics;
        MonitorService service(std::move(options), *diagnostics);
        service.run(notification);
    } catch (const std::exception &error) { std::cerr << "secmon: " << error.what() << '\n'; return 1; }
    return 0;
}
