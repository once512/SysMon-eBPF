// SPDX-License-Identifier: MIT
#include "options.h"
#include <charconv>
#include <filesystem>
#include <iostream>
#include <set>
#include <stdexcept>
#include <string_view>

namespace {
unsigned int number(std::string_view option, std::string_view text,
                    unsigned int minimum, unsigned int maximum)
{
    unsigned int value = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() ||
        value < minimum || value > maximum)
        throw std::invalid_argument(std::string(option) + " requires " +
                                    std::to_string(minimum) + ".." + std::to_string(maximum));
    return value;
}
bool allow(std::string_view option, std::string_view text)
{
    if (text == "allow") return true;
    if (text == "deny") return false;
    throw std::invalid_argument(std::string(option) + " requires allow|deny");
}
}

bool parse_fanotify_options(int argc, char **argv, FanotifyOptions &options)
{
    if (argc == 2 && std::string_view(argv[1]) == "--help") {
        std::cout << "Usage: secmon-fanotify --file PATH --run-for SECONDS [--decision allow|deny |\n"
                     "       --analyzer ABSOLUTE_PATH --deny-marker TEXT]\n"
                     "  --scan-limit-bytes 1..1048576      (default 65536; oversized files return error)\n"
                     "  --analyzer-error-decision allow|deny (default deny)\n"
                     "  --event open|access|exec          (default open; one event type)\n"
                     "Optional deferred-decision experiment:\n"
                     "  --decision-delay-ms 0..60000     (default 0; synthetic analysis delay)\n"
                     "  --request-timeout-ms 1..60000    (default 250; starts on event receipt)\n"
                     "  --max-pending 1..4096            (default 64; delivered events only)\n"
                     "  --timeout-decision allow|deny    (default deny)\n"
                     "  --overload-decision allow|deny   (default deny)\n"
                     "Single-inode permission experiment; requires CAP_SYS_ADMIN.\n"
                     "SECONDS: 1..3600. Closing/crashing releases unread/pending requests.\n";
        return false;
    }
    std::set<std::string_view> seen;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg(argv[i]);
        if (!seen.insert(arg).second) throw std::invalid_argument("Duplicate option: " + std::string(arg));
        if (i + 1 >= argc) throw std::invalid_argument("Missing value: " + std::string(arg));
        const std::string_view value(argv[++i]);
        if (arg == "--file") options.path = value;
        else if (arg == "--analyzer") options.analyzer.executable = value;
        else if (arg == "--deny-marker") options.analyzer.marker = value;
        else if (arg == "--scan-limit-bytes") options.analyzer.scan_limit = number(arg, value, 1, 1048576);
        else if (arg == "--analyzer-error-decision") options.decision.analyzer_error_allow = allow(arg, value);
        else if (arg == "--event") options.event = parse_permission_event(value);
        else if (arg == "--decision") options.decision.allow = allow(arg, value);
        else if (arg == "--run-for") options.seconds = number(arg, value, 1, 3600);
        else if (arg == "--decision-delay-ms")
            options.decision.delay = std::chrono::milliseconds(number(arg, value, 0, 60000));
        else if (arg == "--request-timeout-ms")
            options.decision.timeout = std::chrono::milliseconds(number(arg, value, 1, 60000));
        else if (arg == "--max-pending") options.decision.max_pending = number(arg, value, 1, 4096);
        else if (arg == "--timeout-decision") options.decision.timeout_allow = allow(arg, value);
        else if (arg == "--overload-decision") options.decision.overload_allow = allow(arg, value);
        else throw std::invalid_argument("Unknown option: " + std::string(arg));
    }
    if (options.path.empty() || !options.seconds)
        throw std::invalid_argument("Require --file and --run-for; use --help");
    options.decision.external = seen.count("--analyzer");
    if (options.decision.external) {
        if (!std::filesystem::path(options.analyzer.executable).is_absolute() ||
            options.analyzer.marker.empty() || options.analyzer.marker.size() > 256 ||
            seen.count("--decision") || seen.count("--decision-delay-ms"))
            throw std::invalid_argument("Analyzer requires an absolute executable and a 1..256 byte marker, without static decision/delay");
    } else if (!seen.count("--decision") || seen.count("--deny-marker") ||
               seen.count("--scan-limit-bytes") || seen.count("--analyzer-error-decision"))
        throw std::invalid_argument("Require a static decision or analyzer configuration; use --help");
    return true;
}
