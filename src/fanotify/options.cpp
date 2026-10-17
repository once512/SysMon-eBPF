// SPDX-License-Identifier: MIT
#include "options.h"
#include <charconv>
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
        std::cout << "Usage: secmon-fanotify --file PATH --decision allow|deny --run-for SECONDS\n"
                     "Optional deferred-decision experiment:\n"
                     "  --decision-delay-ms 0..60000     (default 0; synthetic analysis delay)\n"
                     "  --request-timeout-ms 1..60000    (default 250; starts on event receipt)\n"
                     "  --max-pending 1..4096            (default 64; delivered events only)\n"
                     "  --timeout-decision allow|deny    (default deny)\n"
                     "  --overload-decision allow|deny   (default deny)\n"
                     "Single-inode FAN_OPEN_PERM experiment; requires CAP_SYS_ADMIN.\n"
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
    if (options.path.empty() || !seen.count("--decision") || !options.seconds)
        throw std::invalid_argument("Require --file, --decision allow|deny and --run-for; use --help");
    return true;
}
