// SPDX-License-Identifier: MIT
// Emits a draft declaration. Only the root-owned policy/reload path authorizes it.
#include "boot_clock.h"
#include "policy_config.h"
#include <charconv>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string_view>

namespace {
std::uint64_t number(const std::string &text, std::uint64_t low, std::uint64_t high)
{
    std::uint64_t result = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), result);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() || result < low || result > high)
        throw std::invalid_argument("Invalid numeric option");
    return result;
}
}
int main(int argc, char **argv)
{
    try {
        if (argc == 2 && std::string_view(argv[1]) == "--help") {
            std::cout << "Usage: secmon-vault-session --id N --program PATH --uid UID --target PATH\n"
                         "       --mode read|read-write --duration-ms 100..3600000\n"
                         "Print a boot-bound vault-session declaration; root policy reload activates it.\n"
                         "The absolute expiry starts now and survives service restarts.\n";
            return 0;
        }
        std::map<std::string, std::string> options;
        for (int i = 1; i < argc; ++i) {
            const std::string option(argv[i]);
            if (i + 1 == argc || (option != "--id" && option != "--program" && option != "--uid" &&
                option != "--target" && option != "--mode" && option != "--duration-ms") ||
                !options.emplace(option, argv[++i]).second)
                throw std::invalid_argument("Unknown, duplicate or incomplete option; use --help");
        }
        if (options.size() != 6) throw std::invalid_argument("All six options are required; use --help");
        if (options.at("--mode") != "read" && options.at("--mode") != "read-write")
            throw std::invalid_argument("Mode must be read or read-write");
        const auto id = number(options.at("--id"), 1, UINT64_MAX);
        const auto uid = number(options.at("--uid"), 0, UINT32_MAX - 1);
        const auto duration = number(options.at("--duration-ms"), 100, 3600000);
        std::ostringstream line;
        line << "vault-session " << id << ' ' << std::quoted(options.at("--program")) << ' ' << uid
             << ' ' << std::quoted(options.at("--target")) << ' ' << options.at("--mode") << ' ' << duration
             << ' ' << secmon_clock::boot_id() << ' ' << secmon_clock::global_boot_ns() << '\n';
        // Reuse the full policy grammar for paths, controls, quoting and modes.
        std::ostringstream draft;
        draft << "revision 1\nvault " << std::quoted(options.at("--target")) << '\n' << line.str();
        std::istringstream input(draft.str());
        (void)parse_policy(input);
        std::cout << line.str();
        if (!std::cout) throw std::runtime_error("Cannot write session declaration");
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "secmon-vault-session: " << error.what() << '\n';
        return 2;
    }
}
