// SPDX-License-Identifier: MIT
// 真实堵塞/断开管道验证 cerr 适配器，底层队列的文件/socket 语义另由 audit_sink 测试覆盖。
#include "diagnostic_output.h"
#include "owned_fd.h"
#include <cerrno>
#include <atomic>
#include <chrono>
#include <fcntl.h>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <unistd.h>
using namespace std::chrono_literals;
void require(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
struct Pipe {
    OwnedFd input, output;
    Pipe() {
        int fds[2];
        require(!pipe2(fds, O_CLOEXEC | O_NONBLOCK), "pipe2");
        input = OwnedFd(fds[0]); output = OwnedFd(fds[1]);
        require(fcntl(output.get(), F_SETPIPE_SZ, 4096) == 4096, "pipe capacity");
    }
    void fill() {
        const std::string filler(4096, 'X');
        require(write(output.get(), filler.data(), filler.size()) == 4096, "fill pipe");
        const int flags = fcntl(output.get(), F_GETFL);
        require(!fcntl(output.get(), F_SETFL, flags & ~O_NONBLOCK), "blocking inherited stderr");
    }
    std::string drain() {
        std::string result;
        char bytes[8192];
        for (;;) {
            const auto count = read(input.get(), bytes, sizeof(bytes));
            if (count < 0) { require(errno == EAGAIN, "drain pipe"); return result; }
            if (!count) return result;
            result.append(bytes, static_cast<std::size_t>(count));
        }
    }
};
int main()
{
    auto *const previous = std::cerr.rdbuf();
    auto *const tie = std::cerr.tie();
    {
        Pipe pipe;
        {
            DiagnosticOutput output(pipe.output.get());
            std::cerr << "partial" << std::flush;
            require(output.stats().queued == 0 && output.stats().written == 0, "flush must not submit incomplete fragments");
            std::cerr << " line\nnext\n";
            const auto deadline = std::chrono::steady_clock::now() + 1s;
            while (output.stats().written < 2 && std::chrono::steady_clock::now() < deadline) std::this_thread::yield();
            require(output.stats().written == 2, "complete diagnostic lines drain");
            require(pipe.drain() == "partial line\nnext\n", "fragments assemble in order");
            std::cerr << std::string(SECMON_DIAGNOSTIC_MAX_LINE_BYTES, 'L') << "more fragments\nvalid\n";
            const auto stats = output.stats();
            require(stats.invalid == 1 && stats.dropped == 1, "whole oversized line discarded once");
        }
        require(pipe.drain() == "valid\n", "oversized line cannot leak truncated fragments");
        require(std::cerr.rdbuf() == previous && std::cerr.tie() == tie, "restore stream and tie");
    }
    {
        Pipe pipe;
        pipe.fill();
        const int flags = fcntl(pipe.output.get(), F_GETFL);
        const auto started = std::chrono::steady_clock::now();
        {
            DiagnosticOutput output(pipe.output.get());
            require(fcntl(pipe.output.get(), F_GETFL) == flags, "inherited blocking flags preserved");
            for (unsigned i = 0; i < 5000; ++i) std::cerr << "reload rejected\n";
            auto stats = output.stats();
            require(stats.queued == 256 && stats.dropped == 4744 && stats.written == 0, "independent diagnostic budget");
            require(std::chrono::steady_clock::now() - started < 1s, "production never waits for stderr");
        }
        require(std::chrono::steady_clock::now() - started < 2s, "blocked diagnostic teardown bounded");
    }
    {
        Pipe pipe;
        pipe.fill();
        DiagnosticOutput output(pipe.output.get());
        const std::string line = std::string(SECMON_DIAGNOSTIC_MAX_LINE_BYTES - 1, 'B') + '\n';
        for (unsigned i = 0; i < 65; ++i) std::cerr << line;
        const auto stats = output.stats();
        require(stats.queued == 64 && stats.dropped == 1 && stats.invalid == 0, "byte budget bounds maximum-size lines before record budget");
    }
    {
        Pipe pipe;
        { DiagnosticOutput output(pipe.output.get()); std::cerr << "final fragment"; }
        require(pipe.drain() == "final fragment\n", "teardown terminates trailing fragment");
    }
    {
        Pipe pipe;
        pipe.fill();
        DiagnosticOutput output(pipe.output.get());
        for (unsigned i = 0; i < 500; ++i) std::cerr << "recover\n";
        // 只读启动填充的确切字节数；读到 EAGAIN 会与恢复中的写线程竞争，误吞后续记录。
        char filler[4096];
        require(read(pipe.input.get(), filler, sizeof(filler)) == 4096 &&
                std::string(filler, sizeof(filler)) == std::string(4096, 'X'), "remove filler");
        const auto deadline = std::chrono::steady_clock::now() + 1s;
        while (output.stats().queued && std::chrono::steady_clock::now() < deadline) std::this_thread::yield();
        const auto stats = output.stats();
        require(stats.written == 256 && stats.dropped == 244 && stats.output_errno == 0, "drain after diagnostic recovery");
        require(pipe.drain().size() == 256 * 8, "complete queued lines after recovery");
    }
    {
        OwnedFd null(open("/dev/null", O_WRONLY | O_CLOEXEC));
        require(null.get() >= 0, "null diagnostics");
        DiagnosticOutput output(null.get());
        std::atomic<bool> done{false};
        const std::string oversized(SECMON_DIAGNOSTIC_MAX_LINE_BYTES + 1, 'X');
        std::thread producer([&] {
            for (unsigned i = 0; i < 10000; ++i) std::cerr << oversized << '\n';
            done.store(true);
        });
        bool consistent = true;
        while (!done.load()) {
            const auto stats = output.stats();
            if (stats.invalid != stats.dropped || stats.queued || stats.written) consistent = false;
            std::this_thread::yield();
        }
        producer.join();
        const auto stats = output.stats();
        require(consistent && stats.invalid == 10000 && stats.dropped == 10000,
                "concurrent oversized diagnostics have coherent invalid/drop snapshots");
    }
    {
        Pipe pipe;
        DiagnosticOutput output(pipe.output.get());
        pipe.input = OwnedFd();
        std::cerr << "closed peer\n";
        const auto deadline = std::chrono::steady_clock::now() + 1s;
        while (std::chrono::steady_clock::now() < deadline) {
            const auto observed = output.stats();
            if (observed.output_errno && !observed.queued) break;
            std::this_thread::yield();
        }
        std::cerr << "still alive\n";
        const auto stats = output.stats();
        require(stats.output_errno == EPIPE && stats.dropped == 2, "diagnostic EPIPE does not signal service");
    }
    std::cout << "PASS bounded diagnostic lines, independent queue, pipe recovery, EPIPE and teardown\n";
}
