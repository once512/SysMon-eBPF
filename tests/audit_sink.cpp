// SPDX-License-Identifier: MIT
// 无特权验证真实管道/文件出口：背压下队列有界、退出有限等待、断开不触发进程 SIGPIPE、原 FD 标志不变。
#include "audit_sink.h"
#include "owned_fd.h"
#include <cerrno>
#include <chrono>
#include <atomic>
#include <vector>
#include <fcntl.h>
#include <stdexcept>
#include <string>
#include <thread>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
using namespace std::chrono_literals;
void require(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
struct Pipe {
    OwnedFd read, write;
    Pipe() {
        int fds[2];
        require(!pipe2(fds, O_CLOEXEC), "pipe2");
        read = OwnedFd(fds[0]); write = OwnedFd(fds[1]);
    }
    std::size_t fill() {
        const int flags = fcntl(write.get(), F_GETFL);
        require(!fcntl(write.get(), F_SETFL, flags | O_NONBLOCK), "fill flags");
        const std::string bytes(4096, 'P');
        std::size_t total = 0;
        for (;;) {
            const auto count = ::write(write.get(), bytes.data(), bytes.size());
            if (count < 0) { require(errno == EAGAIN, "fill pipe"); break; }
            total += static_cast<std::size_t>(count);
        }
        require(!fcntl(write.get(), F_SETFL, flags), "restore pipe flags");
        return total;
    }
};
int main()
{
    {
        Pipe pipe;
        const auto filled = pipe.fill();
        const auto original = fcntl(pipe.write.get(), F_GETFL);
        AuditSink sink(pipe.write.get(), 2, 64);
        require(fcntl(pipe.write.get(), F_GETFL) == original, "must not modify inherited OFD flags");
        require(sink.enqueue("{}\n") && sink.enqueue("{}\n") && !sink.enqueue("{}\n"), "bounded admission");
        auto stats = sink.stats();
        require(stats.queued == 2 && stats.dropped == 1 && !stats.written, "full queue accounting");
        std::string bytes(filled, '\0');
        std::size_t received = 0;
        while (received < filled) {
            const auto count = ::read(pipe.read.get(), bytes.data() + received, filled - received);
            require(count > 0, "drain filler");
            received += static_cast<std::size_t>(count);
        }
        sink.shutdown();
        stats = sink.stats();
        require(stats.written == 2 && stats.dropped == 1 && !stats.queued && !stats.output_errno, "drain after recovery");
        char records[6];
        require(::read(pipe.read.get(), records, sizeof(records)) == 6 && std::string(records, 6) == "{}\n{}\n", "complete lines after recovery");
    }
    {
        Pipe pipe;
        pipe.fill();
        AuditSink sink(pipe.write.get(), 2, 64);
        require(sink.enqueue("{}\n") && sink.enqueue("{}\n"), "enqueue before shutdown");
        const auto started = std::chrono::steady_clock::now();
        sink.shutdown();
        require(std::chrono::steady_clock::now() - started < 1s, "blocked pipe shutdown bounded");
        const auto stats = sink.stats();
        require(stats.dropped == 2 && !stats.queued && !stats.written, "shutdown drops pending records");
    }
    {
        Pipe pipe;
        AuditSink sink(pipe.write.get(), 2, 64);
        pipe.read = OwnedFd();
        require(sink.enqueue("{}\n"), "queue before peer failure");
        const auto deadline = std::chrono::steady_clock::now() + 1s;
        while (!sink.stats().output_errno && std::chrono::steady_clock::now() < deadline) std::this_thread::yield();
        sink.shutdown();
        auto stats = sink.stats();
        require(stats.output_errno == EPIPE && stats.dropped == 1 && !stats.written, "broken peer accounting and SIGPIPE isolation");
        require(!sink.enqueue("{}\n") && sink.stats().dropped == 2, "offline sink rejects new records");
    }
    {
        char path[] = "/tmp/secmon-audit-unit-XXXXXX";
        OwnedFd file(mkstemp(path));
        require(file.get() >= 0, "mkstemp");
        unlink(path);
        require(::write(file.get(), "prefix", 6) == 6 && lseek(file.get(), 3, SEEK_SET) == 3, "regular position setup");
        AuditSink sink(file.get());
        require(sink.enqueue("X\n"), "regular queue");
        sink.shutdown();
        char bytes[6];
        require(pread(file.get(), bytes, 6, 0) == 6 && std::string(bytes, 6) == "preX\nx", "regular output starts at current shared offset");
        require(lseek(file.get(), 0, SEEK_CUR) == 5, "regular shared offset advances normally");
    }
    {
        int sockets[2];
        require(!socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets), "socketpair");
        OwnedFd output(sockets[0]), input(sockets[1]);
        const int flags = fcntl(output.get(), F_GETFL);
        AuditSink sink(output.get());
        require(sink.enqueue("{}\n"), "socket enqueue");
        sink.shutdown();
        char bytes[3];
        require(recv(input.get(), bytes, sizeof(bytes), MSG_DONTWAIT) == 3 && std::string(bytes, 3) == "{}\n", "socket output");
        require(fcntl(output.get(), F_GETFL) == flags, "socket OFD flags unchanged");
    }
    {
        char path[] = "/tmp/secmon-audit-append-XXXXXX";
        OwnedFd file(mkstemp(path));
        require(file.get() >= 0, "append mkstemp");
        unlink(path);
        require(::write(file.get(), "prefix", 6) == 6 && lseek(file.get(), 0, SEEK_SET) == 0, "append setup");
        const int flags = fcntl(file.get(), F_GETFL);
        require(!fcntl(file.get(), F_SETFL, flags | O_APPEND), "append flag");
        AuditSink sink(file.get());
        require(sink.enqueue("X\n"), "append queue");
        sink.shutdown();
        char bytes[8];
        require(pread(file.get(), bytes, 8, 0) == 8 && std::string(bytes, 8) == "prefixX\n", "preserve append semantics");
        require(lseek(file.get(), 0, SEEK_CUR) == 8, "append shared offset advances normally");
    }
    {
        OwnedFd null(open("/dev/null", O_WRONLY | O_CLOEXEC));
        require(null.get() >= 0, "null output");
        AuditSink sink(null.get());
        std::vector<std::thread> producers;
        std::atomic<unsigned> accepted{0};
        for (unsigned thread = 0; thread < 4; ++thread) producers.emplace_back([&] {
            for (unsigned record = 0; record < 2000; ++record)
                if (sink.enqueue("{}\n")) accepted.fetch_add(1);
        });
        for (auto &producer : producers) producer.join();
        sink.shutdown();
        const auto stats = sink.stats();
        require(stats.written + stats.dropped == 8000 && !stats.queued && !stats.output_errno, "concurrent complete/drop accounting");
        require(stats.written <= accepted.load(), "only admitted records may be written");
    }
    std::cout << "PASS bounded audit queue, pipe recovery, nonblocking shutdown, EPIPE isolation and preserved output flags/position\n";
}
