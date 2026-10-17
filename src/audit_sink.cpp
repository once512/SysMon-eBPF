// SPDX-License-Identifier: MIT
// 只在 I/O 线程 write/poll；互斥锁仅保护队列元数据，等待输出期间不持锁。
// 普通文件的底层 I/O 仍可能受存储故障阻塞，但不会占用管理/fanotify 事件循环。
#include <utility>
#include "audit_sink.h"
#include "owned_fd.h"
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <fcntl.h>
#include <mutex>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdexcept>
#include <system_error>
#include <sys/socket.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

namespace {
[[noreturn]] void fail(const char *operation) { throw std::system_error(errno, std::generic_category(), operation); }
OwnedFd output_reference(int fd, bool &socket)
{
    struct stat info{};
    const int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fstat(fd, &info)) fail("inspect audit output");
    if ((flags & O_ACCMODE) == O_RDONLY || (flags & O_PATH)) throw std::runtime_error("Audit output must be writable");
    socket = S_ISSOCK(info.st_mode);
    if (socket || S_ISREG(info.st_mode)) {
        // socket 使用每次 send 的 DONTWAIT；普通文件在 I/O 线程写，不需要改 O_NONBLOCK。
        // 两者都 dup 原描述：保留普通文件共享偏移/O_APPEND/O_SYNC 等语义，绝不修改共享标志。
        OwnedFd copy(fcntl(fd, F_DUPFD_CLOEXEC, 3));
        if (copy.get() < 0) fail("duplicate audit socket");
        return copy;
    }
    // dup 后 F_SETFL 会连带改变父进程共享的 stdout 标志；通过 proc 创建独立描述，避免此副作用。
    const auto path = "/proc/self/fd/" + std::to_string(fd);
    OwnedFd copy(open(path.c_str(), O_WRONLY | O_NONBLOCK | O_CLOEXEC | (flags & O_APPEND)));
    if (copy.get() < 0) fail("open independent audit output");
    return copy;
}
}
struct AuditSink::State {
    struct Record { std::string bytes; std::size_t offset = 0; };
    const std::size_t record_limit, byte_limit;
    mutable std::mutex mutex;
    std::condition_variable changed;
    std::deque<Record> queue;
    std::size_t queued_bytes = 0;
    bool stopping = false;
    std::chrono::steady_clock::time_point deadline;
    bool socket = false;
    OwnedFd output;
    std::atomic<std::uint64_t> written{0}, dropped{0}, invalid{0};
    std::atomic<int> output_errno{0};
    std::thread writer; // 最后析构；显式 shutdown 必须在其余状态释放之前 join。

    State(int fd, std::size_t records, std::size_t bytes)
        : record_limit(records), byte_limit(bytes), output(output_reference(fd, socket)) {}

    void discard_locked()
    {
        dropped.fetch_add(queue.size(), std::memory_order_relaxed);
        queue.clear();
        queued_bytes = 0;
    }
    void run() noexcept
    {
        // 仅屏蔽本线程的 SIGPIPE；管道断开记录 EPIPE，不改变整个程序/分析器的信号处理合同。
        sigset_t blocked;
        sigemptyset(&blocked);
        sigaddset(&blocked, SIGPIPE);
        const int mask_error = pthread_sigmask(SIG_BLOCK, &blocked, nullptr);
        if (mask_error) {
            output_errno.store(mask_error);
            std::lock_guard<std::mutex> lock(mutex);
            discard_locked();
            return;
        }
        for (;;) {
            Record *record;
            {
                std::unique_lock<std::mutex> lock(mutex);
                changed.wait(lock, [&] { return stopping || !queue.empty(); });
                if (stopping && (queue.empty() || std::chrono::steady_clock::now() >= deadline)) {
                    discard_locked();
                    return;
                }
                // deque 尾部追加不使已有元素引用失效；生产者不修改本条内容，只有此线程在完成后弹出。
                record = &queue.front();
            }
            const auto *data = record->bytes.data() + record->offset;
            const auto size = record->bytes.size() - record->offset;
            const auto count = socket ? send(output.get(), data, size, MSG_DONTWAIT | MSG_NOSIGNAL) : write(output.get(), data, size);
            if (count > 0) {
                record->offset += static_cast<std::size_t>(count);
                if (record->offset == record->bytes.size()) {
                    std::lock_guard<std::mutex> lock(mutex);
                    queued_bytes -= record->bytes.size();
                    queue.pop_front();
                    written.fetch_add(1, std::memory_order_relaxed);
                }
                continue;
            }
            if (count < 0 && errno == EINTR) continue;
            if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                pollfd ready{output.get(), POLLOUT, 0};
                // 20ms 后检查退出期限；不在任何互斥锁下等待 FD。
                const int result = poll(&ready, 1, 20);
                if (result >= 0 || errno == EINTR) continue;
            }
            output_errno.store(count == 0 ? EIO : errno);
            std::lock_guard<std::mutex> lock(mutex);
            discard_locked();
            return; // 此出口永久离线；新记录由 enqueue 直接计入 dropped，安全模块继续运行。
        }
    }
};
AuditSink::AuditSink(int fd, std::size_t records, std::size_t bytes)
{
    if (!records || records > SECMON_AUDIT_MAX_RECORDS || !bytes || bytes > SECMON_AUDIT_MAX_BYTES)
        throw std::invalid_argument("Invalid audit queue limits");
    state_ = std::make_unique<State>(fd, records, bytes);
    state_->writer = std::thread([state = state_.get()] { state->run(); });
}
AuditSink::~AuditSink() { shutdown(); }
bool AuditSink::enqueue(std::string record) noexcept
{
    try {
        std::lock_guard<std::mutex> lock(state_->mutex);
        if (state_->stopping || state_->output_errno.load() || record.empty() || record.size() > SECMON_AUDIT_MAX_LINE_BYTES ||
            state_->queue.size() >= state_->record_limit || record.size() > state_->byte_limit - state_->queued_bytes) {
            note_drop();
            return false;
        }
        state_->queue.push_back({std::move(record), 0});
        state_->queued_bytes += state_->queue.back().bytes.size();
        state_->changed.notify_one();
        return true;
    } catch (...) {
        note_drop(); // 队列分配失败不向 C 回调抛异常，不把审计资源不足变成安全模块退出。
        return false;
    }
}
void AuditSink::note_invalid() noexcept { state_->invalid.fetch_add(1, std::memory_order_relaxed); }
void AuditSink::note_drop() noexcept { state_->dropped.fetch_add(1, std::memory_order_relaxed); }
AuditStats AuditSink::stats() const
{
    std::lock_guard<std::mutex> lock(state_->mutex);
    return {state_->written.load(), state_->dropped.load(), state_->invalid.load(),
            static_cast<std::uint32_t>(state_->queue.size()), state_->output_errno.load()};
}
void AuditSink::shutdown()
{
    if (!state_ || !state_->writer.joinable()) return;
    {
        std::lock_guard<std::mutex> lock(state_->mutex);
        state_->stopping = true;
        state_->deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(200);
    }
    state_->changed.notify_one();
    state_->writer.join();
}
