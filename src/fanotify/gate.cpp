// SPDX-License-Identifier: MIT
// fanotify 权限事件会挂起请求方：读取事件得到 FD，向同一 group 写 fanotify_response 才作出裁决。
// 这不同于只观察事件的通知接口；close 事件 FD 本身不等同于发送拒绝，关闭整个 group 会释放未决请求。
#include "gate.h"
#include "management/protocol.h"
#include <algorithm>
#include <utility>
#include <cerrno>
#include <fcntl.h>
#include <poll.h>
#include <stdexcept>
#include <system_error>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {
[[noreturn]] void fail(const char *operation)
{
    throw std::system_error(errno, std::generic_category(), operation);
}
int pin_file(const std::string &path)
{
    int fd = open(path.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) fail("pin fanotify target");
    struct stat st{};
    if (fstat(fd, &st)) {
        const int saved = errno;
        close(fd);
        errno = saved;
        fail("stat fanotify target");
    }
    if (!S_ISREG(st.st_mode)) {
        close(fd);
        throw std::runtime_error("fanotify target must be an existing regular file, not a symlink");
    }
    return fd;
}
int create_group()
{
    // FAN_CLASS_CONTENT 支持权限裁决；NONBLOCK 只让监听端读取不阻塞，请求方仍等待裁决。
    // 第二组参数指定事件 FD 的打开方式：只读/CLOEXEC；不是把被监控业务的打开模式改成只读。
    // group 是 fanotify_init 返回的监听 FD；mark 是附着到 inode 的订阅，两者不是同一个对象。
    int fd = fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK,
                          O_RDONLY | O_LARGEFILE | O_CLOEXEC);
    if (fd < 0) fail("fanotify_init (requires CAP_SYS_ADMIN and permission-event support)");
    return fd;
}
}

PermissionGate::PermissionGate(const std::string &path, DecisionConfig config, PermissionEvent event,
                               const AnalyzerConfig &analyzer, const std::string &policy_path)
    : analyzer_(config.external ? std::make_unique<AnalysisClient>(analyzer) : nullptr), target_(pin_file(path)), group_(create_group()), mask_(permission_mask(event)),
      pending_(config, [this](int fd, Verdict verdict) { respond(fd, verdict); })
{
    if (!policy_path.empty()) {
        OwnedFd policy(open(policy_path.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC));
        struct stat source{}, target{};
        if (policy.get() < 0 || fstat(policy.get(), &source) || fstat(target_.get(), &target))
            throw std::runtime_error("Cannot inspect fanotify policy identity");
        if (source.st_dev == target.st_dev && source.st_ino == target.st_ino)
            throw std::runtime_error("Fanotify policy file cannot be the marked inode");
    }
    // Follow the pinned FD rather than resolving the user's path a second time.
    const auto pinned = "/proc/self/fd/" + std::to_string(target_.get());
    // mark 选中固定的对象与事件类型，不是目录递归规则；通过 /proc/self/fd 引用避免再次解析目标路径。
    if (fanotify_mark(group_.get(), FAN_MARK_ADD, mask_,
                      AT_FDCWD, pinned.c_str())) fail("fanotify_mark permission event");
}

bool PermissionGate::poll_once(int timeout_ms)
{
    service_analysis();
    // 同时等待内核事件与分析结果，不能在这里同步读取大文件，否则整个权限服务会被一个分析拖住。
    pollfd ready[] = {{group_.get(), POLLIN, 0}, {analyzer_ ? analyzer_->fd() : -1, POLLIN, 0}};
    const int wait_ms = pending_.poll_timeout(timeout_ms, PendingDecisions::Clock::now());
    const int result = poll(ready, 2, wait_ms);
    if (result < 0) {
        if (errno == EINTR) return false;
        fail("fanotify poll");
    }
    if (!result) {
        service_analysis();
        return false;
    }
    service_analysis();
    if (ready[0].revents & (POLLERR | POLLHUP | POLLNVAL))
        throw std::runtime_error("fanotify poll reported an unusable group");
    if (!(ready[0].revents & POLLIN)) return false;
    // No FAN_REPORT_* flags: the kernel returns fixed-size metadata records.
    // Read one record so an exception cannot strand FDs from an unread batch.
    fanotify_event_metadata event{};
    // 一次只接收一个 metadata，立即用 OwnedFd 接管 event.fd，避免批量读取中途抛错遗留其他 FD。
    const auto size = read(group_.get(), &event, sizeof(event));
    if (size < 0) {
        if (errno == EAGAIN || errno == EINTR) return false;
        fail("fanotify read");
    }
    if (size != sizeof(event)) throw std::runtime_error("Short fanotify metadata record");
    OwnedFd event_fd(event.fd);
    if (event.vers != FANOTIFY_METADATA_VERSION || event.event_len != sizeof(event) ||
        event.metadata_len != sizeof(event))
        throw std::runtime_error("Unexpected fanotify metadata ABI");
    // 内核队列溢出意味着监控覆盖不完整，选择报错关闭；不要把它当成用户态 max_pending 容量回退。
    if (event.mask & FAN_Q_OVERFLOW) {
        ++stats_.overflow;
        // Stop visibly rather than presenting incomplete coverage as healthy.
        throw std::runtime_error("fanotify queue overflow; closing group releases pending requests");
    }
    if (event.fd < 0 || event.mask != mask_)
        throw std::runtime_error("Unexpected fanotify permission event");
    pending_.submit(std::move(event_fd), PendingDecisions::Clock::now());
    stats_.peak_pending = std::max(stats_.peak_pending, pending_.size());
    service_analysis();
    return true;
}

void PermissionGate::respond(int fd, Verdict verdict)
{
    // 回复用的是当前事件 FD，而不是业务进程 PID；写入 group 成功后，队列才会关闭对应事件 FD。
    fanotify_response response{fd, static_cast<unsigned int>(verdict.allow ? FAN_ALLOW : FAN_DENY)};
    ssize_t written;
    do { written = write(group_.get(), &response, sizeof(response)); }
    while (written < 0 && errno == EINTR);
    if (written < 0) fail("fanotify permission response");
    if (written != sizeof(response)) throw std::runtime_error("Short fanotify response");
    if (verdict.allow) ++stats_.allowed;
    else ++stats_.denied;
    switch (verdict.reason) {
    case DecisionReason::timeout: ++stats_.timed_out; break;
    case DecisionReason::capacity: ++stats_.overloaded; break;
    case DecisionReason::shutdown: ++stats_.shutdown_denied; break;
    case DecisionReason::policy: break;
    case DecisionReason::analysis:
        ++stats_.analyzed;
        if (!verdict.allow) ++stats_.analysis_denied;
        break;
    case DecisionReason::analyzer_error: ++stats_.analyzer_error; break;
    }
}

void PermissionGate::service_analysis()
{
    pending_.process_due(PendingDecisions::Clock::now());
    if (!analyzer_) return;
    if (!analyzer_->online()) {
        analyzer_->receive(); // Reap a previously killed child without blocking.
        pending_.fail_analysis();
        return;
    }
    // Timeouts win over a late reply, and the worker's duplicate FD must not
    // survive indefinitely after the parent releases the original event FD.
    // 宿主超时移除了请求，但工作进程仍可能持有它的重复 FD；终止工作进程，避免请求对象长期残留。
    if (analyzer_->active() && !pending_.contains(analyzer_->active())) {
        analyzer_->stop();
        ++stats_.analyzer_failures;
        pending_.fail_analysis();
        return;
    }
    std::optional<analysis::Response> response;
    try { response = analyzer_->receive(); }
    catch (const std::exception &) {
        analyzer_->stop();
        ++stats_.analyzer_failures;
        pending_.fail_analysis();
        return;
    }
    // 队列完成前再次按当前单调时间检查超时，迟到的 allow 不能覆盖已经生效的超时回退。
    if (response)
        pending_.complete(response->id, response->result == analysis::Result::allow,
                          response->result == analysis::Result::error, PendingDecisions::Clock::now());
    if (!analyzer_->active()) {
        auto request = pending_.next_request();
        if (request) {
            try { analyzer_->submit(request->id, request->fd); }
            catch (const std::exception &) {
                analyzer_->stop();
                ++stats_.analyzer_failures;
                pending_.fail_analysis();
            }
        }
    }
}

void PermissionGate::reconfigure(DecisionConfig config)
{
    // Do not service/expire old requests as a side effect of a rejected update.
    if (analyzer_ && analyzer_->active())
        throw management::Error(management::Code::busy, "Policy reload requires an idle analyzer; retry later");
    pending_.reconfigure(config);
}
