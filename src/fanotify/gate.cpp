// SPDX-License-Identifier: MIT
// fanotify 权限事件会挂起请求方：读取事件得到 FD，向同一 group 写 fanotify_response 才作出裁决。
// 这不同于只观察事件的通知接口；close 事件 FD 本身不等同于发送拒绝，关闭整个 group 会释放未决请求。
#include "gate.h"
#include "cached_inode.h"
#include "writer_identity.h"
#include "metadata.h"
#include <array>
#include "audit_sink.h"
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
#include <sys/sysmacros.h>
#include <secmon/policy_limits.h>
#include <set>
#include <unistd.h>

namespace {
[[noreturn]] void fail(const char *operation)
{
    throw std::system_error(errno, std::generic_category(), operation);
}
int pin_file(const std::string &path)
{
    return pin_policy_file(path, false).fd.release();
}
std::vector<OwnedFd> pin_targets(const std::vector<std::string> &paths, const std::string &policy_path,
                               const std::vector<std::pair<std::string, int>> &retained)
{
    if (paths.empty() || paths.size() > SECMON_MAX_FANOTIFY_TARGETS)
        throw std::invalid_argument("Fanotify requires 1..64 targets");
    OwnedFd policy;
    struct stat source{};
    if (!policy_path.empty()) {
        policy = OwnedFd(open(policy_path.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC));
        if (policy.get() < 0 || fstat(policy.get(), &source)) fail("inspect fanotify policy");
    }
    std::set<std::pair<dev_t, ino_t>> identities;
    std::vector<OwnedFd> targets;
    targets.reserve(paths.size());
    for (const auto &path : paths) {
        const auto previous = std::find_if(retained.begin(), retained.end(), [&](const auto &binding) {
            return binding.first == path;
        });
        OwnedFd target(previous == retained.end() ? pin_file(path) : fcntl(previous->second, F_DUPFD_CLOEXEC, 0));
        if (target.get() < 0) fail("duplicate retained fanotify target");
        struct stat value{};
        if (cached_inode_stat(target.get(), &value)) fail("stat pinned fanotify target");
        if (!S_ISREG(value.st_mode)) throw std::invalid_argument("Fanotify target must remain a regular file");
        if (!identities.emplace(value.st_dev, value.st_ino).second)
            throw std::invalid_argument("Duplicate fanotify inode, including hard links");
        if (policy.get() >= 0 && source.st_dev == value.st_dev && source.st_ino == value.st_ino)
            throw std::invalid_argument("Fanotify policy file cannot be a marked inode");
        targets.push_back(std::move(target));
    }
    return targets;
}
// group FD 是监听/回复通道；
// 事件 FD 是具体文件对象引用，不能把两者互换传给分析器。
int create_group(bool requester_pidfd)
{
    // FAN_CLASS_CONTENT 支持权限裁决；NONBLOCK 只让监听端读取不阻塞，请求方仍等待裁决。
    // 第二组参数指定事件 FD 的打开方式：只读/CLOEXEC；不是把被监控业务的打开模式改成只读。
    // group 是 fanotify_init 返回的监听 FD；mark 是附着到 inode 的订阅，两者不是同一个对象。
    int fd = fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK | (requester_pidfd ? FAN_REPORT_PIDFD : 0),
                          O_RDONLY | O_LARGEFILE | O_CLOEXEC);
    if (fd < 0) fail("fanotify_init (requires CAP_SYS_ADMIN and permission-event support)");
    return fd;
}
}

PermissionGate::PermissionGate(const std::vector<std::string> &paths, DecisionConfig config, PermissionEvent event,
                               const AnalyzerConfig &analyzer, const std::string &policy_path,
                               AuditSink *audit, std::uint64_t instance_ns, std::uint64_t revision, bool requester_pidfd,
                               std::uint64_t *request_sequence,
                               const std::vector<std::pair<std::string, int>> &retained,
                               std::uint64_t subscription_generation)
    : analyzer_(config.external ? std::make_unique<AnalysisClient>(analyzer) : nullptr), targets_(pin_targets(paths, policy_path, retained)), group_(create_group(requester_pidfd)), mask_(permission_mask(event)), requester_pidfd_(requester_pidfd),
      audit_(audit), revision_(revision),
      pending_(config, [this](int fd, const PermissionRequest &request, Verdict verdict) { respond(fd, request, verdict); }, request_sequence)
{
    if (!subscription_generation) throw std::invalid_argument("Subscription generation exhausted");
    if (audit_) {
        struct stat pid_namespace{};
        // Cache the group creator's PID namespace once, never look up requesters by numeric PID.
        if (stat("/proc/self/ns/pid", &pid_namespace)) fail("stat permission audit PID namespace");
        audit_identity_ = {instance_ns, getpid(), 0, 0, 0, event, pid_namespace.st_ino};
    }
    audit_identity_.subscription_generation = subscription_generation;
    // 配置若就是被标记对象，重载读取它会等待本监听器给自己裁决；
    // 必须在添加 mark 前排除。
    // Follow the pinned FD rather than resolving the user's path a second time.
    objects_.reserve(targets_.size());
    target_fds_.reserve(targets_.size());
    for (const auto &target : targets_) {
        struct stat value{};
        if (cached_inode_stat(target.get(), &value)) fail("stat fanotify target");
        objects_.push_back({major(value.st_dev), minor(value.st_dev), value.st_ino});
        target_fds_.push_back(target.get());
        const auto pinned = "/proc/self/fd/" + std::to_string(target.get());
        // Any failure destroys the entire group, releasing all earlier marks.
        if (fanotify_mark(group_.get(), FAN_MARK_ADD, mask_, AT_FDCWD, pinned.c_str()))
            fail("fanotify_mark permission event");
    }
    if (!analyzer_) reader_ = std::make_unique<EventReader>(group_.get(), requester_pidfd_);
}

bool PermissionGate::poll_once(int timeout_ms)
{
    service_analysis();
    if (reader_) reader_->flush();
    // 同时等待内核事件与分析结果，不能在这里同步读取大文件，否则整个权限服务会被一个分析拖住。
    pollfd ready[] = {{reader_ ? reader_->fd() : group_.get(), POLLIN, 0}, {analyzer_ ? analyzer_->fd() : -1, POLLIN, 0}};
    const int wait_ms = pending_.poll_timeout(timeout_ms, PendingDecisions::Clock::now());
    // 分析器 channel 与 fanotify group 一起等待；
    // 队列给出的更短截止时间防止 poll 阻塞过头。
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
    const auto received = PendingDecisions::Clock::now();
    PermissionMetadata event;
    PermissionObject object{};
    if (reader_) {
        auto delivered = reader_->receive();
        if (!delivered) return false;
        event = std::move(delivered->metadata); object = delivered->object;
    } else {
        std::array<char, sizeof(fanotify_event_metadata) + sizeof(fanotify_event_info_pidfd)> buffer{};
        const auto size = read(group_.get(), buffer.data(), buffer.size());
        if (size < 0) {
            if (errno == EAGAIN || errno == EINTR) return false;
            fail("fanotify read");
        }
        event = decode_permission_metadata(buffer.data(), static_cast<std::size_t>(size), requester_pidfd_);
        if (event.file.get() >= 0) {
            struct stat value{};
            if (cached_inode_stat(event.file.get(), &value)) fail("stat permission event target");
            object = {major(value.st_dev), minor(value.st_dev), value.st_ino};
        }
    }
    if (event.mask & FAN_Q_OVERFLOW) {
        ++stats_.overflow;
        throw std::runtime_error("fanotify queue overflow; closing group releases pending requests");
    }
    if (event.file.get() < 0 || event.mask != mask_)
        throw std::runtime_error("Unexpected fanotify permission event");
    const auto event_object = object;
    const auto found = std::find_if(objects_.begin(), objects_.end(), [&](const auto &object) {
        return object.major == event_object.major && object.minor == event_object.minor && object.inode == event_object.inode;
    });
    if (found == objects_.end()) throw std::runtime_error("Unmarked permission event target");
    pending_.submit(std::move(event.file), received, event.pid, revision_, std::move(event.requester), *found);
    stats_.peak_pending = std::max(stats_.peak_pending, pending_.size());
    service_analysis();
    return true;
}

void PermissionGate::respond(int fd, const PermissionRequest &request, Verdict verdict)
{
    // 回复用的是当前事件 FD，而不是业务进程 PID；写入 group 成功后，队列才会关闭对应事件 FD。
    fanotify_response response{reader_ ? reader_->kernel_fd(fd) : fd, static_cast<unsigned int>(verdict.allow ? FAN_ALLOW : FAN_DENY)};
    ssize_t written;
    do { written = write(group_.get(), &response, sizeof(response)); }
    while (written < 0 && errno == EINTR);
    if (written < 0) fail("fanotify permission response");
    if (written != sizeof(response)) throw std::runtime_error("Short fanotify response");
    if (reader_) reader_->release(fd);
    const auto responded = PendingDecisions::Clock::now();
    if (audit_) {
        try {
            auto identity = audit_identity_;
            identity.major = request.object.major;
            identity.minor = request.object.minor;
            identity.inode = request.object.inode;
            audit_->enqueue(format_permission_decision(identity, request, verdict, responded));
        }
        catch (...) { audit_->note_drop(); } // 审计失败不能把已成功的内核回复变成重试或退出。
    }
    if (verdict.allow) ++stats_.allowed;
    else ++stats_.denied;
    // allowed/denied 统计实际回复总量；
    // 下面的 reason 是同一批回复的分类，不能再累加成额外请求数。
    switch (verdict.reason) {
    case DecisionReason::timeout: ++stats_.timed_out; break;
    case DecisionReason::capacity: ++stats_.overloaded; break;
    case DecisionReason::shutdown: ++stats_.shutdown_denied; break;
    case DecisionReason::policy: break;
    case DecisionReason::analysis:
        ++stats_.analyzed;
        if (!verdict.allow) ++stats_.analysis_denied;
        break;
    case DecisionReason::analyzer_error:
        ++stats_.analyzer_error;
        if (verdict.scan_error == analysis::ScanError::none) ++stats_.backend_error_requests;
        else {
            ++stats_.scan_errors[static_cast<std::size_t>(verdict.scan_error)];
            stats_.last_scan_error = verdict.scan_error;
            stats_.last_scan_errno = verdict.scan_errno;
        }
        break;
    }
}

void PermissionGate::service_analysis()
{
    pending_.process_due(PendingDecisions::Clock::now());
    if (!analyzer_) return;
    // 离线是已观测通道状态，不会自动重启；
    // receive 在这里仅尝试非阻塞回收先前停止的子进程。
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
                          response->result == analysis::Result::error, PendingDecisions::Clock::now(), response->error, response->system_errno);
    // 同一时刻最多向一个工作进程派发一个请求；
    // 未派发的条目仍排队并受各自接收时间的超时约束。
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

void PermissionGate::validate_reconfigure(DecisionConfig config) const
{
    // Do not service/expire old requests as a side effect of a rejected update.
    if (analyzer_ && analyzer_->active())
        throw management::Error(management::Code::busy, "Policy reload requires an idle analyzer; retry later");
    pending_.validate_reconfigure(config);
}
void PermissionGate::reconfigure(DecisionConfig config)
{
    validate_reconfigure(config);
    commit_reconfigure(config, revision_);
}

void PermissionGate::shutdown()
{
    pending_.shutdown();
    // close group 立即释放仍在内核队列的等待；统计渲染和分析器退出不能推迟这个资源边界。
    if (reader_) reader_->stop();
    group_ = OwnedFd();
    if (analyzer_) analyzer_->stop();
}

PermissionGate::~PermissionGate()
{
    if (reader_) reader_->stop();
}
