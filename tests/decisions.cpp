// SPDX-License-Identifier: MIT
// 用可控时钟和真实 FD 验证裁决状态机，无需等待实际超时，也不依赖 fanotify 的内核调度时序。
#include "fanotify/decisions.h"
#include <cerrno>
#include <fcntl.h>
#include <iostream>
#include <stdexcept>
#include <utility>
#include <vector>
#include <limits>

namespace {
using Clock = PendingDecisions::Clock;
using namespace std::chrono_literals;
void require(bool condition, const char *message)
{
    if (!condition) throw std::runtime_error(message);
}
OwnedFd descriptor()
{
    int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (fd < 0) throw std::runtime_error("Cannot open test FD");
    return OwnedFd(fd);
}
bool closed(int fd)
{
    errno = 0;
    return fcntl(fd, F_GETFD) < 0 && errno == EBADF;
}
struct ReplyRecord { int fd; Verdict verdict; PermissionRequest request; };
}

int main()
{
    try {
        const auto start = Clock::time_point{};
        std::vector<ReplyRecord> replies;
        auto reply = [&](int fd, const PermissionRequest &request, Verdict verdict) {
            require(fcntl(fd, F_GETFD) >= 0, "Event FD must remain open through reply");
            replies.push_back({fd, verdict, request});
        };
        DecisionConfig config;
        config.allow = true;
        config.delay = 10ms;
        config.timeout = 20ms;
        config.max_pending = 2;
        {
            PendingDecisions queue(config, reply);
            auto fd = descriptor();
            const int raw = fd.get();
            queue.submit(std::move(fd), start, 123, 7, {}, {8, 9, 101});
            require(fd.get() == -1 && queue.size() == 1, "Submit must transfer FD ownership");
            require(queue.poll_timeout(100, start + 9500us) == 1, "Round fractional wait up");
            require(queue.poll_timeout(3, start) == 3, "Outer wait bound must hold");
            queue.process_due(start + 9ms);
            require(replies.empty(), "No early decision");
            queue.process_due(start + 10ms);
            require(replies.size() == 1 && replies.back().verdict.allow &&
                    replies.back().verdict.reason == DecisionReason::policy, "Policy decision due");
            require(queue.size() == 0 && closed(raw), "Successful reply releases FD exactly once");
            require(replies.back().request.object.major == 8 && replies.back().request.object.minor == 9 &&
                    replies.back().request.object.inode == 101, "Object identity survives deferred reply");
        }
        replies.clear();
        {
            PendingDecisions queue(config, reply);
            queue.submit(descriptor(), start);
            queue.process_due(start + 30ms);
            require(replies.size() == 1 && !replies[0].verdict.allow &&
                    replies[0].verdict.reason == DecisionReason::timeout, "Late wakeup must expire");
        }
        replies.clear();
        config.delay = 20ms;
        config.timeout_allow = true;
        {
            PendingDecisions queue(config, reply);
            queue.submit(descriptor(), start);
            queue.process_due(start + 20ms);
            require(replies.size() == 1 && replies[0].verdict.allow &&
                    replies[0].verdict.reason == DecisionReason::timeout, "Timeout wins equal timestamps");
        }
        replies.clear();
        config.timeout_allow = false;
        config.delay = 10ms;
        {
            PendingDecisions queue(config, reply);
            queue.submit(descriptor(), start, 101, 7);
            queue.submit(descriptor(), start + 1ms, 102, 7);
            auto overflow = descriptor();
            const int raw = overflow.get();
            queue.submit(std::move(overflow), start + 2ms, 103, 7);
            require(queue.size() == 2 && replies.size() == 1 && closed(raw), "Bound pending ownership");
            require(!replies[0].verdict.allow && replies[0].verdict.reason == DecisionReason::capacity,
                    "Capacity fallback must deny by default");
            require(replies[0].request.id == 3 && replies[0].request.requester_pid == 103 &&
                    replies[0].request.revision == 7 && replies[0].request.received == start + 2ms,
                    "Capacity reply retains unique ID, sender, receive time and revision");
            queue.process_due(start + 10ms);
            require(replies[1].request.id == 1 && replies[1].request.requester_pid == 101 && replies[1].request.revision == 7,
                    "Delayed reply retains original request context");
            require(queue.size() == 1 && replies.size() == 2, "FIFO timestamps stay independent");
            queue.shutdown();
            require(queue.size() == 0 && replies.size() == 3 && !replies[2].verdict.allow &&
                    replies[2].verdict.reason == DecisionReason::shutdown, "Graceful shutdown denies delivered event");
            require(replies[2].request.id == 2 && replies[2].request.requester_pid == 102 && replies[2].request.revision == 7,
                    "Shutdown reply retains the original pending request context");
            queue.shutdown();
            require(replies.size() == 3, "Shutdown is idempotent");
        }
        replies.clear();
        config.max_pending = 1;
        config.overload_allow = true;
        {
            PendingDecisions queue(config, reply);
            queue.submit(descriptor(), start);
            queue.submit(descriptor(), start + 1ms);
            require(replies.size() == 1 && replies[0].verdict.allow &&
                    replies[0].verdict.reason == DecisionReason::capacity, "Explicit allow on capacity exhaustion");
            // Due requests are processed before checking capacity for a new request.
            queue.submit(descriptor(), start + 10ms);
            require(queue.size() == 1 && replies.size() == 2 &&
                    replies.back().verdict.reason == DecisionReason::policy, "Free due slots before capacity check");
        }
        replies.clear();
        config.delay = 0ms;
        {
            PendingDecisions queue(config, reply);
            queue.submit(descriptor(), start);
            require(queue.size() == 0 && replies.size() == 1, "Immediate policy keeps no pending events");
        }
        int failed_fd = -1;
        {
            config.delay = 10ms;
            PendingDecisions queue(config, [](int, const PermissionRequest &, Verdict) { throw std::runtime_error("simulated write failure"); });
            auto fd = descriptor();
            failed_fd = fd.get();
            queue.submit(std::move(fd), start);
            bool failed = false;
            try { queue.process_due(start + 10ms); }
            catch (const std::runtime_error &) { failed = true; }
            require(failed && queue.size() == 1 && !closed(failed_fd), "Failed reply retains event ownership");
        }
        require(closed(failed_fd), "Exceptional destruction must close pending FD");
        {
            auto original = descriptor();
            int first = original.get();
            auto replacement = descriptor();
            int second = replacement.get();
            original = std::move(replacement);
            require(closed(first) && original.get() == second && replacement.get() == -1,
                    "Move assignment closes old FD and transfers new FD");
            OwnedFd transferred(std::move(original));
            require(original.get() == -1 && transferred.get() == second, "Move constructor transfers FD");
        }
        replies.clear();
        config.external = true;
        config.max_pending = 2;
        config.timeout = 20ms;
        config.delay = 0ms;
        {
            PendingDecisions queue(config, reply);
            queue.submit(descriptor(), start);
            auto first = queue.next_request();
            require(first.has_value() && replies.empty(), "External analysis must not use static delay/policy");
            queue.submit(descriptor(), start + 1ms);
            require(queue.complete(first->id, true, false, start + 10ms), "Accept current response ID");
            require(replies.back().verdict.reason == DecisionReason::analysis && replies.back().verdict.allow,
                    "External verdict controls policy response");
            require(!queue.complete(first->id, false, false, start + 10ms), "Duplicate reply must not affect next request");
            auto second = queue.next_request();
            require(second && second->id != first->id, "Request IDs remain distinct");
            require(!queue.complete(second->id, true, false, start + 21ms), "Expired external verdict must lose to timeout");
            require(replies.back().verdict.reason == DecisionReason::timeout, "Timeout reason is preserved");
            queue.submit(descriptor(), start + 22ms);
            queue.fail_analysis();
            require(queue.size() == 0 && !replies.back().verdict.allow &&
                    replies.back().verdict.reason == DecisionReason::analyzer_error, "Backend failure applies explicit fallback");
        }
        replies.clear();
        {
            DecisionConfig old;
            old.allow = true; old.delay = 10ms; old.timeout = 20ms;
            PendingDecisions queue(old, reply);
            queue.submit(descriptor(), start);
            DecisionConfig next = old; next.allow = false; next.delay = 0ms;
            bool busy = false;
            try { queue.reconfigure(next); } catch (const std::runtime_error &) { busy = true; }
            require(busy && queue.size() == 1 && replies.empty(), "Busy reload preserves pending contract");
            queue.process_due(start + 10ms);
            require(replies.size() == 1 && replies.back().verdict.allow, "Old request keeps old verdict and delay");
            // 仅准备成功后，若另一模块随后失败，本队列仍应采用旧规则。
            queue.validate_reconfigure(next);
            queue.submit(descriptor(), start + 11ms);
            queue.process_due(start + 21ms);
            require(replies.size() == 2 && replies.back().verdict.allow, "Preparation alone must not commit new verdict");
            queue.validate_reconfigure(next);
            queue.commit_reconfigure(next);
            queue.submit(descriptor(), start + 22ms);
            require(replies.size() == 3 && !replies.back().verdict.allow, "New request uses new policy");
            next.external = true;
            bool backend = false;
            try { queue.reconfigure(next); } catch (const std::invalid_argument &) { backend = true; }
            require(backend, "Queue cannot change backend mode");
        }
        replies.clear();
        {
            auto immediate = config;
            immediate.external = false;
            immediate.delay = 0ms;
            std::uint64_t sequence = 1;
            PendingDecisions first(immediate, reply, &sequence);
            first.submit(descriptor(), start, 10, 20);
            {
                PendingDecisions replacement(immediate, reply, &sequence);
                replacement.submit(descriptor(), start, 11, 21);
                replacement.reconfigure(immediate);
                replacement.submit(descriptor(), start, 12, 22);
            }
            first.submit(descriptor(), start, 13, 23);
            require(replies.size() == 4 && replies[0].request.id == 1 && replies[1].request.id == 2 &&
                    replies[2].request.id == 3 && replies[3].request.id == 4,
                    "Gate replacement shares one monotonically increasing request sequence");
            sequence = std::numeric_limits<std::uint64_t>::max();
            first.submit(descriptor(), start);
            require(replies.back().request.id == std::numeric_limits<std::uint64_t>::max(), "Final request ID remains valid");
            bool exhausted = false;
            try { first.submit(descriptor(), start); } catch (const std::runtime_error &) { exhausted = true; }
            require(exhausted && sequence == 0, "Request ID exhaustion cannot wrap into reused identities");
        }
        replies.clear();
        {
            auto external = config; external.external = true; external.analyzer_error_allow = true;
            PendingDecisions queue(external, reply);
            queue.submit(descriptor(), start); queue.fail_reader();
            require(queue.size()==0 && replies.size()==1 && !replies.back().verdict.allow &&
                    replies.back().verdict.reason==DecisionReason::reader_error,"Reader fault denies independently of analyzer fallback");
            queue.submit(descriptor(), start); const auto count=replies.size();
            require(queue.abandon()==1 && queue.size()==0 && replies.size()==count,"Unconfirmed request abandonment fabricates no reply");
        }
        config.max_pending = 0;
        bool rejected = false;
        try { PendingDecisions queue(config, reply); }
        catch (const std::invalid_argument &) { rejected = true; }
        require(rejected, "Reject an unbounded/empty pending budget");
        std::cout << "PASS deterministic deadlines, capacity, shutdown and FD ownership\n";
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
