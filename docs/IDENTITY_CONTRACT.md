# 审计身份合同与并发边界

当前审计能描述发生过的内核拒绝和已写回的权限裁决。它没有为 fanotify 请求提供可认证的任务生命周期引用。本合同限制下游关联能够声称的内容，不授予进程任何新权限。

## 两类记录使用的坐标

| 来源 | 数字身份 | 生命周期信息 | 时钟 |
|---|---|---|---|
| BPF file_denied / exec | pid 为内核初始 PID namespace 的 TGID，tid 为实际任务 TID | start_ns 为该任务的 task_struct.start_boottime，不是所有线程共享的进程启动时间 | timestamp_ns 为 bpf_ktime_get_ns 的单调时间；start_ns 为 boottime，不能直接相减 |
| fanotify_decision | requester_pid 为创建组的监听器 PID namespace 中的 TGID；requester_pid_kind 固定 tgid | 没有 requester 启动时间、pidfd 或可信可执行文件身份 | received_ns/responded_ns 为用户态接收/回复单调时间，不是内核访问发生时间 |

fanotify 的 `pid_namespace_inode` 在初始化时从 `/proc/self/ns/pid` 缓存；服务不改变 PID namespace，也没有开启 FAN_REPORT_TID。每次请求不查询 `/proc/<pid>`。`listener_pid` 与 requester 使用相同 namespace 坐标。该 inode 在本机当前启动上下文中用于区分坐标，不是跨启动、跨机器的唯一 ID。

BPF 任务键应按 `(boot 上下文, pid, tid, start_ns)` 理解。`start_ns` 区分线程生命周期，不自动认证执行内容或进程历史；exec 的线程身份变化仍须按已有 exec/基线合同处理。不能用 `pid + start_ns` 把不同工作线程当成不同进程，也不能把 BPF 纳秒值与 `/proc/stat` 的时钟 tick 当作同精度身份。

## 允许与不允许的关联

- 同一启动上下文内，权限请求用 `(pid_namespace_inode, listener_pid, instance_ns, request_id)` 标识；request_id 属于监听器实例，不是请求方身份。
- 同一进程的多个线程可能同时触发权限事件。TGID 相等、时间接近只能给出候选进程范围；即使候选时间窗暂时唯一，也不能由此认证实际线程或其生命周期。
- namespace 坐标不同或 requester_pid 非正时，不能直接与 BPF 数字 PID 拼接。尤其 `0` 可能表示请求方不在监听器可见的 namespace 内，不是 PID 0 内核任务的证据。
- 进程退出后再读取 `/proc/<pid>`，可能已经读到另一个生命周期；查询成功不能修复原事件缺失的身份。不得据此自动授权、发信号或隔离。
- inode/时间关联也不是因果证明。fanotify allow 表示成功回复，BPF file_denied 表示独立检查点拒绝；二者没有统一操作 ID，也没有保证一一对应。

生产自动响应尚未启用。下一步若增加稳定 requester 身份，应先验证内核提供的生命周期引用、支持矩阵、事件附件解析、FD 上限与回收、任务退出及不可见身份的失败语义，再设计与 BPF task/group 身份的绑定。当前不使用无生命周期保护的数字 PID 来执行响应。

## 可复现实验

```sh
sudo python3 -B tests/identity_threads.py --build-dir build --report /tmp/identity-threads.json
sudo python3 -B tests/permission_namespace.py --build-dir build
# 多次完整创建/退出循环，0 表示只运行一轮；最多 1200 秒：
sudo python3 -B tests/identity_threads.py --build-dir build --duration 900 --report /tmp/identity-soak.json
```

`identity-threads` 有四个变体：open/access × 宿主/子 PID namespace 请求方。监听服务保持在宿主；每个变体创建四个并发工作线程及一个 leader，重建工作线程两次。每代各线程执行 12 次读取和旧 FD 写入，leader 再执行一次；共 147 条 allow 和 147 条 write 拒绝。线程都保持存活到控制器完成快照；宿主从 NSpid 获取测试映射，另一个不启用自保护的 BPF 观察器提供本次任务的凭证基线键。测试不会绕过主服务自保护读取其 fdinfo。

实验核对每条拒绝的 TGID/TID/start_ns 与当前 live 任务键、准确操作时间窗和文件身份；重建后旧 worker 键消失，leader 键保持不变；进程退出后全部键清理。fanotify 始终报告进程 TGID；并发时间窗的候选线程集合完整保留，不挑选“最近”的线程。时间窗歧义数量依调度变化，不作为固定断言。重复模式还核对控制器 FD 数回到基线。

`permission-namespace` 将监听服务放在子 PID namespace，分别运行 fanotify-only 和联合模式。外层请求得到 requester_pid=0，同 namespace 请求得到该 namespace 的局部 TGID；两者都成功访问。服务的 namespace inode 与宿主不同。测试保留自保护，通过同 namespace 管理客户端退出；外层客户端的 PID 坐标检查会拒绝响应，未放宽原管理认证检查。

这些是受控进程和显式 namespace 映射的实验。没有覆盖真实宿主 PID 数字复用、非 leader exec 的全套审计关联、线程逃逸、完整容器或通用线上关联器。过去已有的非 leader exec/基线清理专题仍独立运行，不能据此宣称权限事件也获得了同等生命周期能力。
