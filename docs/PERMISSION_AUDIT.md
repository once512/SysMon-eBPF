# fanotify 逐请求裁决审计

`--audit-permissions` 在服务启动时开启逐请求 JSONL。适用于默认联合模式和 fanotify-only 模式；需要实际启用 fanotify，不能与 bpf-only 组合。此选项不是配置文件字段，在线重载不会开关审计出口。

```bash
sudo ./build/secmon --policy /absolute/policy.conf --audit-permissions > events.jsonl
# 单独研究 fanotify，同样需要已存在的普通目标文件：
sudo ./build/secmon --fanotify-only --file /absolute/target --decision deny \
    --audit-permissions --run-for 20 > permission-events.jsonl
```

启用后 stdout 只包含审计 JSONL，fanotify 最终汇总写 stderr。未启用此选项时不产生逐请求 fanotify 记录，fanotify-only 的最终汇总仍写 stdout；BPF 原有事件仍按原方式输出。

## 记录表示什么

只有向 fanotify group 成功写回完整 `fanotify_response` 后才生成 `fanotify_decision`，静态裁决、容量回退、超时、扫描结果、后端故障和正常停止拒绝都经过同一完成回调。

它证明监听器写回了一次权限回复，不证明原系统调用最终成功：其他检查仍可拒绝操作，请求方也可能已经取消。回复写入失败时不伪造完成记录；崩溃、异常关闭以及仍未读出的内核请求在组释放时也没有逐条完成记录。

示例字段如下（数值仅作字段说明）：

```json
{"event":"fanotify_decision","listener_pid":321,"instance_ns":123,"request_id":1,"requester_pid":456,"requester_pid_kind":"tgid","pid_namespace_inode":4026531836,"revision":7,"major":8,"minor":1,"inode":999,"permission_event":"open","decision":"deny","reason":"policy","scan_error":"none","scan_errno":0,"received_ns":1000000,"responded_ns":3500000,"latency_us":2500}
```

| 字段 | 含义 |
| --- | --- |
| listener_pid / instance_ns | 监听服务 PID 和同管理状态一致的实例时刻；实例时刻不是持久 UUID 或身份认证 |
| request_id | 本权限门的递增非零请求号，容量回退也占用一个；重启后重新开始 |
| requester_pid | 原样保存 `fanotify_event_metadata.pid`；当前组未启用 FAN_REPORT_TID，因此是 TGID，外层不可见任务可为 0 |
| requester_pid_kind | 固定 `tgid`，避免将进程组 ID 误作实际操作线程 TID |
| pid_namespace_inode | 创建组时缓存的监听进程 PID namespace inode；requester_pid 和 listener_pid 使用这一坐标，不是永久全局 UUID |
| revision | 用户态接收事件时的活动策略 revision，命令行无文件策略时可为 0 |
| major / minor / inode | 从事件 FD 核对固定目标集合后保存的本请求设备及 inode；别名和重命名仍指向原对象 |
| permission_event | `open` / `access` / `exec`，与实际订阅入口一致 |
| decision | 已写回的 `allow` / `deny` |
| reason | 下表中的完成原因 |
| scan_error / scan_errno | 已校验的单文件扫描错误；不是请求方系统调用 errno |
| received_ns / responded_ns | 用户态 `steady_clock` 的接收/回复时刻，单位 ns |
| latency_us | 两时刻之差，向下取整到微秒；不含用户态接收前的内核排队时间 |

同一启动上下文中的请求关联使用 `(pid_namespace_inode, listener_pid, instance_ns, request_id)`；跨机器/跨启动汇总还需要采集端提供机器及 boot 身份。请求号按接收分配，回复顺序可以不同：例如第二个请求先容量回退，第一个请求稍后才完成分析。`requester_pid` 仅保留 fanotify 返回值；没有 PID namespace 转换、UID/EUID 认证或与 BPF 任务生命周期身份的自动绑定，不应将它当作长期授权主体。namespace inode 是坐标说明，不能补出 requester 的进程启动时间，也不能把 0 转换成可归属的任务。线程与生命周期边界见 [身份合同](IDENTITY_CONTRACT.md)。

| reason | 发生条件 | 对应汇总 |
| --- | --- | --- |
| policy | 静态策略按配置延迟作答 | allowed / denied |
| capacity | 用户态 pending 已满，采用 overload 回退 | overloaded |
| timeout | 接收后超过请求期限，采用 timeout 回退 | timed_out |
| shutdown | 正常停止时拒绝已交付的 pending 请求 | shutdown_denied |
| analysis | 分析器返回有效 allow/deny | analyzed |
| analyzer_error | 单文件错误或后端不可用，采用 error 回退 | analyzer_error |

`analyzer_error` 的 `scan_error=none` 表示后端故障回退；具体单文件错误保留其类型及 errno。字节标记扫描仍是实验机制，记录原因不等于确认恶意行为。

## 版本、输出与失败

请求身份、接收时刻和 revision 随 pending 一起保存。忙时重载被拒绝，候选准备失败也不会提前修改裁决版本；新版本只在联合提交成功后用于后续接收的请求。内核中尚未交付的请求不具有旧的用户态 revision 合同。

一个 group 可订阅最多 64 个固定对象。每条请求也保存对象快照，因此不同目标的延迟、容量、超时、分析和停止回复不会混淆对象；共享预算与固定目标重载边界见[多目标订阅](FANOTIFY_MULTITARGET.md)。

[受限在线目标切换](FANOTIFY_HANDOVER.md)保持服务内 request_id 连续，并新增 fanotify_target_handover 事件标明旧内核未读取请求按先前 allow 释放的边界。该事件不补造逐请求回复，也不参与访问后拒绝规则。

`MonitorService` 拥有唯一 stdout `AuditSink`，BPF 和 fanotify 借用它；没有第二个 stdout 写线程。共同使用最多 1024 条、1 MiB、每条 4096 字节的预算，没有按事件种类保留配额。大量权限审计可以挤占其他用户态审计记录的预算。

格式转换/分配失败、队列满、出口离线和停止未排空都计入共享 `audit_dropped`。它们不改变已经写回的回复，也不触发重复回复；背压不会让主循环等待 stdout。联合模式的 `audit_*` 是两种事件的总计数，无法据此精确拆分每种事件丢失了多少条。内核 BPF ring 丢失和 fanotify overflow 仍各自独立；不能只看用户态出口便宣称覆盖完整。

所有管理响应都返回 `permission_audit` 布尔值。BPF 后端及已开启权限审计的 fanotify-only 后端返回共享 `audit_written/dropped/invalid/queued/errno`；written 仅表示完整写出，不代表下游已持久化。fanotify 格式转换失败计为 dropped，invalid 仍描述 BPF 二进制事件校验失败。

正常退出先回复已交付请求并关闭权限组，再卸载/消费 BPF，最后排空统一出口；非阻塞管道/socket 最多等待约 200ms，未排空条目计为丢弃。普通文件底层存储故障仍可能影响输出线程 join。其他输出行为见 [审计/诊断出口](AUDIT_OUTPUT.md)。

## 验证入口

```bash
ctest --test-dir build --output-on-failure
sudo python3 -B tests/run_privileged.py --build-dir build \
    --only permission-audit permission-audit-backpressure --permission-audit-soak-duration 30
```

`permission-audit` 核对身份/文件对象、别名与重命名、并发、revision、失败回滚、六类完成原因、扫描错误及汇总对账；`permission-audit-backpressure` 在联合和 fanotify-only 两种模式下分别验证堵塞/恢复、断开和持续洪流中的重载与停止。fanotify-only 还核对完整写出加丢弃等于实际回复数。

可选持续负载依次运行静态 open、分析 open、分析 access，每种运行指定秒数（0 禁用，5..1800 秒），逐行验证审计记录、连续唯一请求号、回复总量、策略版本与管理状态。它使用按实际回复总数分配的字节标记数组，不把全部 JSON 对象载入内存。

本轮固定产物、30 项特权专题与三组逐条对账负载的实际结果见 [验证记录](VALIDATION_PERMISSION_AUDIT_2026_10_18.md)。

可选 `--requester-pidfd` 增加内核进程引用及经 pidfs 验证的 requester_process_inode，与 BPF process_inode 做受约束的进程级关联；字段、资源和失败合同见 [请求方 pidfd](REQUESTER_PIDFD.md)。默认不开启，不增加这些权限记录字段。
