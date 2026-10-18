# 身份坐标与并发生命周期验证（2026-10-18）

内核为 `6.12.0-211.61.1.el10_2.x86_64`，x86_64，当前 boot ID 为 `54bb622b-e851-4599-b9c3-3627b7627852`。实验使用临时文件、临时 root 私有管理 socket、受控多线程进程和私有 mount/PID namespace；没有部署持久策略或自动响应。

## 身份坐标阶段

代码提交 `b177d3d` 增加 `requester_pid_kind=tgid`、`pid_namespace_inode`，namespace 只在初始化时缓存，逐请求不增加 `/proc/<pid>` 查询。字段、任务时钟及允许的关联范围见 [身份合同](IDENTITY_CONTRACT.md)。

默认构建与 Release 构建的 23 项 CTest 均通过。Clang ASan/UBSan（含泄漏检测）权限编码检查通过，覆盖 namespace 字段缺失、最大数值和单行预算。全量 34 个特权专题全部通过，runner 累计专题耗时 189.537 秒，原始日志为 `/tmp/secmon-identity-full-validation.log`。

线程专题有四个变体：open/access × 宿主/子 PID namespace 请求方。每个变体有 3 代工作线程；每代四个 worker 各执行 12 次读取和旧 FD 写入，主线程另执行一次。每个变体逐条核对 147 条 allow 与 147 条 BPF write 拒绝，以及实际任务键、进程退出清理和零审计/内核丢失。fanotify 时间窗有歧义时保留候选集合，不强行归到某个线程。

反向 namespace 专题的 fanotify-only 和联合模式均通过：监听器位于子 namespace，外层请求 PID 为 0，同 namespace 请求为局部 TGID；字段中的 namespace inode 与实际监听器 namespace 一致。管理客户端保留原 PID 坐标检查，从同 namespace 完成查询和退出。

持续循环使用冻结目录 `build/identity-checkpoint`，对应上述提交；SHA-256：

| 产物 | SHA-256 |
|---|---|
| secmon | `59a8c80c4140fbe029bbf02bd28c5620a9607ff8ab718855d5f48114c30a6218` |
| secmon-analyzer | `c99aad5add45d93d27dc6bd4df24e7a15452f20706b81015bf8913ea08ce361f` |
| secmon-policyctl | `fd031ec93de0a4b9938b9058c8b402a8b0176c5831c7fc58ead715a693405723` |

该快照不含后续 self_denied JSON 调用方 start_ns 补充，不能把两阶段产物混作同一二进制。

## 持续创建、并发访问与退出

命令为 `identity_threads.py --build-dir build/identity-checkpoint --duration 900 --report /tmp/secmon-identity-soak.json`。约 15 分钟，完成最后一整轮后退出：

| 指标 | 结果 |
|---|---:|
| 完整循环 | 67 |
| 变体实例（每轮四种） | 268 |
| 逐条核对的权限 allow | 39396 |
| 逐条核对的 BPF write 拒绝 | 39396 |
| 多个候选线程时间窗的权限记录 | 37121 |
| actor 工作线程创建数 | 3216 |
| actor 线程/进程退出后的基线键残留 | 0 |
| 控制器循环间 FD 增长 | 0 |
| 各被测监听服务审计丢弃/非法/未排空/写错误、内核丢失与基线更新失败 | 均为 0 |

每条拒绝都与实际 live BPF 任务键、TID、启动时间和操作时间窗核对；读取返回值、旧 FD 写入的 EACCES 与原文件内容均检查。37121 条歧义记录保留候选集合，没有自动选择线程。它们说明时间相近不能补齐实际线程身份，不表示发生了攻击。

原始逐变体日志为 `/tmp/secmon-identity-soak.log`；JSON 报告包含累计数量和最后完整循环的原始证据。控制器 FD 检查针对测试控制器，不是单个常驻服务的 FD 峰值测量。每个变体的服务和观察器都会重新创建并退出。

## 补充自保护拒绝调用方的启动时间

代码提交 `be02bd2`：`self_denied` 的内核事件原本已填充调用方 start_boottime，但 JSON 编码遗漏该字段。补充 `start_ns` 后，不改变二进制事件 ABI、内核拒绝或管理协议。纯编码测试验证所有事件种类均保留该值，自保护专题核对实际调用方的 pid/tid 和一致的非零启动时间。

最终默认 secmon SHA-256 为 `70fe5c9946137e199ec3c22f1eca9db56f80b1a3c704441db01bbdf03becbcde`。默认与 Release 的 23 项 CTest 再次全部通过；Clang ASan/UBSan 的 BPF 编码检查通过。持续循环仍使用前述冻结版本，没有将这项补充追认到旧产物。

最终版本全量 34 个特权专题再次全部通过，runner 累计专题耗时 188.079 秒，日志为 `/tmp/secmon-identity-final-full-validation.log`。其中自保护专题已实际核对调用方启动时间；两阶段全量回归均包含输出背压、管理故障、授权回滚和凭证生命周期。

结束后检查未发现本轮实验服务或 actor 进程残留。所有新增生产改动仅涉及审计身份字段及编码，不启用恶意识别或自动隔离。
