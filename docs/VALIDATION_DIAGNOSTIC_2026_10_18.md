# 诊断输出隔离验证（2026-10-18）

诊断隔离实现为 `c2432dc`；`f5d9d54` 进一步让并发日志与状态查询共享短锁，避免超长行 invalid/dropped 快照看到中间状态。内核为 `6.12.0-211.61.1.el10_2.x86_64`。范围是主服务 stderr 的启动/运行/停止诊断，不改变 BPF 授权匹配或 fanotify 裁决语义。契约见 [审计/诊断出口](AUDIT_OUTPUT.md)。

## 固定产物

首轮完整特权回归和持续负载使用 `c2432dc` 的 `build/diagnostic-checkpoint`，开发和 Release 构建不覆盖它。该主程序 SHA-256：

```text
b57be6540c850bc86b3004a0100cced3ece2094d985961312b8739815f0e8b65
```

分析器 SHA-256 为 `c99aad5add45d93d27dc6bd4df24e7a15452f20706b81015bf8913ea08ce361f`；policyctl 为 `1898014dbd3c3671ebcc5447f76be9187980913064836d1fbf0fb1357a35fc88`。

最终源码 `f5d9d54` 的产物另外保存在 `build/diagnostic-final`，主程序 SHA-256 为 `73770a6d9261ca893cb71ab45b77ee0765f5e47f49fc47b80659c96c55d5982d`。分析器与 policyctl 未改变。持续负载结束后，已顺序对最终产物重新运行完整 28 项特权专题，全部通过。长时结果对应前一快照，最终快照的验证范围为本轮 CTest、sanitizer、完整特权回归及下述 stderr 加强实验。

## 已完成的构建与回归

- 默认及 Release 构建完成；两个构建的 22 项 CTest 均通过。最终默认及 Release 构建的 diagnostic-output-queue 各连续运行 20 次通过，包含一万条超长日志的并发计数快照检查。
- 新诊断适配器使用 Clang AddressSanitizer/UBSan 构建，真实管道、条目/字节双预算、恢复、EPIPE 与退出检查通过，未报告 sanitizer 错误。
- 初始及最终两个快照分别运行的完整特权回归均为 28 个专题全部通过，包含文件/凭证审计、程序授权及矩阵、自保护、分析故障、命名空间、管理异常帧、联合重载、stdout 背压及新增 stderr 背压。具体范围保持 [测试矩阵](TESTING.md) 中的边界。
- Release 验证发现并修正了新增测试的读端时序问题：排空到 EAGAIN 可能顺带消费写线程刚恢复的日志。现在只读预填充的确切 4096 字节，再独立核对后续记录；同时等待 EPIPE 队列清理完成后再核对丢弃总量。

## stderr 实验

四种场景均使用真实 4096 字节管道及继承的阻塞 stderr；每种执行 400 次同 revision 拒绝，并发进行权限打开和 status 查询，再成功更新 revision 2 和授权停止。启动已满场景还跨过 10 秒周期报告。恢复场景重新消费日志；其余退出无需读取 stderr。

| 场景 | 并发权限/状态探测 | 诊断丢弃 | 永久 errno | FD 基线/观测峰值 |
| --- | ---: | ---: | ---: | ---: |
| 启动前已满 | 200 | 151 | 0 | 54 / 54 |
| 堵塞后恢复 | 200 | 144 | 0 | 54 / 54 |
| 堵塞时停止 | 200 | 144 | 0 | 54 / 54 |
| 关闭读端 | 200 | 400 | 32 (EPIPE) | 54 / 54 |

表中计数取失败洪流后的 status，FD 峰值取洪流期间采样；不包含随后周期报告、成功重载和退出的新增丢弃，也不代表准备阶段的全资源瞬时峰值。

这些丢弃是特意制造的诊断出口损失；重载拒绝计数仍完整记为 400，文件权限未因此放行。恢复后已排队的行继续写出；永久错误后不自动重开。

最终快照另外完成每种场景 3000 次失败重载，共 12000 次；四种场景全部通过。原始日志为 `/tmp/secmon-diagnostic-final-20261018.log`。

| 最终快照场景 | 并发权限/状态探测 | 失败重载 | 诊断丢弃 | 永久 errno | FD 基线/观测峰值 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 启动前已满 | 1500 | 3000 | 2771 | 0 | 54 / 54 |
| 堵塞后恢复 | 1500 | 3000 | 2764 | 0 | 54 / 54 |
| 堵塞时停止 | 1500 | 3000 | 2764 | 0 | 54 / 54 |
| 关闭读端 | 1499 | 3000 | 3020 | 32 | 54 / 54 |

这些计数同样取洪流后的快照，包含已触发的周期报告；关闭读端场景的丢弃因此可多于失败重载数。所有场景的 diagnostic_invalid=0、队列不超过 256，重载拒绝计数仍恰为 3000；之后的 revision 2 联合更新与无需消费 stderr 的授权停止均通过。

## 持续负载

三项联合负载已全部通过，共 4,480,730 次权限请求、35,295 次状态查询、1,730 次成功更新及同样数量的同版本拒绝。另完成 600 秒写授权负载。原始日志：`/tmp/secmon-diagnostic-soak-20261018.log`。

| 模式 | 秒数 | 权限请求 | 状态查询 | 成功更新/同版本拒绝 | FD 基线/观测峰值 | 最大查询 ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| static / open | 1200 | 907690 | 11828 | 563 / 563 | 56 / 60 | 7.24 |
| analysis / open | 1200 | 1788521 | 11742 | 583 / 583 | 58 / 63 | 7.254 |
| analysis / access | 1200 | 1784519 | 11725 | 584 / 584 | 58 / 62 | 7.276 |

上述阶段的业务回复完全对账，结束时 ringbuf_dropped、baseline_update_failed、audit_dropped、audit_invalid、audit_queued、audit_errno 均为 0；最终 status 的 diagnostic_dropped、diagnostic_invalid、diagnostic_queued、diagnostic_errno 同样为 0。最大查询耗时是本机实验观测，不能当作性能 SLA。

写授权负载完成 2112 次成功更新和 301 次失败候选回滚，闲置 FD 基线为 52，观测闲置峰值为 53。背景请求单独统计如下；每次确认重载后还同步验证已有 FD 与新打开。

| 常驻主体 | 放行 | EACCES |
| --- | ---: | ---: |
| 授权程序 / EUID 0 | 9887 | 19739 |
| 授权程序 / EUID 65534 | 9774 | 19850 |
| 未授权程序 | 0 | 29619 |

写授权负载最终 status 的 audit_dropped/audit_invalid/audit_errno 及 diagnostic_dropped/diagnostic_invalid/diagnostic_errno 均为 0；该快照在授权停止前获取，audit_queued=1，不将它写成退出后的排空结果。FD 统计也不声称覆盖候选准备时的瞬时峰值。

持续负载的实际入口：

```bash
sudo python3 -B tests/run_privileged.py --build-dir build/diagnostic-checkpoint \
    --only diagnostic-backpressure --combined-soak-duration 1200 --writer-soak-duration 600
```

最终快照的实际入口：

```bash
sudo python3 -B tests/run_privileged.py --build-dir build/diagnostic-final
sudo python3 -B tests/diagnostic_backpressure.py --build-dir build/diagnostic-final --reload-count 3000
```

本轮测试进程均已结束并回收，最终清理检查未发现遗留 secmon 进程。

## 保持的边界

普通文件底层 I/O 卡住仍可能阻塞对应输出线程的 join；非阻塞管道/socket 的有限排空不能推导为任意存储故障下的硬退出期限。fanotify-only 的最终 stdout 统计仍在权限组关闭后同步输出。短时管理/检查 CLI 及独立分析器有各自的输出行为。

本轮没有增加逐请求 fanotify 审计、真实攻击识别、内容/加载链认证或保险箱会话。崩溃后不提供持久拒绝；既有共享可写映射不会随授权删除而撤销。后续优先级见 [下一步](NEXT_STEPS.md)。
