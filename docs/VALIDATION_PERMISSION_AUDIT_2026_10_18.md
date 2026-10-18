# 逐请求权限审计验证（2026-10-18）

实现提交为 `80fb434`，使用本机 `6.12.0-211.61.1.el10_2.x86_64`。字段与语义见 [逐请求裁决审计](PERMISSION_AUDIT.md)。本轮新增 --audit-permissions 和服务拥有的统一 stdout 出口，不更改内核授权规则或 fanotify 回退策略。

## 产物与实际入口

特权验证使用固定 `build/permission-audit-checkpoint`，开发及 Release 构建不覆盖它。SHA-256：

| 程序 | SHA-256 |
| --- | --- |
| secmon | `945707c1e6170b5e22f97d56a3df80ef5adec8d49180bf46b60e1245c8701397` |
| secmon-analyzer | `c99aad5add45d93d27dc6bd4df24e7a15452f20706b81015bf8913ea08ce361f` |
| secmon-policyctl | `fd031ec93de0a4b9938b9058c8b402a8b0176c5831c7fc58ead715a693405723` |

```bash
sudo python3 -B tests/run_privileged.py --build-dir build/permission-audit-checkpoint \
    --permission-audit-soak-duration 30
```

原始日志：`/tmp/secmon-permission-audit-validation-20261018.log`。完整入口的 30 项特权专题和 3 项可选持续负载均通过，共 33 项；运行结束后没有遗留 secmon 进程。

## 编码、状态机与实际请求

默认和独立 Release 构建各 23 项 CTest 全部通过。逐请求编码器及请求队列另以 Clang AddressSanitizer/UBSan 构建运行通过，未报告 sanitizer 错误。格式测试核对最大数值、单调时钟、六类完成原因、扫描错误与非法输入；状态机测试核对容量请求号、接收身份/revision、延迟/停止回调及 FD 生命周期。

真实权限专题通过：

- 联合和 fanotify-only 两种模式的静态允许/拒绝、24 个并发请求、硬链接身份和逐条汇总对账。
- 重命名后继续记录原 inode；替换路径指向新 inode 时不伪造受标记对象的记录。
- 忙队列拒绝更新，旧请求保留接收时的 revision；BPF 候选准备失败后，新接收请求仍使用原 revision，随后合法版本正常提交。
- 容量回退、超时、正常停止的 pending 拒绝，以及 open/access 扫描允许/拒绝、oversized 单文件错误、工作进程故障和显式允许错误回退。
- exec 权限拒绝的真实发起者身份和固定文件对象。

所有完成记录在写回内核成功后生成，按 `(listener_pid, instance_ns, request_id)` 核对。权限回复不是原系统调用最终成功的证明；测试中逐条比较的是本次受控客户端的实际结果。

## 正常输出下的持续负载

| 模式 | 秒数 | 权限回复/审计条数 | 查询 | 成功更新/同版本拒绝 | FD 基线/观测峰值 | 最大查询 ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| static / open | 30 | 22739 | 297 | 14 / 14 | 56 / 61 | 5.321 |
| analysis / open | 30 | 44760 | 294 | 14 / 14 | 58 / 61 | 6.232 |
| analysis / access | 30 | 44721 | 294 | 14 / 14 | 58 / 62 | 6.582 |

共核对 112220 条逐请求记录、885 次查询、42 次成功更新与同样次数的同版本拒绝。每组请求号唯一且完整覆盖 1..N，允许/拒绝数量与客户端及结束统计一致；接收 revision、实例、PID 和事件入口逐条核对。

三组结束时 ringbuf_dropped、baseline_update_failed、audit_dropped、audit_invalid、audit_queued、audit_errno 均为 0；最终 status 的 diagnostic_dropped/invalid/queued/errno 也均为 0。FD 数值是负载采样与闲置回收检查，不声称覆盖候选准备的所有瞬时峰值；查询时间不是性能 SLA。

## 输出背压与错误

每个后端均运行 recover、blocked-stop、closed-peer、continuous 四组。前三组的背景生产者各产生 8000 次标记文件打开，持续组保持真实请求洪流直至完成状态查询、重载与裁决检查。stdout 管道缩至 4096 字节且不被消费；恢复组随后重新读取。

| 后端 | 场景 | 快照丢弃数 | 永久 errno |
| --- | --- | ---: | ---: |
| combined | recover | 6969 | 0 |
| combined | blocked-stop | 6969 | 0 |
| combined | closed-peer | 8003 | 32 |
| combined | continuous | 187 | 0 |
| fanotify-only | recover | 6966 | 0 |
| fanotify-only | blocked-stop | 6966 | 0 |
| fanotify-only | closed-peer | 8000 | 32 |
| fanotify-only | continuous | 56 | 0 |

表中是压力期间 status 快照，未计入随后重载/停止的新增记录或丢弃。丢弃是故意触发的预期输出损失；联合模式的丢弃包含 BPF 和 fanotify 两种记录，不直接等同于丢失的权限请求数。

八组均保持裁决、revision 2 更新、状态查询及授权停止可用；恢复后的输出为完整 JSONL，读端断开记录 EPIPE。fanotify-only 的结束统计额外核对 `audit_written + audit_dropped == allowed + denied`。正常退出不会依赖消费端重新读取管道。

## 保持的边界

--audit-permissions 为显式启动选项，默认不开启。开启后 fanotify-only 的汇总写 stderr，stdout 为 JSONL。共享队列没有事件种类配额；背压时记录可以丢失，不能以规则仍生效代替审计完整性。

原始 fanotify PID 未补查 UID 或绑定 BPF 全局任务身份；单调时钟不直接提供 UTC 墙钟时间，接收前的内核等待不计入 latency_us。仍未读出的请求、异常关闭或崩溃释放的请求没有逐条完成日志。普通文件底层 I/O 卡住仍可能拖住输出线程 join。

本轮不认定真实攻击、可信程序内容或完整保险箱会话已完成。下一项实验见 [当前进度与下一步](NEXT_STEPS.md)。
