# 离线进程与文件证据归组

`tools/evidence.py` 从 stdin 读取单个服务实例的 JSONL，按声明的来源、process_inode、设备号、文件 inode 和订阅代际汇总事实。数字 PID 不参与关联。工具只统计观察，不判定恶意，也不触发响应。

```sh
python3 -B tools/evidence.py \
  --machine-id SOURCE_MACHINE_ID --boot-id SOURCE_BOOT_UUID \
  --capture-id CAPTURE_NAME < audit.jsonl > evidence.jsonl
```

来源参数必须取自采集端并随原始日志保存，不能使用分析机器当前的 boot ID。来源为操作者声明，工具不验证真实性。每次只输入一个服务实例，不能拼接不同启动或实例。检测到权限记录的监听器 namespace、PID 或 instance_ns 变化后，该行及后续行均计入 invalid；此前输出也不能作为完整采集的验收结果。

支持 fanotify_decision 和 file_denied。权限记录需要可用的 requester pidfd 进程 inode；引用缺失、不可见或身份查询失败只计入 unattributed。BPF 记录没有非零 process_inode 时同样不归组。非法字段、重复 JSON 键、非有限数字、非法 UTF-8 和超长行计入 invalid；其他事件计入 ignored。

每个 process_object_evidence 输出权限允许/拒绝数、修改拒绝数、操作计数及最近若干原始行号与紧凑证据。allow_and_mutation_denial_observed 仅表示同一分段同时观察到允许与修改拒绝，不证明先读后写、同一次调用或攻击。文件 inode 重用未验证，进程历史和审计丢失也未验证；classification 始终为 undetermined。

默认最多保留 1024 个活动归组，每组 8 个样本；--max-groups 范围为 1..4096，--samples 为 1..32。按最近访问淘汰并立即输出独立分段；相同键再次出现会建立新分段。输入每行最多 4096 字节，超长行按一条非法记录处理。重复输入逐条计数，不做全局去重。

最后的 evidence_summary 给出 records、grouped、unattributed、invalid、ignored、淘汰和分段数。records 等于四种输入分类之和。退出码 0 表示没有非法输入，不表示证据完整或系统安全；参数错误为 2，非法输入为 1。

无 root 的语义回归：

```sh
python3 -B tests/offline_evidence.py
ctest --test-dir build -R offline-evidence-grouping --output-on-failure
```

覆盖合成记录的生命周期/文件分离、缺失身份、容量淘汰、采样、混合实例、非法输入及 CLI。真实审计流的端到端验收已加入 `tests/behavior_workloads.py`，详见 [行为观察规则](BEHAVIOR_OBSERVATION.md)。

可选的 `--rule-window-ms 1000` 开启第一条有界行为观察规则，默认 0 关闭。`--rule-history 32` 指定每组保留的允许与未匹配拒绝历史上限（各 1..128 条）。输出增加 behavior 及汇总的 rule_matches、rule_history_evictions；普通归组计数与退出码合同不变。

```sh
python3 -B tests/offline_behavior.py
python3 -B tests/offline_evidence_stress.py --records 100000
```

后者流式产生输入并消费输出，不累计所有记录；分别核对热点键和大量新进程键下的计数、历史淘汰、归组淘汰与 traced Python 分配峰值。它不代表进程 RSS 或内核资源上限。

可用 `--mode saturated --groups 1024 --history 32 --samples 8 --memory-limit-mib 128` 检查多个归组同时保留满额允许与未匹配拒绝的场景。该模式记录数由容量决定；groups/history/samples 分别遵循实际工具的 4096/128/32 上限。memory-limit-mib 是本次测试的 traced 分配验收阈值，不是工具施加的运行时内存限制。


## 订阅代际与离线批次

权限事件现在携带 subscription_generation，初始为 1，目标集合每次成功替换加一；仅裁决更新和失败候选不增加。fanotify_target_handover 提供前后代际、监听器 namespace、请求号与单调时钟边界。工具先校验完整边界序列，再处理事实，因此反序或乱序投递不会把旧读取支持错误带入新订阅。

每次 group 切换保守地分割所有对象，包括保留目标。BPF 拒绝按发生时间归入相应代际；恰好等于边界时间的拒绝归为 0，只计数、不参与配对。权限的代际、请求号、revision 和时间区间必须相符；缺失中间边界、重复/矛盾切换或跨实例数据不能通过完整采集验收。没有代际字段的固定目标权限记录仅按初始代际解释，不推断任何丢失的切换。

这是订阅区间隔离，不是文件全生命周期认证，object_lifetime_verified 仍为 false。输入丢掉全部后续权限和对应边界时不能凭空发现缺失，零丢失与完整采集仍是独立前提。多对象工具也按进程及代际分别计算，不跨代凑齐对象阈值。

为在输出前获得完整边界，consume/CLI 将一个离线批次暂存到自动清理的临时文件，最大 128 MiB、1000000 条输入、4096 次切换，每行仍为 4096 字节；不再把 stdin 当作无限在线流。归组/样本状态仍有界，输入内容不累计为内存列表。磁盘或预算失败返回非零；超限批次不输出成功报告。覆盖评估器另保留其更严格的 32 MiB/50000 条输入限制。

验证：`python3 -B tests/subscription_generations.py`；真实同进程、同 inode、旧 FD 的保留/移除/重加实验为 `sudo python3 -B tests/subscription_live.py --build-dir build`。
