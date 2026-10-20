# 行为观察规则覆盖评估

`tools/evaluate_capture.py` 在已经核验的采集包上，对比有界规则与完整输入历史的时间参考算法。它评估的是“给定证据中能否观察到该时间模式”，不是恶意识别准确率，不输出生产误报率、攻击召回率或自动响应。

```sh
python3 -B tools/evaluate_capture.py CAPTURE_DIRECTORY \
  --window-ms 1 100 1000 --history 1 8 32 128 > evaluation.json
```

工具先检查原始流、保存结果与清单摘要，并用当前实现精确重放原结果；之后对相同的原始时间戳执行七种投递实验：原始顺序、反序、按事实时间排序、权限记录后到、固定种子的乱序、删除权限记录、删除拒绝记录。后六种均为明确标记的合成投递/缺失实验，既不修改原始采集包，也不冒充实际内核故障。默认 seed 为 20261020。

每个窗口/容量/投递组合报告：

| 字段 | 含义 |
|---|---|
| source_eligible | 原始输入完整历史中，满足该窗口的拒绝观察数 |
| delivered_eligible | 本次实际投递的输入完整历史中，仍有支持证据的拒绝数 |
| eligibility_lost_with_input | 因输入记录删除而失去的模式证据数 |
| bounded_matches | 实际有界规则观察数 |
| missed_with_bounded_state | 投递证据中可观察、但有界状态未匹配的数量 |
| removed_denials | 从原始输入删除的拒绝记录数，按角色报告 |
| capacity_evictions / history_evictions | 实际归组/历史淘汰次数，不等于漏匹配数 |

完整历史参考算法先按进程/文件键收集 open/access allow 的回复时间，再用二分查找检查每条拒绝之前最近的回复。严格要求 `0 < denial.timestamp_ns - permission.responded_ns <= window`；exec、权限 deny、缺少可信进程键均不充当支持证据。0 毫秒显式关闭规则。参考历史只针对输入文件，没有证明整个进程历史或实际文件生命周期完整。

角色来自 manifest 中 scenarios/tools 的声明，并按非零进程 inode 关联，不用数字 PID 补身份。未声明角色为 unlabelled，缺少拒绝主体键为 unattributed。正常维护程序、GNU sed 保存、受控重复写入等标签仅说明本实验安排，不认证生产程序的意图；冲突角色声明会拒绝分析。所有结果保持 classification=undetermined、response=none、authenticity_verified=false。

## 生成连续操作和正常保存反例

```sh
sudo python3 -B tests/behavior_workloads.py --build-dir build \
  --mutation-attempts 96 --benign-edit --artifact-dir /tmp/secmon-evaluation-captures
```

四种模式仍为 open/access × pidfd 开关。mutation-attempts 允许 1..128（默认 1），同一个受控进程反复读取并通过预先打开的 FD 尝试写入，写入应被内核拒绝。采集基线使用 max(32, mutation-attempts) 条历史，以保留该进程的完整受控证据；评估时另行调整历史上限，不能把受裁剪的基线当成完整参考。

benign-edit 为可选 GNU sed 负载：`sed -i` 读取目标、写临时文件，随后替换受保护目的 inode 时被拒绝。测试核对 GNU sed 返回码 4、BPF rename/EACCES、同一真实 pidfd 进程键、原文件和备份内容不变。它是实际正常程序的保存失败反例，命中时间模式仍不证明恶意。原有默认负载不启用此选项。

## 资源与解释边界

评估器会保留完整输入作参考，与流式生产归组工具不同。输入限制为 32 MiB、50000 条记录，保存的 evidence 限制 64 MiB，manifest 限制 2 MiB，最多 128 个声明进程、8 个窗口、8 个历史容量和 7 种投递模式。超限、损坏或无法重放时以非零状态结束，不输出成功报告。

报告区分模式支持消失、拒绝记录消失和有界状态的漏匹配。任何一项为零都不能解释为没有行为或系统安全；增大历史和时间窗也不能直接当作误报修复。测试用独立二次复杂度参考算法验证二分参考，并在容量足够时核对各类乱序结果；刻意降低容量时则验证可重现的漏匹配。

```sh
python3 -B tests/capture_evaluation.py
ctest --test-dir build -R 'offline-(capture|behavior|evidence)' --output-on-failure
```
