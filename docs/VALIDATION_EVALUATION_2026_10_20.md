# 行为覆盖评估验收（2026-10-20）

本轮增加 [离线覆盖评估器](BEHAVIOR_EVALUATION.md)，将输入证据缺失与有界状态漏匹配分开报告；加入连续读取/拒绝写入和 GNU sed 正常保存反例。原生服务代码没有修改，观察结果仍为 classification=undetermined、response=none，不启用自动隔离。

## 验证结果

- 构建成功；全部 28 个 CTest 通过，耗时 1.97 秒。最后针对忽略事件的时间戳处理调整，再次通过四个离线专题测试。
- 新负载运行 10 轮、40 个变体，耗时 123.236 秒，退出码 0，测试进程 FD 基线/结束均为 4。
- 默认负载回归运行一轮、四个变体，耗时 12.84 秒，退出码 0，FD 仍为 4/4。
- 40 份采集包全部精确重放；每包运行三个窗口、四个历史容量、七种投递模式，共 3360 个评估配置通过，耗时 13.351 秒。

四种变体为 open/access × requester pidfd 开关。每个新负载变体包含同进程 96 次读取及拒绝写入，采集基线历史容量为 96；每变体共 101 条 BPF 拒绝。pidfd 开启时，每包基线观察 98 次，包括连续操作 96 次、维护反例一次、GNU sed 正常保存反例一次。关闭时缺少关联所需的权限主体键，基线观察为零。GNU sed 返回码 4，替换目标时发生 rename/EACCES，受保护内容保持不变。

## 容量与投递顺序的实际结果

以下为窗口 1000 ms、20 份 pidfd 开启采集包中，实际有界规则相对完整投递历史参考算法的漏匹配数。

| 投递模式 | 历史 1 | 历史 8 | 历史 32 | 历史 128 |
|---|---:|---:|---:|---:|
| 原始顺序 | 83–95 | 0 | 0 | 0 |
| 权限记录集中后到 | 95 | 88 | 64 | 0 |

完整输入在该窗口每包支持 98 次观察；集中后到且历史 32 时实际观察 34 次。后到、乱序和删除输入均为评估器明确标记的合成实验，不是声称内核实际发生相应故障。三个窗口分别为 1、1000、10000 ms；历史 128 时，所有不删除输入的投递方式均与完整参考一致。

各 pidfd 开启采集包在原始顺序、1000 ms、历史 32 下，正常维护与 GNU sed 各观察一次；cat、sha256sum 索引、cp/tar 备份与别名 cat 均为零。这些角色仅是负载声明。正常程序保存也会满足观察规则，因此上述数字不能转换为恶意识别准确率或生产误报率。

## 复现与原始记录

生产采集脚本及核心离线工具在运行前复制至 `build/evaluation-checkpoint-20261020`，摘要记录为其中的 `SHA256.json`。该目录包含此前已验证的四个原生二进制。评估器随后修正了忽略事件的时间戳处理，矩阵使用工作区最终版本；其摘要单独记录，不能把采集快照整体视为评估器最终版本。

```sh
sudo python3 -B build/evaluation-checkpoint-20261020/tests/behavior_workloads.py \
  --build-dir build/evaluation-checkpoint-20261020/bin --duration 120 \
  --mutation-attempts 96 --benign-edit \
  --artifact-dir /tmp/secmon-behavior-evaluation-final-20261020

python3 -B tools/evaluate_capture.py CAPTURE_DIRECTORY \
  --window-ms 1 1000 10000 --history 1 8 32 128
```

本机记录位置（`/tmp` 文件不是永久归档）：

- 构建：`/tmp/secmon-evaluation-build-20261020.log`。
- CTest：`/tmp/secmon-evaluation-ctest-20261020.log`。
- 新负载：`/tmp/secmon-behavior-evaluation-final-20261020.log` 及同名无后缀采集目录。
- 默认负载：`/tmp/secmon-behavior-evaluation-default-20261020.log`。
- 每包完整评估及汇总：`/tmp/secmon-evaluation-reports-20261020/`，汇总为 `summary.json`。

矩阵使用的 SHA-256：

| 文件 | SHA-256 |
|---|---|
| tools/evaluate_capture.py | c3b3e95d35e58cb10f2ba44d0f2a4f886fd33a15a257a84decc60a862fb5751b |
| tools/replay_capture.py | b23e5c82048a95239cd59b5f09402d1941cea763543fe5dae928309b23edd963 |
| tools/evidence.py | 31f259a75e4ba814d897da710da23a0026ce1b4c545600324548958417084300 |
| tools/behavior.py | c028eff1a9f6d24f6ece0727257f2fe6d84e75a71854ffe27ddc8cc028f224a2 |

摘要用于核验输入与版本一致，未证明采集来源真实性、全系统日志完整性或文件全生命周期。下一阶段仍需明确部署应用和真实攻击样本，再评估误报控制与确认后的响应。
