# 应用与受控破坏场景验收（2026-10-20）

新增 `tests/behavior_applications.py`，纳入特权 runner 的 `behavior-applications` 专题。八类场景及其前提见 [场景合同](BEHAVIOR_APPLICATIONS.md)。本轮未修改原生服务、规则实现或默认响应行为。

## 正式运行

冻结快照为 `build/applications-checkpoint-20261020`，包含 67 个脚本/工具/二进制文件及 `SHA256.json`。全部快照摘要复核通过，生产采集脚本与工作区最终版本一致。正式命令：

```sh
sudo python3 -B build/applications-checkpoint-20261020/tests/behavior_applications.py \
  --build-dir build/applications-checkpoint-20261020/bin \
  --artifact-dir /tmp/secmon-applications-final-20261020
```

32 个变体全部通过，耗时 68.257 秒，退出码 0，控制器 FD 为 4/4，无遗留子进程。每个变体目标 inode 及全部内容不变；SQLite 原记录和 integrity_check 均通过。审计/内核丢失及历史淘汰为零。

| requester pidfd | 权限模式 | 权限允许 | BPF 修改拒绝 | 1000 ms 规则观察 |
|---|---|---:|---:|---:|
| 关闭 | open | 6 | 8 | 0 |
| 关闭 | access | 14 | 8 | 0 |
| 开启 | open | 6 | 8 | 3 |
| 开启 | access | 14 | 8 | 3 |

每种模式覆盖八类场景，每场景一次原生修改拒绝。三次观察分别来自普通文件保存、GNU sed 保存、受控读取后 XOR 覆盖。SQLite、日志改名、直接截断、分进程读写、延迟写入均未命中。SQLite 版本为 3.46.1，读写打开被拒绝后回退只读，实际更新返回 SQLITE_READONLY。

## 离线核验

32 份正式采集包全部精确重放。窗口 100/1000/5000 ms × 历史 32/128 × 七种投递模式，共 1344 个配置通过，耗时 0.302 秒。

全部不删除输入的配置中，有界观察与完整输入参考算法一致。开启 pidfd 的延迟写入在 100/1000 ms 为零，5000 ms 为一次；删除权限或拒绝记录后不再命中。直接截断及分进程读写在全部窗口和投递配置下仍为零。跨进程读写没有按数字 PID 或其他猜测方式拼接。

全量 CTest 28/28 通过，耗时 1.97 秒。runner 注册表和脚本语法核查通过，现有 39 个专题，默认附加三个 pidfd 变体，共 42 项 runner 调用；本轮没有重跑全部特权专题。

## 记录位置和摘要

本机记录位置，`/tmp` 内容不作为永久归档：

- 正式负载日志：`/tmp/secmon-applications-final-20261020.log`。
- 原始采集包和场景汇总：`/tmp/secmon-applications-final-20261020/`。
- 每包评估和汇总：`/tmp/secmon-applications-evaluation-20261020/`。
- CTest 日志：`/tmp/secmon-applications-ctest-20261020.log`。

采集脚本 SHA-256：`adf16979dd0585f2b64e0153ba12c926ffe5f32c879a9d28b3c148379f097a1e`。
正式 `summary.json` SHA-256：`b5d6926ab0357edfb478f722b865b8dfe324319721d1bd39edab535e0b026b92`。
评估器及核心工具摘要与 [覆盖评估验收](VALIDATION_EVALUATION_2026_10_20.md) 一致，另保存在评估汇总中。

## 结论边界与后续

正常保存和受控破坏可以产生相同的观察模式；原生修改拒绝也可能没有对应规则观察。此处场景意图是测试声明，受控 XOR 覆盖不是已确认恶意软件样本，不能据此给出生产误报率或攻击召回率。classification 保持 undetermined，response 保持 none。

下一步选择具体部署应用，补充经过独立标注的操作链与攻击样本，研究访问、修改尝试、对象范围、时间和授权变化的组合依据。任何响应仍需独立明确身份引用、触发条件、策略修改、解除和恢复合同。
