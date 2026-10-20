# 有界行为观察规则

第一条规则为 `allowed-access-before-denied-mutation-v1`，在离线证据归组中显式启用：

```sh
python3 -B tools/evidence.py --machine-id SOURCE_MACHINE_ID \
  --boot-id SOURCE_BOOT_UUID --capture-id CAPTURE_NAME \
  --rule-window-ms 1000 --rule-history 32 < audit.jsonl > evidence.jsonl
```

## 规则含义

同一来源、进程 inode 和文件对象分段中，存在 open/access 的 allow，以及一条 BPF 修改拒绝，且满足：

```text
0 < mutation.timestamp_ns - permission.responded_ns <= window_ms * 1000000
```

使用回复时间，而非接收时间，避免将尚未得到回复的请求当成先行允许。两个时间相等时不认定有先后。exec 权限不参与这条规则。窗口允许 1..3600000 毫秒，0 表示关闭。每条被拒绝的观察记录最多计一次匹配，不同允许不会重复增加同一条拒绝的计数；输入重复的拒绝仍被计为不同观察，没有全局去重。

fanotify 与 BPF 日志可能交错或延后到达，因此同时保留允许记录和未匹配拒绝。拒绝先到、允许后到时，只要原始时间满足条件且记录仍在历史中，也能匹配。拒绝到达时，从已保留的允许中选回复时间最近的一条作为支持证据；允许到达时可解释多个尚未匹配的拒绝。具体支持记录可能随投递顺序变化，这不是因果关系或共同调用 ID。

## 输出与资源边界

每个分段的 behavior 包含规则 ID、窗口、matches、history_evictions 和 evidence_samples。每个支持样本成对保存 permission 与 denial、原始行号及 delta_ns，不依赖普通样本队列是否已覆盖旧记录。权限样本保留 reason、revision；不能由此推断拒绝事件所在的策略 revision。

每组分别最多保留 `--rule-history` 条允许和未匹配拒绝（默认各 32，最大各 128），超限淘汰最早投递的记录。历史淘汰和归组容量淘汰都可能导致漏掉模式；它们会计数，不恢复无限历史。总状态随 max_groups × (rule_history + samples) 增长，处理每条事实最多扫描该组的有界历史。输出在归组淘汰或 EOF 时产生，当前是离线分析接口。

输出始终为 classification=undetermined、interpretation=observation-only、response=none、complete=false。它没有恶意置信度，也没有“安全”结论。文件 inode 重用、日志完整性、代码身份及来源真实性仍未由此验证。进程 exec 后 inode 可以保持，不能据相同进程键认定执行内容相同。历史 inode 也不是可用于发信号的活 pidfd。

## 真实负载与对照

```sh
sudo python3 -B tests/behavior_workloads.py --build-dir build \
  --artifact-dir /tmp/secmon-behavior-captures
```

默认依次运行 open/access × pidfd 关闭/开启四个变体。每个变体创建独立服务、进程和临时目录，只监控本次临时文件。原生 actor 在挂载前打开写 FD；控制器通过真实 pidfd 取得预期进程 inode，不用日志里的数字 PID 作为归组答案。

| 对照 | 预期观察规则结果（开启 pidfd） |
|---|---|
| 仅读取的进程 | 0 |
| 先读、获授权的已打开 FD 写入 | 0 |
| 先读、随后未授权写入 | 1 |
| 维护程序先读，在线撤销写授权后仍尝试写入 | 1，明确的良性匹配反例 |
| 仅写入被拒绝，与其他读取进程不能合并 | 0 |
| 同一进程读取受监控对象、写入另一受保护对象被拒绝 | 0 |
| 读取后等待超过窗口才写入被拒绝 | 0 |
| cat、sha256sum、cp、tar 正常读取/备份 | 0 |

关闭 pidfd 时权限事件计为 unattributed，不用 PID 补身份；规则匹配均为 0，这不表示行为未发生。脚本核对原始拒绝的进程/对象与预期 pidfd 一致，随后分别通过 Python API 和真实 CLI 分析相同原始流，输出必须一致。反向投递原始流后，分组计数与匹配数也必须一致。

完整目录含 256 个普通文件和两个指向受保护文件的别名，共 258 个文件路径。sha256sum 对全部路径建立索引，cp -RL 和 tar 递归备份，并按独立 fixture 逐文件核对字节。另验证硬链接、符号链接、授权重命名及原路径换成不同 inode；替代文件不继承旧对象的归组。这里仅覆盖本机所用工具和该目录负载，不代表所有备份模式或文件系统。

目录和文件规模可显式扩展，例如：

```sh
sudo python3 -B tests/behavior_workloads.py --build-dir build \
  --corpus-files 4096 --protected-bytes 4194304 \
  --artifact-dir /tmp/secmon-behavior-large
```

corpus-files 为普通文件数（1..16384），另外创建两个诱饵别名；payload-bytes 为普通文件大小（1..65536，普通文件合计不超过 128 MiB）；protected-bytes 为受保护文件大小（1..16777216）。默认分别为 256、2048 和 10040。大文件的正常 access 记录可超过有界历史容量，history_evictions 增加属于声明过的证据裁剪，不是恶意标签，也不等于内核或审计丢失。

每个 capture 产物目录含 audit.jsonl、evidence.jsonl 和 manifest.json。manifest 保留机器/boot/capture、原始流和结果 SHA-256、程序及脚本摘要、环境、受控角色和诊断。角色是测试声明，不是生产系统对意图的认证。测试还核对零审计/内核丢失、请求 ID 连续、服务实例、每轮控制器 FD 回到基线及没有遗留子进程。

不需要 root 即可核对已完成的采集包，并比较其他时间窗：

```sh
python3 -B tools/replay_capture.py /tmp/secmon-behavior-captures/cycle-1-open-pidfd-1 \
  --window-ms 0 1 10 100 1000
```

工具先核对两个文件与 manifest 的摘要，再用当前实现重放；只有逐字节重现已保存的 evidence 和相同汇总后，才输出比较结果。缺文件、摘要不符、来源不一致、非法记录或实现结果变化均以非零状态结束，不输出成功结果。manifest 上限 2 MiB，其余输入和结果流式处理。摘要只是与操作者清单的一致性检查，不是签名或来源认证。仅对已完成、不再改写的包执行核查。

并发线程及 PID namespace 到归组的链路另有专题：

```sh
sudo python3 -B tests/behavior_identity.py --build-dir build --report /tmp/behavior-identity.json
```

它覆盖 pidfd 开关、宿主/子 PID namespace 和 open/access 共八个变体。每个进程经历三代并发线程，共 147 次权限允许和 147 次修改拒绝。持续模式的报告只保留最后完整轮的原始投递流，日志逐变体保留累计结果；独立全历史时间 oracle 给出可匹配数，有界历史下的观察数不承诺等于完整 oracle。权限证据始终保留 TGID 而不虚构实际线程，拒绝证据保留 tid/start_ns，进程级匹配不等于相同线程或同一次调用。

## 误报与下一步

多对象拒绝范围、不同对象时间窗与单文件权限审计限制见 [进程内多对象观察](OBJECT_CHAINS.md)。

八类正常应用与受控破坏场景、已有 FD 和跨进程/时间窗边界见 [应用场景验证](BEHAVIOR_APPLICATIONS.md)。

完整输入历史与有界状态的差异、乱序/缺失实验，以及 GNU sed 正常保存反例见 [覆盖评估工具](BEHAVIOR_EVALUATION.md)。

本阶段证明规则可对真实记录关联并复现，同时明确展示正常维护程序也能命中。不能把“先允许访问、后拒绝修改”直接升级为恶意标签或隔离条件。当前只有受控正反例，没有足以估计生产误报率的样本基线。

下一步扩展部署场景的正常应用与已确认攻击样本、记录缺失条件和更长行为链。任何响应方案还需独立明确确认条件、正在持有的进程引用、策略变更权限、回滚和恢复语义，不能拿离线 inode 重新打开数字 PID 替代它。
