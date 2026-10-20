# 正常应用与受控破坏场景

`tests/behavior_applications.py` 将八类场景分别放入独立临时目录和服务实例，验证 open/access × requester pidfd 开关，共 32 个变体。测试只操作自建文件，角色仅声明实验意图。

```sh
sudo python3 -B tests/behavior_applications.py --build-dir build \
  --artifact-dir /tmp/secmon-application-captures
sudo python3 -B tests/run_privileged.py --build-dir build --only behavior-applications
```

所有目标均启用 BPF 修改保护，fanotify 访问裁决为 allow。观察窗口为 1000 ms，历史容量 128。下表命中列针对 pidfd 开启；关闭时权限证据缺少所需进程键，均不关联。

| 场景 | 实际操作与结果 | 观察规则命中 |
|---|---|---|
| benign-inplace-save | Python 普通文件保存，读取后 pwrite 被拒绝 | 是 |
| benign-sed-save | GNU sed -i 读取、写临时文件、替换目标被拒绝 | 是 |
| benign-sqlite-update | SQLite 读写打开被拒绝，回退只读后读取成功，更新报 SQLITE_READONLY | 否 |
| benign-log-rotation | GNU mv 将日志改名，被拒绝 | 否 |
| controlled-read-overwrite | 读取内容、计算 XOR 替换内容、pwrite 被拒绝 | 是 |
| controlled-truncate | 不先读取，直接 truncate 被拒绝 | 否 |
| controlled-split-process | 独立 cat 进程读取，另一进程通过已有 FD 写入被拒绝 | 否 |
| controlled-delayed-write | 读取后等待 1.2 秒，再通过已有 FD 写入被拒绝 | 否 |

Python 保存及覆盖/分进程/延迟场景在保护启用前打开可写 FD；保护启用后才执行读取和写入。读取另外正常打开目标，写入使用已有 FD。此安排验证已有能力仍受修改保护，且延迟写入前不会因重新打开而刷新访问时间。GNU sed、GNU mv 和 SQLite 在服务启用后正常启动。日志轮转只覆盖改名步骤，不代表完整 logrotate 配置或压缩/清理链；Python 保存也不等于完整交互编辑器验收。

“正常”与“受控破坏”是操作者声明的实验意图。XOR 覆盖只模拟读取后破坏的操作，不等于完整勒索软件样本；直接截断、跨进程、超过窗口的写入仍被原生保护拒绝，但不满足现有观察规则。规则未命中不等于原生防护失败，正常保存命中也不等于已确认攻击。

## 验证与采集合同

控制器在子进程操作前取得真实 pidfd，并持有至本变体验收结束。SQLite 必须返回 SQLITE_READONLY；Python 修改必须返回 EACCES；GNU sed 和 mv 的退出码分别为 4 和 1。所有变体要求目标 inode 和全部字节不变，SQLite 额外检查 integrity_check 和原记录。

测试核对 BPF 拒绝的进程键、设备/inode 和 EACCES，权限请求 ID 连续、服务实例、对象和 pidfd 主体，以及零审计/内核丢失、零历史淘汰。每个变体比对 CLI 与库结果，执行反序回放和独立完整时间参考算法；控制器 FD 恢复基线且无遗留子进程。

每包保存 audit.jsonl、evidence.jsonl、manifest.json，全部完成后生成 summary.json。清单包含角色、声明意图、目标不变断言、环境和实现摘要。SQLite 结果反映当前 Python/SQLite 版本；其他版本行为变化时测试会失败，需独立核对后更新合同。摘要不证明采集来源真实性。

```sh
python3 -B tools/replay_capture.py CAPTURE_DIRECTORY
python3 -B tools/evaluate_capture.py CAPTURE_DIRECTORY \
  --window-ms 100 1000 5000 --history 32 128
```

更长时间窗可以使延迟写入变为可观察，但无法解决跨进程身份边界、直接截断和正常保存混淆。后续仍需选择明确部署应用，补充已确认攻击样本和独立判定依据，再设计误报控制与响应条件。
