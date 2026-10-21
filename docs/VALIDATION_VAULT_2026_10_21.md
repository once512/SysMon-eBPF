# 保险箱会话阶段验收（2026-10-21）

本轮从原规划的“保险箱最小会话”推进，复用文件策略、对象身份和 root 管理通道。合同及使用方式见 [保险箱会话](VAULT_SESSIONS.md)。本记录不把访问控制扩大为加密保险箱、可信代码认证或反勒索自动响应。

## 交付范围

- vault 默认拒绝内容读取和修改；独立 read/read-write 会话按程序 inode、全局 EUID 和目标授权。
- 普通已有 FD 后续读写、打开、私有/共享映射及 mprotect 检查；纯大小截断可使用写会话，元数据、删除、改名、链接仍受限。
- 会话声明含启动 UUID、全局启动时钟签发时间和有界期限。同实例重载及同一系统启动内的服务重启不续期，其他启动的配置保持无效；生成工具为 GNU++17 的 secmon-vault-session。
- 同实例 ID 变更/复用拒绝、关闭墓碑、候选失败回滚，最多 16 配置会话及 4096 历史 ID；管理 v6/392 字节提供配置、有效、旧启动会话数和期限。
- 目标、writer、会话共同使用最多 336 个 inode、352 字节 value 的私有候选 Map。已有 writer 语义保留；目标的 vault 别名不能经 allow-writer 绕过。

## 检查结果

- 原生构建及 32/32 CTest 通过，日志 `/tmp/secmon-vault-final-ctest.log`；Release 构建及 32/32 CTest 通过，日志 `/tmp/secmon-vault-release-ctest.log`。
- 最终完整特权 runner 55/55 通过，专题耗时合计 446.495 秒。包含新增会话、336 项联合容量、服务重启、4096 历史 ID、真实 cat/dd、跨时钟命名空间六个专题，原始日志 `/tmp/secmon-vault-final-regression-v2.log`。
- 真实 cat/dd 验证完整 8192 字节内容读取、授权修改、错误 UID/程序拒绝、关闭后拒绝及服务停止后的独立字节核验。
- 签发工具与服务分处 +3600/-60 秒启动时钟偏移的两个方向，外层独立时钟核对签发和到期。未修改宿主时钟，未重启开发机；旧启动场景通过模拟不匹配 UUID 验证。
- 解析器 libFuzzer 的 ASan/UBSan 构建完成 2,058,904 次输入、121 秒，未发现 sanitizer 错误，日志 `/tmp/secmon-vault-fuzz-run.log`。归一化模型包含 vault、完整会话与启动字段；不是内核/全服务模糊测试。
- 事件编码 ASan/UBSan（含泄漏检测）通过，日志 `/tmp/secmon-vault-event-asan.log`。Clang 静态分析 file_policy.cpp、boot_clock.cpp、vault_session_main.cpp 无诊断，日志 `/tmp/secmon-vault-static-analysis.log`；不代表全程序已无缺陷。
- 15 秒持续预检通过：同一服务 14 轮、434 个原生命令、31 次成功重载、2 个失败候选、42 个历史 ID、238 条拒绝及 70 条过期拒绝。控制器 FD 起止均为 4，产物 `/tmp/secmon-vault-preflight-20261021`。

首轮并发构建/模糊测试时，重启专题的短租期前置条件未满足，完整 runner 中止。将租期从 3 秒改为 10 秒，保留截止时间不变、到期后拒绝和重启后仍拒绝的断言，并从头重跑。失败日志保留在 `/tmp/secmon-vault-final-regression.log`，不算通过。最终原生源码/二进制与初始冻结一致；测试调整仅为 vault_restart.py 的租期及诊断断言。

较早的相对期限检查点 57dcedb 已通过 30/30 CTest 和 51/51 特权回归（424.201 秒），日志 `/tmp/secmon-vault-regression.log`；该旧合同随后被当前绝对期限取代。

## 持续验收

持续脚本为 tests/vault_soak.py。单一服务反复执行短写会话到期、另一 UID 的较长只读会话、第二目标独立写会话、别名旧 FD、关闭、配置重排和准备失败回滚。按原生命令返回码、内核计数、审计条数、过期身份及 FD 回基线交叉核验；最终结果在运行结束后追加。

## 保留边界

已有映射不会被撤销，测试已实际证明到期后仍可通过旧共享映射修改字节。不会收回明文、取消在途 I/O，也没有跨服务间隙的持久 BPF 防护。会话面向匹配程序的所有实例，尚无最终用户认证、动态加载链认证、目录递归、完整特殊 I/O/文件系统覆盖、加密/密钥、备份恢复。虚拟诱饵、在线恶意判定与自动进程响应仍未实现。

## 最终单实例持续验收结果

冻结功能提交 `03b8ed9`，执行：

```bash
sudo python3 -B tests/vault_soak.py --build-dir build --duration 1000 \
  --artifact-dir /tmp/secmon-vault-soak-20261021-F2vgwf
```

完整通过，进程退出码 0：

- 单一服务 PID 83504，最终采样 uptime 1,000,185 ms；整体控制器运行 1,002.461 秒。不是重复启动短实例。
- 909 轮、28,179 次原生命令、909 次短会话到期检查、2,000 次成功重载、130 次准备失败候选，累计 2,727 个会话历史 ID。
- 15,453 条文件拒绝，含 4,545 条预期过期拒绝。独立重读原始流确认每轮分别为 17/5 条；过期拒绝仅来自两个预期进程，进程 inode/start_ns 在整个期间保持各自唯一。
- 总审计 28,247 条，与最终 audit_written 一致；policy_denied 与全部文件拒绝数一致。每次周期/最终输出中的 ringbuf_dropped、baseline_update_failed、audit_dropped、audit_invalid、audit_errno 均为 0。
- 每轮关闭后服务 FD 回基线，控制器起止 FD 为 4/4；最终服务 PID 已退出，未留下 secmon 测试进程。
- 持续段前后共 259 项已提交文件及所用二进制摘要全部一致。随后只更新本文等验收/推进文档，不将文档变更混入被测功能提交。

原始日志 `/tmp/secmon-vault-final-soak.log`。产物目录包含 audit.jsonl、diagnostics.log、cycles.jsonl、summary.json、source_sha256.json，以及独立核验后的 verified_manifest.json；后者记录各产物大小与 SHA-256。摘要中 secmon 为 `9011e4d226f62d69eb5774c75bf9ff9d58c2b49445dd151974ad441d0cc96549`，会话工具为 `504365562575c05342ee876e4e6971b48cacbb7e5eb44ca5b11d5f55fa499b80`。

该结果覆盖受控指定文件会话的持续执行和审计守恒，不证明全部内核资源生命周期、生产性能、真实攻击识别率或未覆盖 I/O 的安全性。
