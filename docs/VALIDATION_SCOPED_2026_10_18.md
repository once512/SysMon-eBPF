# 2026-10-18：目标授权与统一主进程可靠性验证

本轮从 17 日深夜持续到 18 日凌晨，按约一个半小时推进。实现范围是按目标/文件检查点授权、配置模块整理，以及统一主服务的审计输出与退出边界；真实诱饵、行为识别、完整可信内容/加载链认证和保险箱会话尚未因此完成。

环境为本机 x86_64 Linux 6.12.0-211.61.1.el10_2.x86_64，活动 BPF LSM/BTF 和 fanotify 支持沿用项目既有环境。以下是可复现的开发回归，不是产品性能 SLA 或完整安全审计。

## 实现与学习入口

| 提交 | 主要内容 |
| --- | --- |
| 8de8a56 | 配置来源读取、字段构建拆分及 C/BPF/C++ 共用容量 |
| ccc734d | 明确程序、EUID、目标和操作的授权规则；80 字节私有 Map value |
| 4b596dc | Clang libFuzzer/ASan/UBSan 纯解析目标、边界种子和属性检查 |
| d0fb0fc | 纯事件编码、有界 AuditSink、主循环公平性、线程安全停止和先关权限组再统计 |
| 243a7de | 独立 Python 规则模型、64 条同主体边界、同进程健康负载工具 |
| b1116f9 | 矩阵工具的运行时限随迭代次数变化；默认 40 次仍为 180 秒 |

配置当前写法为 `allow-writer "/program" EUID "/explicit/protect/target" open-write,write`。旧的程序/UID 两字段全局授权写法直接拒绝；没有格式版本或历史管理协议转换。每条规则选中一个目标和检查点集合，all 也只限本条目标。读法与限制见 [授权导读](WRITER_IDENTITY.md)、[单服务结构](UNIFIED_SERVICE.md) 和 [审计出口](AUDIT_OUTPUT.md)。

## 最终短回归与插桩检查

- 最终 C++ 产物固定到 build/audit-shutdown-final，完整 38 项权限/负载回归通过：27 个核心专题加 11 项各 10 秒负载。原始本机日志 /tmp/secmon-final-full.log。
- 后增的显式审计健康检查模式另完成 shutdown-order 和静态 open/分析 open/access 三项各 10 秒负载，全部通过；结束时 ringbuf_dropped、baseline_update_failed、audit_dropped、audit_invalid、audit_queued、audit_errno 为 0。日志 /tmp/secmon-verified-combined-smoke.log。
- 普通及 libstdc++ 调试构建各 21 项 CTest、三个正式程序生产构建、31 个手写生产头文件独立编译通过。
- AuditSink 的真实管道/socket/普通文件及四生产者测试在 ThreadSanitizer 和 ASan/UBSan 下通过，覆盖输出标志、共享文件偏移/追加、背压恢复、EPIPE、退出丢弃及并发对账。
- Clang 静态分析完成 41 次生产源翻译单元分析（含不同目标复用同源），随后更新的输出/生命周期单元补查无诊断。该检查不构成无漏洞或所有交错无竞争的证明。
- 纯解析 fuzz 运行 1801 秒，执行 22,274,693 次输入，未触发 sanitizer 或重编码属性失败；新增语料单位 3616，峰值 RSS 734 MiB。内存含插桩/隔离区/语料开销，不代表生产服务。复现见 [模糊测试](POLICY_FUZZING.md)。

## 固定产物与持续负载范围

三个阶段使用不同的不可变可执行快照，不在测试期间覆盖其二进制：

| 快照 | secmon SHA-256 | 解释范围 |
| --- | --- | --- |
| build/scoped-final | 2de7e24748c2985a6dbd16e054beb7b5efe03fde3e233816a181beee12911d10 | 授权完成、异步审计之前；证明目标/操作/EUID 切换 |
| build/audit-final | 6d08f2ae001b0736403908bfdc51774ac97200f5fa33296c58cce15a5ead2667 | 审计初版；后来补共享文件偏移和关闭权限组时序，不作为最终这些修正的长测证据 |
| build/audit-shutdown-final | fd77b460351aa010846e34bff51102c118c6b6591ddc72b41da8501170f15d98 | 最终生产源码 d0fb0fc，配合当前测试工具验证健康队列、内核计数及联合授权 |

最终分析器 SHA-256 为 c99aad5add45d93d27dc6bd4df24e7a15452f20706b81015bf8913ea08ce361f，管理工具为 e5301965401737ca5c59ebcea123faf88cc772e31a341f9ce156eb587121851b。三个生产程序始终绑定使用同包接口；快照差异仅用于区分本轮历史验证范围。

| 阶段 | 模式 | 秒数 | 业务请求 | 成功更新 | 服务 FD 基线/观测峰值 |
| --- | --- | --- | --- | --- | --- |
| 授权快照 | static/open | 1200 | 910408 | 566 | 54/58 |
| 授权快照 | analysis/open | 1200 | 1814335 | 565 | 56/60 |
| 授权快照 | analysis/access | 1200 | 1798018 | 565 | 56/60 |
| 授权快照 | EUID 轮换/撤销 | 600 | 背景请求 88799 | 2109 | 50/51（闲置） |
| 审计初版快照 | static/open | 600 | 454431 | 282 | 55/59 |
| 审计初版快照 | analysis/open | 600 | 903207 | 281 | 57/61 |
| 审计初版快照 | analysis/access | 600 | 899677 | 281 | 57/61 |
| 最终产物 | analysis/access | 1200 | 1801106 | 562 | 57/61 |

全部持续任务均已正常退出。最终产物的 output-health 核对确认 ringbuf_dropped、baseline_update_failed、audit_dropped、audit_invalid、audit_queued、audit_errno 均为 0。

这些场景部分并行，表中时长不能直接相加作为本轮墙钟时间。FD 基线/业务采样峰值不代表候选准备时全部瞬时资源峰值，更不等同于全进程内存无增长。每次确认后检查新操作，背景请求可能跨版本，因此不以背景结果推断跨钩子原子切换。

静态/分析负载使用八个业务请求线程，阶段间排空后更新，额外核对指定目标、未授权目标与未授权程序的已有 FD/新打开。单独 EUID 负载保持 root、65534 和未授权原生程序存活，轮换身份与撤销，并拒绝错误候选。EUID 负载完成 2109 次更新、301 次错误候选拒绝、88799 次背景操作，未授权程序 29603 次全部拒绝；每次确认后另有六次同步新操作检查，未混入背景数。独立 writer-matrix 默认种子 5456717，40 次提交、6 次冲突 UID 候选拒绝，逐字段模型和实际新写结果一致。

## 复现与边界

```bash
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
sudo python3 tests/run_privileged.py --build-dir build \
    --soak-duration 10 --analysis-soak-duration 10 --management-soak-duration 10 \
    --combined-soak-duration 10 --writer-soak-duration 10
# 最终产物的同进程健康长测：
sudo python3 tests/management_soak.py --build-dir build --combined \
    --verify-audit-output --backend analysis --event access --duration 1200
```

长测使用已完成构建的独立快照；不要同时重新链接测试正在执行的目录。测试仅创建临时文件/策略、进程和内核对象，结束时清理，收尾未见残留监控、分析器、管理客户端或临时原生测试进程；本记录不将以前的历史验证替代当前源码检查。

已确认的边界保持明确：授权仍按执行 inode/EUID，不认证动态库、插件或运行时内容；既有共享可写映射不能靠撤销追回。stdout 背压与断开不会直接卡主循环，但 stderr 诊断仍同步，普通存储 I/O 阻塞也不受非阻塞管道期限保证。停止已先关闭 fanotify 组，避免诊断等待留下无监听处理的权限请求。服务崩溃不提供持久拒绝保护，其他文件系统/容器、异步 I/O 和真实攻击仍需各自验证。
