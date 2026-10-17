# 验证入口与覆盖矩阵

先构建，再运行无特权检查：

```bash
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
./build/secmon --check
```

当前 CTest 有 21 项（含审计输出队列与事件格式边界），覆盖命令行拒绝、确定性裁决时钟与 FD 所有权、基础执行及线程/exec 场景工具，以及分析协议、真实扫描和接收 FD 前的内存分配故障。它们不加载 BPF，也不证明内核策略生效。

## 一次运行特权回归

```bash
sudo python3 tests/run_privileged.py --build-dir build
# 可选：再运行两种模式各 90 秒的并发负载
sudo python3 tests/run_privileged.py --build-dir build --soak-duration 90
# 只运行一个专题
sudo python3 tests/run_privileged.py --build-dir build --only credential-transitions
```

BUILD_TESTING 开启时还需要 Python 3 解释器，用于无特权协议验证。

入口按顺序启动测试，失败即停止，最后输出每项结果与耗时的 JSON 汇总。不要使用 `python -O` 或 `PYTHONOPTIMIZE`，测试需要启用断言。运行前停止手工启动的旧版 secmon，避免额外策略影响结果。

要求 root、活动 BPF LSM、BTF 和 fanotify 权限事件支持。凭证 Map 检查使用系统 libbpf 与 bpftool，合法权限转换实验另需 `setcap`。临时文件系统须支持相关标记、setuid、文件 capabilities 与执行；不满足时报告失败，不悄悄省略场景。

| 入口名称 | 脚本 | 验证内容 |
| --- | --- | --- |
| shutdown-order | `shutdown_order.py` | 填满 stderr 后停止仍先关闭权限组，不留下无人处理的打开请求 |
| audit-backpressure | `audit_backpressure.py` | 审计 stdout 堵塞/恢复/断开/持续洪流时的裁决、重载与停止；用户态丢失可诊断 |
| audit-file | `integration.py` | 执行/凭证事件、旧 TID、文件只读的 13 类拒绝、读取与私有映射、退出解除 |
| self-protection | `self_protection.py` | 信号、ptrace 类检查、管理端身份、授权停止、期限及 socket 清理 |
| fanotify-open | `fanotify.py` | 单文件打开裁决、硬链接/重命名、已有 FD、崩溃释放 |
| fanotify-deferred | `fanotify_deferred.py` | 延迟、接收后超时、容量回退、队列预算、正常退出排空 |
| analysis-faults | `fanotify_analysis_faults.py` | 错误/重复/迟到回复、FD 超额、请求取消及后端隔离 |
| fanotify-analysis | `fanotify_analysis.py` | 独立进程内容扫描、传递 FD、无递归、降权与故障回退 |
| fanotify-events | `fanotify_events.py` | 普通读取、mmap 边界、ELF/脚本直接执行与解释读取区别 |
| fanotify-policy | `fanotify_policy.py` | 共用配置、静态与扫描模式、空闲切换/忙队列拒绝、固定后端、配置自阻塞防护、FD 稳定 |
| policy-consistency | `policy_consistency.py` | 同进程活动来源、联合 revision/摘要、预期版本与只读查询 |
| unified-service | `unified_service.py` | 同进程双模块、联合重载、准备/忙时回滚、协调停止、启动失败清理与独立分析器故障 |
| management-live | `management_live.py` | 活动内存查询、稳定重载错误、独立版本、忙请求、权限与 FD 稳定 |
| management-faults | `management_faults.py` | 伪服务错误帧/身份/附带 FD 的客户端拒绝 |
| control-loop | `control_loop.py` / `control_nonblocking.cpp` | 静默连接无阻塞推进与稍后发送，root 身份，不加载内核策略 |
| pid-namespace | `pid_namespace.py` | 局部 PID=1 与宿主 BPF 身份、真实凭证和退出基线删除；非真实宿主 PID 复用 |
| namespace-policy | `namespace_policy.py` | 私有 bind 别名与私有 tmpfs 的跨挂载对象策略、两层独立清理 |
| writer-matrix | `writer_matrix.py` | 固定随机种子的独立 Python 规则模型、真实 Map 全字段、新写操作及候选失败回滚 |
| writer-scope | `writer_scope.py` | 每目标/操作授权、已有 FD、新打开、别名位合并、重命名双操作数、规则重排与撤销 |
| writer-capacity | `writer_capacity.py` | 256+64 不同 inode、完整候选失败回滚、重合标志、旧 Map 快照/回收与按路径 FD 回收 |
| writer-layers | `writer_layers.py` | 共用来源、BPF 授权与 fanotify 独立裁决、既有 FD 与撤销 |
| writer-identity | `writer_identity.py` / `writer_scenario.cpp` | 程序 inode 与 EUID、fork/exec、别名和替换、程序保护、授权撤销与失败回滚 |
| policy-reload | `policy_reload.py` | 真实 BPF 完整切换、版本拒绝、准备失败保留旧保护、配置权限、root 控制与重复切换 FD 回收 |
| policy-layers | `policy_composition.py` | BPF 与 fanotify 同时启用，允许不覆盖拒绝，两层独立停止 |
| baseline-lifecycle | `baseline_lifecycle.py` | 活线程 Map key/value、join 删除、合法降权、非主线程 exec 与最终删除 |
| credential-transitions | `credential_transitions.py` | 临时普通、setuid 和 file-capability 程序的真实凭证与事件一致 |
| baseline-mismatch | `baseline_mismatch.py` | 私有测试 Map 的合成不一致、flags 位 0、exec 后刷新，不修改真实任务凭证 |
| soak-policy/soak-timeout | `fanotify_soak.py` | 可选的持续并发负载，用户态队列与 FD 上限、客户端结果和回复总量对账 |

测试文件、socket、root 所有的辅助程序及权限设置均放在临时目录。BPF 专题会实际加载/挂载内核程序，随后解除；fanotify 实验会暂时影响对应临时文件的打开、读取或执行。合成不一致只写本次宿主 Map 中由受控测试进程保持存活的确切 key，不扫描或修改其他实例 Map，不执行真实内核攻击。

## 已验证与尚未验证

已分别完成两轮 300 秒 fanotify 负载，处理 231241 和 231760 次打开，全部回复对账一致；配置 pending=4 时 FD 基线 5、峰值 10，未见随时间增长。详细数字和阶段记录保留在 DESIGN 中。

这些结果不是吞吐基准，也不覆盖所有文件系统和命名空间。真实内核队列溢出、真实 PID 复用、完整容器支持、异步 I/O、真实提权攻击和更复杂分析引擎的故障仍需后续专项验证。独立字节扫描组件的崩溃、卡住、协议异常、初始化失败及请求取消现已覆盖。用户态容量回退与内核队列溢出是两件不同的事。

专题导读：[源码结构](CODE_GUIDE.md)、[fanotify](FANOTIFY_LAB.md)、[策略组合](POLICY_LAYERS.md)、[凭证生命周期](CREDENTIAL_LIFECYCLE.md)。


独立分析组件可加入两种权限入口的持续负载（各指定秒数，交替修改临时文件内容）：

```bash
sudo python3 tests/run_privileged.py --build-dir build --analysis-soak-duration 30
```

示例扫描只做字节标记匹配，详细故障预算见 [分析组件导读](ANALYSIS_WORKER.md)。

带运行 revision 的文件配置增加无特权 `policy-config` CTest，格式与在线切换边界见 [策略配置](POLICY_CONFIG.md)。

`analysis-scan-errors` 使用仅测试目标的系统调用/分配包装，验证扫描原因和 errno；有效错误回退与畸形错误报文另由真实权限专题覆盖。

私有挂载的范围与限制详见 [命名空间策略验证](NAMESPACE_POLICY.md)。

本轮完整的分阶段验证数字与代码快照范围见 [2026-10-17 验证记录](VALIDATION_2026_10_17.md)。

## 程序对象授权的持续验证

```bash
sudo python3 tests/run_privileged.py --build-dir build \
    --only writer-identity writer-capacity writer-layers --writer-soak-duration 30
```

writer-soak-duration 默认 0（禁用），可选 5..1800 秒。常驻程序分别保持 root、65534 与未授权对象身份，在 O_PATH 固定策略切换期间持续尝试已有 FD 写入和新 open；每次确认更新后同步验证新规则，记录背景结果、更新/拒绝次数、来源摘要和闲置 FD 基线。它不验证共享映射追回或性能 SLA，不能替代真实攻击测试。详细边界见 [程序对象授权](WRITER_IDENTITY.md)。

## 构建与回归的产物隔离

运行特权回归时，不要同时重新链接它正在使用的同一 build 目录。链接器替换可执行文件期间，测试子进程可能碰到不可执行或不存在的文件。需要并行开发时，先完成构建，再将所需可执行程序复制到独立快照目录，通过 --build-dir 指向该目录；构建继续写原目录。架构整理这一轮使用 build/structure-checkpoint 验证固定产物，避免将构建竞态解释为后端裁决失败。

机制专题的 harness 使用同一个 secmon 可执行文件加 --bpf-only/--fanotify-only，仅为独立观察裁决层。unified-service 与 policy-consistency 使用默认联合入口和一个管理 socket。

## 同进程联合持续负载

```bash
sudo python3 tests/run_privileged.py --build-dir build --only writer-scope unified-service \
    --combined-soak-duration 30
```

此选项依次增加静态 open、分析 open、分析 access 三项，每项运行指定秒数（0 禁用，5..1800 秒）。同一主服务同时运行 BPF 与 fanotify，联合更新静态裁决/扫描内容及一条按目标的写授权。原生探针在监听前保留 FD，每次确认后验证授权目标、未授权目标、未授权程序的已有 FD 和新打开。业务回复全部对账，联合模式还检查审计队列/内核丢失与基线更新失败计数；闲置 FD 按当前规则数回归，峰值含已交付请求与临时连接；不把闲置采样称为准备阶段的全资源峰值。

`writer-matrix` 使用固定种子独立生成按目标/操作的规则模型，比较真实 HASH value 的 flags、UID、主体规则位和八类目标位，再核对每次成功后的实际写打开/写入。它也验证字段乱序、别名、同 inode UID 冲突和规则位重排。可单独指定 --seed/--iterations 复现；随机覆盖不能代替所有内核入口的覆盖证明。

纯解析的 sanitizer/libFuzzer 入口另见 [配置模糊测试](POLICY_FUZZING.md)。

审计出口的队列边界、线程分工、输出失败行为及诊断限制见 [有界审计出口](AUDIT_OUTPUT.md)。

单独运行 management_soak.py 时可用 --combined --verify-audit-output 开启当前审计出口健康检查；该模式要求所有相应字段存在且错误/丢弃为零，不把旧字段缺失当作通过。

本轮目标授权、审计出口与持续负载的具体产物/范围/数字见 [2026-10-18 验证记录](VALIDATION_SCOPED_2026_10_18.md)。
