# 验证入口与覆盖矩阵

先构建，再运行无特权检查：

```bash
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
./build/secmon --check
```

当前 CTest 有 30 项（含独立审计/诊断输出队列、BPF 事件及 fanotify 裁决格式边界，以及离线归组、行为、重放、评估和多对象检查），覆盖命令行拒绝、确定性裁决时钟与 FD 所有权、基础执行及线程/exec 场景工具，以及分析协议、真实扫描和接收 FD 前的内存分配故障。它们不加载 BPF，也不证明内核策略生效。

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
| permission-audit | `permission_audit.py` | 逐请求身份/对象、revision/回滚、六类原因、open/access/exec 与汇总对账 |
| decoy-evidence | `decoy_evidence.py` | 受控读取、授权修改、旧 FD、未授权修改与撤销后的证据关联 |
| decoy-workloads | `decoy_workloads.py` | 完整文件索引/备份、硬链接/符号链接、改名与原路径 inode 替换 |
| identity-threads | `identity_threads.py` | 并发 TGID/TID、task start 键、线程重建/退出及宿主/子 namespace |
| permission-namespace | `permission_namespace.py` | 子 namespace 监听器的局部 TGID、不可见请求 PID=0 与坐标字段 |
| requester-pidfd | `requester_pidfd.py` | 取消、容量、停止、超时、分析成功/错误、FD 压力及直接 exec 的内核引用与回收 |
| requester-lifecycle | `requester_lifecycle.py` | 宿主/子 namespace 的 exec、非 leader exec、leader 单独退出和稳定进程 inode |
| permission-audit-backpressure | `permission_audit_backpressure.py` | 两种后端下逐请求审计的堵塞/恢复/断开/持续洪流，裁决/重载/停止仍可用 |
| diagnostic-backpressure | `diagnostic_backpressure.py` | stderr 启动已满、失败重载洪流、周期报告、恢复/断开时裁决与管理继续，停止不依赖排空诊断 |
| shutdown-order | `shutdown_order.py` | 填满 stderr 后不排空也完成退出，释放权限组 |
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
| credential-transitions | `credential_transitions.py` | 普通、setuid/setgid、file-capability 和子 user namespace 的完整凭证与事件一致 |
| baseline-mismatch | `baseline_mismatch.py` | 私有测试 Map 的 14 个单字段合成不一致、flags 位 0、exec 后刷新，不修改真实任务凭证 |
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

management_soak.py 的所有后端还核对 diagnostic_dropped/diagnostic_invalid/diagnostic_errno 为零，诊断队列不超过 256 条。

单独运行 management_soak.py 时可用 --combined --verify-audit-output 开启当前审计出口健康检查；该模式要求所有相应字段存在且错误/丢弃为零，不把旧字段缺失当作通过。

本轮目标授权、审计出口与持续负载的具体产物/范围/数字见 [2026-10-18 验证记录](VALIDATION_SCOPED_2026_10_18.md)。

诊断洪流可单独提高到每种场景 400..10000 次失败重载，并并发核对 status/权限请求与主服务 FD 预算：

```bash
sudo python3 -B tests/diagnostic_backpressure.py --build-dir build --reload-count 3000
```

四种场景依次运行，内部服务期限随请求数扩大；不要同时重新链接该 build 目录。洪流后的诊断丢弃属于预期结果，管理拒绝计数必须仍与尝试次数一致，临时管道恢复后队列可排空，断开时 errno 必须为 EPIPE。

本轮诊断隔离的构建快照、背压实验与持续负载范围见 [诊断隔离验证记录](VALIDATION_DIAGNOSTIC_2026_10_18.md)。

逐请求权限审计可增加三项带审计记录对账的联合持续负载（每项 0 或 5..1800 秒）：

```bash
sudo python3 -B tests/run_privileged.py --build-dir build \
    --only permission-audit permission-audit-backpressure --permission-audit-soak-duration 30
```

具体字段与输出模式见 [fanotify 逐请求裁决审计](PERMISSION_AUDIT.md)。management_soak.py 也可单独使用 --audit-permissions；联合模式可同时指定 --verify-audit-output 检查共享队列和内核计数。

## 进程、线程与 namespace 身份

离线证据工具不需要 root，已纳入 CTest；使用方法与证据边界见 [离线证据归组](OFFLINE_EVIDENCE.md)。

```sh
sudo python3 -B tests/run_privileged.py --build-dir build --only identity-threads permission-namespace
sudo python3 -B tests/identity_threads.py --build-dir build --duration 900 --report /tmp/identity-soak.json
```

当前默认 runner 运行 49 个专题/模式变体（46 个可选专题，另追加线程、namespace、背压的 pidfd 变体）。持续身份循环覆盖完整服务/观察器及线程创建退出，核对基线键回收和控制器 FD；报告保留累计循环数、累计回复/拒绝数及最后完整循环的原始证据。并发时间窗只输出候选线程集合，不把 TGID 升格为线程身份。前提、字段和限制见 [身份合同](IDENTITY_CONTRACT.md)。

真实审计流至离线规则的完整链路见 [行为观察规则](BEHAVIOR_OBSERVATION.md)。`behavior-workloads` 内含四种模式及第三方目录备份负载；可单独使用 `--duration 3600` 重复完整循环，并用 `--artifact-dir` 保留每个服务实例的原始流、结果及来源清单。持续运行应冻结 Python 脚本与可执行文件，避免验证中途改变实现。

`offline-capture-evaluation` 检查独立完整历史参考算法、乱序、输入缺失、容量漏匹配及采集包完整性；工具与新增 `--mutation-attempts` / `--benign-edit` 真实负载见[覆盖评估](BEHAVIOR_EVALUATION.md)。

新增 `behavior-applications` 专题包含普通文件保存、GNU sed、SQLite 和日志改名，以及四类受控破坏操作，共 32 个变体；场景前提和观察边界见[应用场景验证](BEHAVIOR_APPLICATIONS.md)。

`offline-object-chains` 与特权 `behavior-chains` 专题分别验证完整输入上的不同对象窗口算法、八对象七进程真实负载；见[多对象观察](OBJECT_CHAINS.md)。

`fanotify-multiple` 验证固定多目标及共享预算，涵盖启动清理、并发裁决、重载拒绝/回滚、配置硬链接自我等待防护、分析/超时/容量/停止与 exec。`behavior-chains --mark-all --objects 64` 可运行最大目标数负载；资源和版本合同见[多目标订阅](FANOTIFY_MULTITARGET.md)。

`fanotify-handover` 验证[即时静态 allow 模式的在线目标切换](FANOTIFY_HANDOVER.md)：共同 inode 保留、删除/重加、候选与 BPF 准备失败、唯一请求序列、累计统计及切换审计事件；另覆盖 64/65 边界、内核积压请求、busy/延迟/分析限制。可用 --rounds 128 --duration 1200 持续运行并保存逐实例采集包。

`subscription-generations` 验证离线订阅代际与乱序边界；`subscription-lifecycle` 特权专题让同一进程持有旧 FD，验证保留/移除/重加同一 inode 时不沿用旧访问证据。

`writer-lease` 验证内核按启动时钟收回维护写例外：已有 FD、新打开、mmap/mprotect、程序/目标范围、失败与同版本不续期、显式续期、删除授权和服务被 SIGSTOP 时仍到期。测试只暂停未启用自保护的临时实例，结束前恢复服务。

`userns-credentials` 验证本地 root 的全局 UID/GID 仍为 65534，且不继承宿主 UID 0 的程序写授权。`lease-time-namespace` 从外层独立时钟核对 +3600/-60 秒偏移服务的租期，使用 BPF-only 临时实例，不代表 fanotify 跨 time namespace 时间关联已验收。

保险箱专题：`--only vault-sessions vault-capacity`，验证限时读写、关闭、暂停服务、ID 合同与 336 项联合容量，详见 [会话合同](VAULT_SESSIONS.md)。
