<p align="center">
  <a href="./README_en.md">English</a>
  &middot;
  <a href="./README.md">简体中文</a>
</p>

# SecMon

在所有的Linux系统监控方法中，唯有基于eBPF方法没有做过了，故创建此开源仓库

也欢迎和我一样有兴趣的人一起加入并迭代这个项目

## 当前实现

目前实现执行与凭证审计、指定文件对象的只读保护与授权修改原型，以及可选的 secmon 进程自保护；同一主进程内提供[最多 64 个固定目标的 fanotify 裁决](docs/FANOTIFY_MULTITARGET.md)，支持[即时 allow 模式的在线目标切换](docs/FANOTIFY_HANDOVER.md)，另以独立降权进程完成有界字节标记扫描实验。已有临时真实诱饵的受控证据、完整文件读取/备份实验，以及按可信进程键归组的[离线行为观察规则](docs/BEHAVIOR_OBSERVATION.md)，包含真实第三方目录负载与良性匹配反例。生产诱饵管理、真实恶意行为识别和完整保险箱仍待实现。

总体方案见 [DESIGN.md](DESIGN.md)，学习入口见 [代码导读](docs/CODE_GUIDE.md)。结构与面向对象评估见 [架构整理](docs/ARCHITECTURE_REVIEW.md)，验证入口见 [测试矩阵](docs/TESTING.md)，当前待办见 [下一步](docs/NEXT_STEPS.md)。

- 管理员可声明 [canary 诱饵修改响应](docs/CANARY_RESPONSE.md)：修改尝试被拒绝后，对触发线程组施加有期限的文件修改、fork/clone 和 exec 限制；读取不触发，尚非通用恶意分类。验证结果见[本轮验收](docs/VALIDATION_CANARY_2026_10_21.md)。
- 可选 [FUSE 虚拟诱饵视图](docs/VIRTUAL_DECOYS.md)提供没有磁盘后端的合成文件，复用上述 canary 策略与响应。可[由主服务显式托管启动与进度监督](docs/MANAGED_DECOYS.md)，保留独立挂载方式；尚无业务目录透明注入或自动重挂载重新绑定。验证范围见[阶段验收](docs/VALIDATION_VIRTUAL_2026_10_23.md)。
- fanotify 的静态及[内容分析路径](docs/ANALYSIS_EVENT_READER.md)均隔离事件文件读取与释放；[读取者进度](docs/READER_HEALTH.md)可在状态查询中观察，超过两秒未确认会标为无响应，不自动重建权限组。
- 自保护覆盖主服务及其[特权直接辅助进程](docs/HELPER_PROTECTION.md)，保留授权停止和降权分析器错误回退。
- GNU++17 宿主使用 libbpf skeleton 加载、挂载和消费事件。
- 在执行安全检查点输出 JSON Lines；这些事件表示执行检查，不表示执行最终成功。
- 新增 `exec_success` 完成事件及 `old_tid` 字段，区分检查与成功，并关联非主线程 exec 前后的 TID；该事件的 `flags=0` 不代表执行后重新做过异常检查。
- 同一次执行可能多次经过检查点（例如脚本与解释器处理），不按检查事件数量统计成功执行次数。`comm` 是检查时的当前任务名，可能仍为调用者名称；`filename` 是本次执行请求路径。
- 在 `commit_creds` 返回后、fork 和 exec 完成时记录已观测凭证，按线程生命周期清理。
- 凭证与基线不一致时设置事件 `flags` 的位 0，仅审计，不阻断。合法提交也可能来自攻击，基线不等同于可信授权。
- 执行凭证观测包含保存/文件系统 UID、各类 GID、五类 capability 集合及 user namespace；这是完整性线索，不是提权来源认证。
- `--audit-permissions` 可记录每次 fanotify 权限回复的请求身份、对象、revision、原因和耗时，与 BPF 事件共用有界 stdout；见 [逐请求裁决审计](docs/PERMISSION_AUDIT.md)。可选 `--requester-pidfd` 保留内核请求方引用并输出经验证的进程 inode，见 [请求方 pidfd](docs/REQUESTER_PIDFD.md)。TGID/线程、namespace 及生命周期关联边界见 [身份合同](docs/IDENTITY_CONTRACT.md)。
- stderr 诊断使用独立有界队列，阻塞/断开不拖住裁决和管理循环，状态查询提供诊断丢弃与出口错误；详见 [诊断出口](docs/AUDIT_OUTPUT.md) 与 [本轮验证](docs/VALIDATION_DIAGNOSTIC_2026_10_18.md)。
- 审计 JSONL 经有界队列由独立 I/O 线程写 stdout；背压/输出错误可查询，不直接拖住 fanotify 裁决。每 10 秒及退出时向 stderr 输出内核丢失、基线失败和审计出口计数，详见 [审计出口](docs/AUDIT_OUTPUT.md)。
- 可通过重复的 `--protect-file PATH` 参数启用指定文件只读保护，另输出拒绝操作计数及 `file_denied` 事件。
- 配置可加入 `writer-lease-ms` 限制维护写例外的期限，内核按启动时钟收回；成功新策略会重新计时，语义与既有映射限制见 [策略配置](docs/POLICY_CONFIG.md)。
- 指定文件可使用 [vault 与限时读写会话](docs/VAULT_SESSIONS.md)，默认锁定读取，关闭或到期后重新限制普通已有 FD，绝对期限跨服务重启保留；尚无加密和最终用户认证。
- `secmon-policyctl --socket SOCKET` 只读核对活动策略和可选预期 revision；`--require-ready`及`--require-decoy`可进一步要求采样后端就绪及托管视图存在。
- `--status SOCKET` 查询活动版本、重载结果与后端状态，`--reload` 返回结构化结果，详见 [管理接口](docs/MANAGEMENT.md)。
- `--policy FILE` 加载带递增 revision 的文件策略，`--reload SOCKET` 在线完整替换；同一主进程同时应用 BPF 和 fanotify 字段，支持空闲时联合更新，详见 [策略配置导读](docs/POLICY_CONFIG.md)。
- 配置中的 `allow-writer` 按执行文件 inode、有效 UID、目标 inode 与操作检查点授予文件修改例外，并自动保护程序对象；详见 [程序对象授权](docs/WRITER_IDENTITY.md)。它尚不认证程序内容、加载链或运行时状态。本轮目标/操作授权与审计可靠性验证见 [最新记录](docs/VALIDATION_SCOPED_2026_10_18.md)，此前结果见 [授权阶段记录](docs/VALIDATION_WRITER_2026_10_17.md)。
- `--self-protect SOCKET` 启用自身任务保护，管理退出通过 `--stop SOCKET`；自保护拒绝输出 `self_denied` 事件与累计计数。

服务只有一个入口：`main` → `MonitorService` → `BpfMonitor` / `FanotifyMonitor`。一份配置、一个管理 socket、一次重载统一协调两个对象；分析器继续独立降权运行。`--bpf-only` 与 `--fanotify-only` 供机制诊断，正常部署无需分别启动。详见 [单服务结构](docs/UNIFIED_SERVICE.md)。

组件采用同包交付：主程序、库、分析器及 skeleton 嵌入的 eBPF 对象一起构建/更新。配置只有当前字段集合（没有 version 行）；管理命令统一完整响应，不兼容历史报文。保留的 ABI/长度检查用于检错，revision 用于运行策略更新，详见 [管理契约](docs/MANAGEMENT.md)。

## 构建与运行

当前目标为开发机的 x86_64 Linux 6.12，要求活动 LSM 列表包含 `bpf`，并具有本机 BTF、对应跟踪点和足够的 BPF 加载权限。直接针对本机能力构建，不提供旧内核兼容层。

在当前 RPM 系统安装开发依赖：

```bash
sudo dnf install clang llvm libbpf-devel elfutils-libelf-devel zlib-devel cmake gcc-c++ pkgconf-pkg-config openssl-devel fuse3-devel
cmake -S . -B build
cmake --build build -j
./build/secmon --check
sudo ./build/secmon > events.jsonl
```

## 指定文件只读保护

```bash
sudo ./build/secmon --protect-file /absolute/path/important.txt
```

最多指定 256 个已存在的普通文件；路径末尾不能是符号链接。程序使用 O_PATH 句柄固定目标 inode，按设备主次号与 inode 匹配，持有当前策略的句柄直到策略被替换或 BPF 链接释放，防止 inode 复用。策略跟随文件对象，已有硬链接也受保护；不递归保护目录，不阻止父目录重命名。

默认策略作用于所有任务，包括 root 和 secmon 自身。配置可显式按执行文件 inode、有效 UID、目标及操作检查点授予修改例外，并自动保护授权程序文件，见 [程序对象授权](docs/WRITER_IDENTITY.md)。可覆盖写打开、已有 FD 的普通写入和截断、路径截断、删除、源或目标重命名、新建硬链接、setattr，以及新增共享可写 mmap 和共享映射增加写权限。原有读取和私有映射允许。先保留其他 LSM/BPF 程序的拒绝，再执行本策略；审计缓冲区满不会导致放行。

`file_denied` 包含 PID/TID、当前 UID/EUID、设备主次号、inode、操作类型及 errno=13。操作编号：1 写打开，2 写权限，3 截断，4 删除，5 重命名，6 硬链接，7 属性修改，8 共享可写映射。某些操作可能在更早的钩子被拒绝，因此事件编号不必等于用户调用的系统调用名。

边界：不撤销策略启用前已有的共享可写映射，扩展属性/ACL 和部分文件系统 ioctl 已专项覆盖，具体白名单与边界见[元数据合同](docs/FILE_METADATA.md)；不承诺覆盖所有异步 I/O、文件系统专属 ioctl、底层块设备写入或其他尚未测试的操作。现已专项验证私有 bind 别名与私有 tmpfs，见 [挂载命名空间验证](docs/NAMESPACE_POLICY.md)；本合成 FUSE 视图已有专项验证，其他 FUSE、overlay/NFS 等环境仍需分别验证。策略按对象保护，不锁定路径命名空间。加载时各钩子依次挂载，不提供原子启用保证；正常退出、崩溃或进程被终止后，不固定到 bpffs 的链接会释放，不能视为持久防护。

## secmon 进程自保护

```bash
sudo install -d -m 0700 /run/secmon
sudo ./build/secmon --self-protect /run/secmon/control.sock
# 在另一个终端进行授权退出：
sudo ./build/secmon --stop /run/secmon/control.sock
```

可以与 `--protect-file` 组合。未指定管理 socket 时自保护关闭；使用 `--control SOCKET` 或 `--self-protect SOCKET` 且启用 BPF 时自动开启。启用后，在 task_kill 和 ptrace_access_check 钩子拒绝其他进程向目标发送非零信号或进行相应访问，包括 root 发出的信号。信号 0 探测与目标线程组自身操作放行。策略通过 pidfd 写入任务本地存储，跟随线程组 leader 生命周期，不使用裸 PID 白名单。

管理 socket 必须使用绝对路径，父目录须已存在、root 所有且无组/其他用户权限；服务要求 root 运行。服务将 socket 权限设为 0600，使用 SO_PEERCRED 校验管理端 UID=0，只接受完整的 `stop` / `reload` / `status` 消息。socket 通过已验证目录的 FD 创建，退出时清理；不自动删除已有 socket。`--stop` 同样校验服务端 root 身份，确认收到接受响应后返回；如需确认全部退出，还应检查服务进程状态。

启用自保护后不要依赖外部 `timeout` 或 kill 停止服务；测试可使用 `--run-for 20`，进程在内部计时结束后自行退出（允许 1..3600 秒）。任务保护对通过已覆盖入口的用户态信号生效，不承诺拦截终端/内核生成的所有信号、OOM、cgroup freeze/kill、重启或内核失陷。不撤销启动前已有的 ptrace 关系或已打开内存访问句柄。高权限管理员仍可通过 BPF 管理等途径解除防护，当前 root 管理身份也不等同于可信应用身份。

ptrace 访问检查同时影响部分 `/proc` 查询；这版策略保守地拒绝外部 ptrace 检查，不区分只读和注入。程序文件、配置和管理目录未自动纳入文件只读策略，需要独立配置，相关完整自保护仍待扩展。

`self_denied` 包含发起者 PID/TID、目标 PID、操作类型、信号和 errno=1。操作编号 9 表示信号，10 表示 ptrace 访问检查。事件字段 PID 使用内核任务标识，容器命名空间展示尚未适配。

构建使用系统 libbpf，不要求初始化子模块。`vmlinux.h` 从 `/sys/kernel/btf/vmlinux` 生成，skeleton 从新编译的对象生成，均输出到构建目录；不使用仓库里旧的生成文件。切换运行内核后重新配置构建。

`--check` 仅检查内核标识、可读 BTF 和活动 BPF LSM，不保证所有钩子和加载权限可用。实际挂载失败会报告错误并退出。Ctrl+C 或 SIGTERM 退出时解除挂载，资源通过 RAII 清理。

事件输出的非 ASCII 字节采用 `\u00XX` 编码，按字节保留文件名，不保证显示为原始 Unicode。文件名字段最多 255 字节。程序启动前已有线程在首次检查时建立观测基线；启动和分步挂载期间不提供无缝覆盖保证。

`uid`、`euid`、`caps` 和 `comm` 反映事件发生时的当前任务状态：检查事件发生在凭证提交前，成功事件发生在执行完成阶段。`exec_check.target_euid` 是该检查点的候选值，可能尚未计算 setuid，不能当作最终 EUID 预测；`exec_success.target_euid` 使用当前任务已提交的 EUID，与该事件的 `euid` 一致。`old_tid` 在成功事件中标识执行前的线程 ID，配合 PID、事件顺序与生命周期信息关联；它不是全局唯一的执行请求 ID。脚本仍可能产生多个检查事件。

当前已在开发机完成 BPF 对象编译、skeleton 生成和 GNU++17 宿主构建，`--check` 与 `--help` 验证通过。用户以管理员权限完成加载、挂载、超时退出及执行事件采集验证，输出包含 `/usr/bin/id` 和 `/usr/bin/true`，提供的样本中 `flags` 均为 0，丢失事件和基线更新失败计数均为 0。后续已补充线程 Map 生命周期、合法 setuid/file capabilities、合成基线不一致和 fanotify 持续负载验证，见下文与测试矩阵；真实提权攻击和其他压力场景仍待专项验证。

## 验证工具

```bash
ctest --test-dir build --output-on-failure
sudo python3 tests/integration.py --build-dir build
sudo python3 tests/self_protection.py --build-dir build
```

第一条验证帮助命令、非法参数校验及测试工具的普通执行、线程创建退出、非主线程 exec，不加载 BPF。

第二条会临时启动审计程序并保护一个临时测试文件，验证 13 类拒绝操作、读取和私有映射放行、拒绝事件身份及停止后的策略解除；同时触发上述进程场景及测试子进程降权到 UID/GID 65534 后执行，检查检查事件、完成事件、TID 关联、凭证字段和失败计数，最后停止程序。不部署持久策略，不修改账户；测试程序所在路径需允许降权后的进程遍历。运行前停止手工启动的旧版 secmon，避免额外挂载干扰。

当前开发机上该特权集成测试已全部通过，包括新增钩子的实际加载、普通执行、线程创建退出、非主线程 exec 的 TID 关联、合法降权后的执行及正常退出；两个失败计数均为 0。该测试不验证真实提权攻击检测，也不直接检查 Map 中的所有生命周期条目是否均已清理。

指定文件保护的特权测试也已通过：写打开、硬链接写打开、已有 FD 写入和截断、路径截断、删除、重命名源与覆盖目标、新建硬链接、chmod、utime、共享可写 mmap 及共享 mprotect 均返回 EACCES。未受保护文件可写，受保护文件可读、私有映射不改变原文件，拒绝事件的文件身份正确，停止后可重新写入。

自保护测试有内部 20 秒运行上限，已验证外部 SIGTERM/SIGINT/SIGSTOP/SIGKILL/SIGUSR1、pidfd 信号、tgkill、PTRACE_SEIZE、`/proc/PID/mem` 打开及 `process_vm_writev` 权限检查被拒绝；非法命令与非 root 管理连接被拒绝，root 授权停止、内部超时和 socket 清理正常，非目标进程信号不受影响。拒绝事件的目标身份正确，事件丢失和基线更新失败计数为 0。

宿主模块拆分至 `src/` 后，已针对代码提交 `4015ced` 重跑上述两项特权集成测试，均通过；文件只读策略、执行/凭证事件、进程自保护及管理退出回归正常，事件丢失和基线更新失败计数均为 0。详细记录见 `DESIGN.md`。


## fanotify 权限裁决实验

fanotify 模块在 `secmon` 主进程内对普通文件的权限事件允许或拒绝，默认使用 `FAN_OPEN_PERM`，也可用 `--event access|exec` 研究读取及执行打开权限。诊断选项 `--fanotify-only` 仅关闭本次进程的 BPF 模块。实现与实验步骤见 [fanotify 学习实验](docs/FANOTIFY_LAB.md)。

```bash
sudo ./build/secmon --file /absolute/path/test-file --decision deny --run-for 20
sudo python3 tests/fanotify.py --build-dir build
```

默认 open 模式下，`deny` 拒绝新增打开，包括读取打开；已有 FD 不受影响。access 模式可裁决已打开 FD 的普通读取，但不覆盖 mmap；exec 模式裁决直接执行打开，不覆盖解释器读取脚本。组关闭或服务崩溃后，等待裁决的打开请求会被放行。单文件标记跟随 inode，不固定路径。当前开发机特权测试通过，覆盖允许/拒绝、并发、硬链接与重命名、已有 FD、正常退出、崩溃释放和运行期限。新增有界延迟裁决队列，支持接收后的请求超时、容量回退与正常退出时拒绝用户态队列中的请求；模拟延迟模式仍可用于实验，也可切换到独立内容分析进程。真实内核队列溢出仍未验证，不提供持久防护。


延迟裁决验证与持续负载工具：

```bash
sudo python3 tests/fanotify_deferred.py --build-dir build
sudo python3 tests/fanotify_soak.py --build-dir build --duration 30 --mode policy
```


两层策略组合与停止行为见 [策略组合实验](docs/POLICY_LAYERS.md)：

```bash
sudo python3 tests/policy_composition.py --build-dir build
```


直接观察凭证 Map 的线程生命周期与降权基线：

```bash
sudo python3 tests/baseline_lifecycle.py --build-dir build --rounds 20
```

阅读步骤与边界见 [凭证生命周期实验](docs/CREDENTIAL_LIFECYCLE.md)。它补充了测试线程组实际 Map key/value 的检查，不代表真实提权攻击验证。


合法 setuid 与文件 capabilities 执行验证（需要 `setcap`，仅修改临时测试文件）：

```bash
sudo python3 tests/credential_transitions.py --build-dir build
```


完整特权回归可一次运行：

```bash
sudo python3 tests/run_privileged.py --build-dir build
```

其中包含仅修改本次测试 Map 的合成基线不一致验证，不修改真实任务凭证。各项范围、依赖与持续负载选项见 [测试矩阵](docs/TESTING.md)。


独立分析进程与实际内容裁决见 [分析组件导读](docs/ANALYSIS_WORKER.md)：

```bash
sudo python3 tests/fanotify_analysis.py --build-dir build
```

首版是有界字节标记规则，不是恶意内容检测引擎；分析程序独立运行，超时或崩溃由接收端回退。
