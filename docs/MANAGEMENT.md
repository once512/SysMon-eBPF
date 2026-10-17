# 活动状态与结构化管理结果

两个宿主现在支持 root 管理查询：

```bash
sudo ./build/secmon --status /run/secmon/bpf.sock
sudo ./build/secmon-fanotify --status /run/secmon/fanotify.sock
# 重载也输出一条 JSON；失败同时非零退出：
sudo ./build/secmon-fanotify --reload /run/secmon/fanotify.sock
```

BPF 的管理端仍由 `--self-protect SOCKET` 创建；fanotify 由 `--control SOCKET` 创建，后者不自动启用 BPF 任务保护。两个端点共用协议，路径决定目标，JSON 的 backend 明确实际服务类型。目录须 root 所有且无组/其他用户权限，服务和客户端校验 SO_PEERCRED 的 root 身份。

## 查询说明的是哪份状态

`--status` 返回事件循环中的活动内存快照，不重新读取配置、不重载、不推进待决请求、不重启或主动探测分析器。配置损坏或被删除后仍可查询当前有效 revision。正常事件循环在查询前后继续运行，因此两次快照的计数或队列可以变化；它不是暂停业务后的全系统快照。

公共字段：

| 字段 | 含义 |
| --- | --- |
| protocol_version / command / code | 管理协议版本、当前命令、本次命令结果 |
| backend / pid / instance_ns | 服务类型、服务进程、该运行协调器建立时的单调时间标识 |
| uptime_ms | 协调器建立以来经过的时间，包括启动加载阶段 |
| configured / revision | 是否从配置文件启动、实际提交的版本；命令行模式 revision=0 |
| source_sha256 | 活动配置原始字节的 SHA-256；包含注释/空白/换行，命令行模式为 null；查询不读当前磁盘文件 |
| reloads / rejections | 本次服务内成功/拒绝的重载数量，查询不修改它们 |
| last_code / last_attempt_revision | 最近一次重载结果、完整读出候选配置后的版本；未成功读取候选时版本为 0 |

pid 与 instance_ns 一起用于识别当前实例，不是持久 UUID、任务启动时间或跨 PID namespace 的授权标识。重启后计数和历史归零，未实现持久防回滚。比较 revision 与 source_sha256 才能核对活动版本及原始配置内容；摘要不是签名、授权或跨进程原子提交。配置字节相同也不证明路径解析到了同一 inode 或处于同一命名空间。

BPF 另返回 protected_paths 和 self_protected，前者按配置路径条数计，硬链接别名不合并。BPF 事件统计仍由既有 stderr 周期报告，本接口不把占位数值展示成已读取的内核统计。

fanotify 另返回当前事件、裁决模式、延迟/超时/容量、三种回退设置、已交付 pending 与峰值、累计允许/拒绝/分析错误/后端故障/内核溢出。analyzer_online 表示宿主**已观测**的通道状态，不是瞬时进程健康保证；查询本身不做 ping/reap。analyzer_pid 可能是尚未回收的原子进程 PID，不能把该数字当成独立授权的发信号目标。内部终止仍使用 pidfd。

## 稳定错误码

| code | 含义与处理 |
| --- | --- |
| ok | 本次请求成功；status 的 ok 不会清除上次重载的 last_code |
| no_policy | 启动没有 `--policy`，不能在线指定另一个配置源 |
| not_newer | 候选 revision 没有严格递增 |
| invalid_policy | 配置读取、权限、格式或配置自身 inode 排除检查失败 |
| prepare_failed | 候选解析成功，但目标固定/Map 准备或提交等后端操作失败 |
| busy | fanotify 已交付队列或分析器仍有活动请求，可排空后重试同一候选版本 |
| restart_required | fanotify 目标、事件、模式或扫描器固定设置改变，需重启 |
| internal_error | 保留给内部错误；不应按正常配置拒绝处理 |

拒绝时活动 revision 保持原值。JSON 包含机器可读原因，服务 stderr 保留详细异常文本。连接失败、协议不兼容、响应超时等传输错误只写 stderr 并非零退出，没有可确认的 JSON 状态；不能因此推断重载一定没有发生，应重新查询实际活动版本。

## 协议与模块

- `src/management/protocol.h/.cpp`：本机同架构的 296 字节 v3 响应（保留 200 字节 v1、288 字节 v2 前缀）、固定枚举、边界校验与 JSON 渲染，与 BPF 事件 ABI、分析器 ABI 独立。
- `src/policy_runtime.h/.cpp`：共用运行版本、重载计数和最近结果。先解析/校验版本，后调用后端准备与提交，成功后才移动活动配置。调用方必须把所有可能失败的准备放在提交之前，移动赋值由编译期 noexcept 检查约束。
- `src/fanotify/status.h/.cpp`：把只读后端状态转换为协议字段。
- `src/control.h/.cpp`：处理根权限、报文边界及附加 FD；异常连接不影响服务的继续运行。

当前结构化命令正文为 `status-v3`、`reload-v3`、`stop-v3`。CLI 的 status/reload 使用 v3，stop 保留原管理行为；新服务仍可向 `*-v1`/`*-v2` 客户端分别返回 200/288 字节的前缀响应。旧的 `stop`/`reload` 继续得到 `ok`/`error`，新 CLI 不向旧服务静默回退。客户端先检查完整长度、magic、ABI、命令、枚举/边界、保留字段与服务端 PID，再渲染 JSON。双方都拒绝意外的 SCM_RIGHTS，并关闭已收到的 FD，包含辅助数据截断的情形。

固定响应不含路径、异常文本和指针，减少转义与信任边界。该接口不用于跨机器通信，不接受请求提供的目标 PID、配置路径或业务进程操作。

## 验证入口

```bash
ctest --test-dir build --output-on-failure
sudo python3 tests/run_privileged.py --build-dir build --only management-live management-faults
```

前者验证协议字段、JSON 和无配置运行状态。真实专题覆盖：磁盘文件损坏/缺失时的状态、两个服务独立版本、配置/版本/准备/忙/需重启错误、忙时原请求完成、查询 FD 稳定、未知/超长/带 FD 命令、非 root 对端、旧协议兼容，以及伪 root 服务返回错误长度、枚举、身份或附带 FD 时客户端拒绝。


可选持续管理负载（每个场景指定秒数，共静态 open、分析 open、分析 access 三项）：

```bash
sudo python3 tests/run_privileged.py --build-dir build --only management-live management-faults --management-soak-duration 30
```

持续请求中反复查询状态，在阶段间排空请求再更新/拒绝相同版本，核对活动摘要、实例标识、闲置 FD 回收与每次业务回复。打印控制查询时延仅作本机回归证据，不是服务时延 SLA。配置摘要使用系统 OpenSSL EVP SHA-256，构建需要 libcrypto 开发包。

管理 v2 还包含扫描原因计数、最近扫描错误与 errno，以及后端故障回退请求数。具体枚举、有效组合和计数守恒关系见 [分析器 v3](ANALYSIS_WORKER.md)。这与重载结果 code/last_code 是两类独立错误，不能把单文件扫描失败解释成配置重载失败。

管理服务接收命令采用非阻塞推进：最多保留一个尚未发送消息的连接，空闲约 100ms 后在后续循环中回收；不在权限事件循环内 poll 等待客户端。正常连接可以稍后提交报文。到期回收受宿主循环调度影响，不是绝对墙钟期限；root 控制专题用独立 helper 验证静默连接不会令 dispatch 阻塞，真实服务验证静默连接期间仍可裁决、查询并回收 FD。

## 双后端活动来源核对

新增只读工具：

```bash
sudo ./build/secmon-policyctl --bpf-socket /run/secmon/bpf.sock \
    --fanotify-socket /run/secmon/fanotify.sock --expect-revision 7
```

工具不读候选文件，也不发送 reload。按 BPF₁ → fanotify₁ → BPF₂ → fanotify₂ 查询，分别检查两次间 pid/instance/revision/source_sha256/成功重载数是否稳定。若稳定，两段观测区间在 fanotify₁..BPF₂ 相交，再比较共同来源；拒绝次数和业务计数变化不算策略变化。

| code | 含义 |
| --- | --- |
| consistent | 活动版本和原始配置字节相同，且满足可选预期版本 |
| revision_mismatch | 两后端活动版本不同 |
| source_mismatch | 版本相同但原始配置摘要不同，包括注释/空白差异 |
| unstable | 采样期间有成功提交、实例或活动来源变化，应重试查询 |
| unconfigured | 至少一端是命令行模式，没有共同配置来源可核对 |
| unexpected_revision | 两端来源一致，但不是指定的预期版本 |
| wrong_backend | socket 指向的服务类型与参数角色不符 |
| query_failed | 服务返回了非 ok 状态 |
| transport_error | 连接/身份/帧校验或等待失败，不能确认完整状态 |

输出的 scope 固定为 active_configuration_bytes，附带后两次有效状态；传输错误只有 code/scope。退出码 0 表示 consistent，1 表示分歧/不稳定/查询失败，2 表示参数错误。当前客户端要求管理 v3；旧服务不会被静默当作一致。

这是只读来源核对，不是原子发布、签名验证、分析器健康检查、内核 Map 外部修改检测或路径对象一致性证明。即使 consistent，也只说明观测到的活动配置字节；要判断运行健康还需检查附带状态。跨命名空间管理坐标仍按项目已有边界处理。

`src/management/consistency.h/.cpp` 是纯快照判定，入口 `src/management/main.cpp` 只负责参数与采集；确定性测试覆盖采样不稳定，真实双后端专题覆盖版本/摘要分歧、预期版本、端点反置和只读资源回收。

```bash
sudo python3 tests/run_privileged.py --build-dir build --only policy-consistency
```

## v3：授权条数

管理 v3 在 v2 末尾追加两个 uint32：`writer_paths` 和必须为零的保留字段，总大小 296 字节。BPF 状态 JSON 的 writer_paths 是已提交的 allow-writer 路径条数，范围 0..64，包括同 inode 别名；protected_paths 仍仅为显式 protect 路径条数。两者都不是不同 inode 数，也不证明对象内容或运行程序可信。fanotify 不应用 writer，JSON 不提供此字段。

旧管理端仍可查询已有字段，但看不到新授权条数；新 CLI 遇到旧服务/旧响应会拒绝，不静默丢失这项信息。配置 v3、管理 v3、分析 v3 各自独立版本化，数字相同没有联动语义。
