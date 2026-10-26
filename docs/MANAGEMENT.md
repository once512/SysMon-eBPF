# 活动状态与结构化管理结果

主服务只有一个 root 管理 socket：

```bash
sudo ./build/secmon --policy /run/secmon/policy.conf --control /run/secmon/control.sock
sudo ./build/secmon --status /run/secmon/control.sock
sudo ./build/secmon --reload /run/secmon/control.sock
sudo ./build/secmon --stop /run/secmon/control.sock
```

`--control` 与 `--self-protect` 指定同一个管理端点；BPF 启用时同时保护整个主服务。诊断模式 `--fanotify-only` 没有 BPF 自保护。目录须 root 所有且无组/其他用户权限，服务和客户端通过 SO_PEERCRED 校验 root 身份。backend 为 bpf、fanotify 或 combined，combined 在同一响应中同时包含两模块字段，pid/revision/摘要/重载历史只有一份。

## 查询说明的是哪份状态

`--status` 返回事件循环中的活动内存快照，不重新读取配置、不重载、不推进待决请求、不重启或主动探测分析器。配置损坏或被删除后仍可查询当前有效 revision。正常事件循环在查询前后继续运行，因此两次快照的计数或队列可以变化；它不是暂停业务后的全系统快照。

公共字段：

| 字段 | 含义 |
| --- | --- |
| protocol_version / command / code | 当前布局标识、当前命令、本次命令结果 |
| backend / pid / instance_ns | 服务类型、服务进程、该运行协调器建立时的单调时间标识 |
| uptime_ms | 协调器建立以来经过的时间，包括启动加载阶段 |
| configured / revision | 是否从配置文件启动、实际提交的版本；命令行模式 revision=0 |
| source_sha256 | 活动配置原始字节的 SHA-256；包含注释/空白/换行，命令行模式为 null；查询不读当前磁盘文件 |
| reloads / rejections | 本次服务内成功/拒绝的重载数量，查询不修改它们 |
| last_code / last_attempt_revision | 最近一次重载结果、完整读出候选配置后的版本；未成功读取候选时版本为 0 |

pid 与 instance_ns 一起用于识别当前实例，不是持久 UUID、任务启动时间或跨 PID namespace 的授权标识。重启后计数和历史归零，未实现持久防回滚。比较 revision 与 source_sha256 才能核对活动版本及原始配置内容；摘要不是签名或授权。配置字节相同也不证明路径解析到了同一 inode 或处于同一命名空间。

permission_audit 表示是否开启逐请求 fanotify 审计，属于固定启动选项。启用 BPF 时另返回 protected_paths、writer_paths 和 self_protected，前者按配置路径条数计，硬链接别名不合并。启用 BPF 或开启权限审计的 fanotify-only 后端，用户态审计队列还返回 audit_written/audit_dropped/audit_invalid/audit_queued/audit_errno，具体口径见 [审计出口](AUDIT_OUTPUT.md)。所有后端另返回 diagnostic_written/diagnostic_dropped/diagnostic_invalid/diagnostic_queued/diagnostic_errno，描述独立 stderr 出口；计数与限制同见上述文档。BPF 事件统计仍由既有 stderr 周期报告，本接口不把占位数值展示成已读取的内核统计。

启用 fanotify 时另返回当前事件、裁决模式、延迟/超时/容量、三种回退设置、已交付 pending 与峰值、累计允许/拒绝/分析错误/后端故障/内核溢出。analyzer_online 表示宿主**已观测**的通道状态，不是瞬时进程健康保证；查询本身不做 ping/reap。analyzer_pid 可能是尚未回收的原子进程 PID，不能把该数字当成独立授权的发信号目标。内部终止仍使用 pidfd。

读取者进度另提供reader_pid、reader_state和reader_progress_age_ms；约250ms异步探测、2000ms未确认显示unresponsive，详情见[进度监督](READER_HEALTH.md)。查询不触发探测，不因超时重建权限组。

## 稳定错误码

| code | 含义与处理 |
| --- | --- |
| ok | 本次请求成功；status 的 ok 不会清除上次重载的 last_code |
| no_policy | 启动没有 `--policy`，不能在线指定另一个配置源 |
| not_newer | 候选 revision 没有严格递增 |
| invalid_policy | 配置读取、权限、格式或配置自身 inode 排除检查失败 |
| prepare_failed | 候选解析成功，但目标固定/Map 准备或提交等后端操作失败 |
| busy | fanotify 已交付队列或分析器仍有活动请求，可排空后重试同一候选版本 |
| restart_required | fanotify 模块启用/禁用、目标、事件、模式或扫描器固定设置改变，需重启 |
| internal_error | 保留给内部错误；不应按正常配置拒绝处理 |

拒绝时活动 revision 保持原值。JSON 包含机器可读原因，服务 stderr 保留详细异常文本。连接失败、协议不兼容、响应超时等传输错误只写 stderr 并非零退出，没有可确认的 JSON 状态；不能因此推断重载一定没有发生，应重新查询实际活动版本。

## 协议与模块

- `src/management/protocol.h/.cpp`：本机同架构的 v8/448 字节完整响应、固定枚举、边界校验与 JSON 渲染，与 BPF 事件 ABI、分析器 ABI 独立；`fanotify_targets` 为固定订阅对象数（1..64）。
- `src/policy_runtime.h/.cpp`：共用运行版本、重载计数和最近结果。先解析配置/校验递增 revision，后调用后端准备与提交，成功后才移动活动配置。调用方必须把所有可能失败的准备放在提交之前，移动赋值由编译期 noexcept 检查约束。
- `src/fanotify/status.h/.cpp`：把只读后端状态转换为协议字段。
- `src/control.h/.cpp`：处理根权限、报文边界及附加 FD；异常连接不影响服务的继续运行。

命令正文只有 `status`、`reload`、`stop`，精确匹配且不带版本后缀。所有命令均返回同一个当前完整结构，CLI 均输出 JSON；没有前缀响应或 ok/error 文本响应。客户端先检查完整长度、magic、当前 ABI、命令、枚举/边界、保留字段与服务端 PID，再渲染 JSON。双方都拒绝意外的 SCM_RIGHTS，并关闭已收到的 FD，包含辅助数据截断的情形。历史后缀命令被拒绝，不会触发停止或重载。

固定响应不含路径、异常文本和指针，减少转义与信任边界。该接口不用于跨机器通信，不接受请求提供的目标 PID、配置路径或业务进程操作。

## 验证入口

```bash
ctest --test-dir build --output-on-failure
sudo python3 tests/run_privileged.py --build-dir build --only management-live management-faults
```

前者验证协议字段、JSON 和无配置运行状态。真实专题覆盖：磁盘文件损坏/缺失时的状态、诊断实例的独立状态及联合服务统一版本、配置/版本/准备/忙/需重启错误、忙时原请求完成、查询 FD 稳定、未知/超长/带 FD 命令、非 root 对端、历史后缀命令拒绝，以及伪 root 服务返回错误长度、枚举、身份或附带 FD 时客户端拒绝。


可选持续管理负载（每个场景指定秒数，共静态 open、分析 open、分析 access 三项）：

```bash
sudo python3 tests/run_privileged.py --build-dir build --only management-live management-faults --management-soak-duration 30
```

持续请求中反复查询状态，在阶段间排空请求再更新/拒绝相同版本，核对活动摘要、实例标识、闲置 FD 回收与每次业务回复。打印控制查询时延仅作本机回归证据，不是服务时延 SLA。配置摘要使用系统 OpenSSL EVP SHA-256，构建需要 libcrypto 开发包。

管理状态还包含扫描原因计数、最近扫描错误与 errno，以及后端故障回退请求数。具体枚举、有效组合和计数守恒关系见 [分析器协议](ANALYSIS_WORKER.md)。这与重载结果 code/last_code 是两类独立错误，不能把单文件扫描失败解释成配置重载失败。

管理服务接收命令采用非阻塞推进：最多保留一个尚未发送消息的连接，空闲约 100ms 后在后续循环中回收；不在权限事件循环内 poll 等待客户端。正常连接可以稍后提交报文。到期回收受宿主循环调度影响，不是绝对墙钟期限；root 控制专题用独立 helper 验证静默连接不会令 dispatch 阻塞，真实服务验证静默连接期间仍可裁决、查询并回收 FD。

## 单服务活动策略核对

```bash
sudo ./build/secmon-policyctl --socket /run/secmon/control.sock --expect-revision 7
```

工具只查询一次主服务的活动快照，不读候选文件或发送 reload。JSON 为 `{ "code": "ok", "status": { ... } }`；可返回 unconfigured、unexpected_revision、query_failed 或 transport_error。退出码 0 表示核对成功，1 表示核对/传输失败，2 表示参数错误。未配置策略文件的诊断实例仍可通过 secmon --status 查看，但此工具报告 unconfigured。

BPF 与 fanotify 共用 PolicyRuntime，不再需要两个 socket、四次采样或跨进程 revision/摘要比较。原有 --bpf-socket/--fanotify-socket 参数已移除；一次快照仍不是所有业务计数的全系统暂停或内核全局原子屏障。

```bash
sudo python3 tests/run_privileged.py --build-dir build --only policy-consistency unified-service
```

## 授权条数

BPF 状态的 writer_paths 是已提交的 allow-writer 规则中的程序路径条数，范围 0..64；相同程序对不同目标的规则分别计数，包括同 inode 别名；protected_paths 为显式 protect/vault 路径条数。两者都不是不同 inode 数，也不证明对象内容或运行程序可信。fanotify 不按 writer 绕过裁决；仅 fanotify 的诊断模式不提供此字段。

## 同包交付与布局检查

主程序、库、分析器和嵌入 skeleton 的 eBPF 对象按同一构建一起发布。协议只保留当前布局标识，用于发现混用产物或异常帧；没有历史解码器、字段转换、版本协商或降级。protocol_version 是该检查值，不是支持范围或产品发布版本。修改结构时同步调整两端和测试即可。

策略 revision 是另一件事：它区分运行中不同的规则提交，用于在线重载去重及拒绝旧候选。它不会随本轮简化而删除。已有配置需去掉 version 行，示例与测试均使用同一字段集合。

## 传输与调用边界

服务端生命周期位于 `src/control.h/.cpp`，客户端请求位于 `src/control_client.h/.cpp`；地址、对端身份及严格无 FD 接收规则共用 `src/management/channel.h/.cpp`。消息布局和字段校验继续由 protocol 模块负责。职责与资源所有权分析见 [架构整理](ARCHITECTURE_REVIEW.md)。

## 保险箱状态

v6 提供 vault_paths、vault_sessions、vault_live_sessions、vault_stale_sessions、vault_session_history、vault_clock_valid、vault_next_deadline_boot_ns，含义及查询时钟边界见 [保险箱会话](VAULT_SESSIONS.md)。所有同包客户端与测试须同步更新，不解码历史响应。
