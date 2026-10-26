# 允许访问模式下的在线目标切换

统一配置重载现在可替换 fanotify 目标列表，但仅限旧权限门使用静态、无延迟 `allow`，且已交付请求队列为空、分析器无活动请求。候选仍需保留至少一个、最多 64 个普通文件。拒绝、延迟或分析模式下变更目标仍要求重启；已交付请求未完成时返回 busy。

这个范围与当前“允许读取、由 BPF 拒绝未授权修改”的证据采集负载一致。它不是任意拒绝策略的无损热迁移，也不新增写入授权或自动隔离。

```sh
# 初始配置：静态即时 allow，可有多个 fanotify-file。
sudo ./build/secmon --policy /absolute/policy.conf --control /run/secmon/control.sock \
  --audit-permissions --requester-pidfd > events.jsonl
# 原子发布更高 revision，改变 fanotify-file 列表后：
sudo ./build/secmon --reload /run/secmon/control.sock
```

## 准备与提交

1. 先以现有全部目标引用排除配置自我等待，再加载候选配置。
2. 验证事件入口、分析器和扫描设置不变，检查旧队列空闲及即时 allow 条件。
3. 独立创建候选 group。共同配置路径复制旧 O_PATH 引用，新增路径重新固定并验证；拒绝重复 inode、配置自身、符号链接和非普通文件。候选 mark 全部成功后，旧 group 仍在运行。
4. 准备并提交 BPF 候选；失败时销毁候选 group，保留旧活动配置、旧引用、旧 group 和请求序列。
5. 成功后通过无异常移动切换 group，释放旧 group 及用户态目标引用，提交裁决设置和 revision。该阶段不再执行可能失败的目标打开或 mark 添加。

准备期间最多存在两个 group、128 个 fanotify 目标引用。候选 group 不消费用户态请求，旧门也必须空闲，因此不会翻倍已交付 pending 预算。失败候选在销毁前可能短暂挂起其新增目标上的访问；“回滚”保证活动策略与资源不被部分替换，不保证外部请求没有额外等待。

事件入口、后端模式和分析器配置变化仍要求重启；禁止在线启用/关闭整个 fanotify 模块。候选可以在切换后使用不同的静态裁决，但下一次目标切换仍取决于当时旧门是否满足即时 allow 条件。

## 为什么保留这个限制

Linux 关闭 fanotify group 会允许其未完成的内核权限事件；移除 mark 与权限事件也可能并发。[fanotify 手册](https://man7.org/linux/man-pages/man7/fanotify.7.html)及[内核 group 释放实现](https://raw.githubusercontent.com/torvalds/linux/master/fs/notify/fanotify/fanotify_user.c)解释了这一边界。[mark/事件并发实现](https://raw.githubusercontent.com/torvalds/linux/master/fs/notify/fanotify/fanotify.c)也不能据此当成用户态排空屏障。

因此不能在旧门本应拒绝或需要扫描时，简单关闭它并声称保留了裁决。本实现只允许旧名义裁决原本就为即时 allow 的目标切换。已经交付的请求必须先完成，未读取的旧内核请求可以按旧允许语义继续，但不会被补造成逐请求审计。一个跨越切换的调用可能走过交叠 group，记录数也不等于唯一系统调用数。

成功重载只保证后续新调用使用新订阅资源，不追溯撤销已经开始的调用；不同内核钩子和在途操作不构成全局原子切换。

## 对象保留与引用释放

共同路径文本继续使用原先固定的 inode，路径改名或被替换时也不重新解析。仅更新裁决同样不会重新解析现有目标。删除某个配置路径会释放其旧 fanotify 用户态引用；后续重新加入该路径时才固定当时的新对象。BPF protect 仍独立按它自己的重载合同处理，不能由 fanotify 目标列表推断写保护范围。

FD 回收测试核对服务描述符数量恢复、旧别名不再被订阅以及重新加入后绑定新 inode。联合服务的进程自保护仍禁止跨进程跟随 `/proc/PID/fd` 引用，测试不绕过它；用户态 FD 释放不表示内核 RCU 对象已同步回收。

## 请求身份、累计统计和切换审计

所有权限门使用同一服务拥有的非零递增请求序列。候选准备不消耗请求号，失败重载不重置序列，成功切换也不复用 request_id。实例身份保持不变；这不会把未读取的内核请求变成有编号的记录。

status 中 allowed/denied、原因计数、错误计数和 peak_pending 保留此前累计值，fanotify_targets 表示当前目标数。结束汇总新增 target_updates，仅计成功的目标 group 替换；规则单独更新和失败候选不增加它。管理线格式仍为 v9/472 字节。

启用 --audit-permissions 后，成功切换额外输出 fanotify_target_handover：

| 字段 | 含义 |
|---|---|
| listener_pid / instance_ns | 同一服务实例 |
| from_generation / to_generation | 连续订阅代际，初始为 1，仅目标 group 成功替换递增 |
| pid_namespace_inode | 监听器的 PID namespace 坐标 |
| from_revision / to_revision | 切换前后 revision |
| old_targets / new_targets | 旧、新目标数 |
| retained_targets | 共同路径文本复用旧引用的数量，不等于共同 inode 总数 |
| next_request_id | 切换点后下一条用户态权限请求的编号 |
| timestamp_ns | 旧 group 释放后的用户态单调时钟 |
| kernel_unread | 固定 released_under_prior_allow，说明旧未读取请求按先前允许语义释放 |
| individual_audit_complete | 固定 false，不认证该过渡的逐请求记录完整性 |

该事件使用同一有界 AuditSink，失败/背压计入 audit_dropped，不能阻塞提交或让已经完成的切换重试。离线归组工具使用该记录构造订阅代际边界；它本身不充当访问证据或攻击判定。

离线规则按进程键、设备/inode 和订阅代际归组，object_lifetime_verified=false。每次 group 成功替换会使所有目标进入新代际，包含保留的 inode；不跨代配对。详见 [离线边界](OFFLINE_EVIDENCE.md)。

## 验证入口

```sh
sudo python3 -B tests/fanotify_handover.py --build-dir build \
  --artifact-dir /tmp/secmon-handover-captures
sudo python3 -B tests/fanotify_handover.py --build-dir build --rounds 128 --duration 1200 \
  --artifact-dir /tmp/secmon-handover-soak
sudo python3 -B tests/run_privileged.py --build-dir build --only fanotify-handover
```

专题覆盖 open/access × pidfd 开关的列表增删、保留/重加 inode、候选 mark 与 BPF 准备失败、配置自我等待、持续请求号及累计统计。另有 64/65 边界、忙时/延迟/分析模式拒绝、停止 fanotify-only 实例后排队八个旧内核请求的受控恢复测试。暂停实验不用于联合自保护实例。每个完整循环保存原始流、离线结果、来源摘要和角色声明；rounds 为 1..512，duration 为 0..2400 秒。

后续任意拒绝/扫描模式的目标热迁移，需要独立解决旧在途事件的裁决与生命周期问题；本轮不以宽松的排空判断代替这个合同。

## 显式同路径刷新

更高`fanotify-rebind-epoch`可在相同allow/空闲条件下重新固定全部候选目标；相同代际仍保留共同路径。失败不消耗代际，新增审计from_rebind_epoch/to_rebind_epoch，详见[重绑定合同](FANOTIFY_REBIND.md)。上文默认对象保留规则继续适用于普通重载。
