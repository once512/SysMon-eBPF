# 固定多目标 fanotify 订阅

同一服务支持 1..64 个固定普通文件，在一个 fanotify group 内订阅同一种 open/access/exec 权限事件。配置重复 `fanotify-file`，或在 CLI 重复 `--file`：

```text
revision 1
protect "/srv/demo/one"
protect "/srv/demo/two"
fanotify-file "/srv/demo/one"
fanotify-file "/srv/demo/two"
fanotify-event access
fanotify-decision allow
```

```sh
sudo ./build/secmon --policy /absolute/policy.conf --control /run/secmon/control.sock \
  --audit-permissions --requester-pidfd > events.jsonl

sudo ./build/secmon --fanotify-only --file /absolute/one --file /absolute/two \
  --event access --decision deny --run-for 20
```

这不是目录递归订阅或通配规则。BPF protect 与 fanotify-file 独立声明：保护某文件不自动订阅其访问，订阅访问也不自动拒绝修改。所有目标共用裁决、分析器、扫描参数、超时及 pending 预算，没有逐目标授权或独立队列。

## 身份、资源与启动失败

每个路径用 O_PATH/O_NOFOLLOW 固定最终对象，只接受普通文件。解析拒绝重复路径文本和第 65 个目标；启动进一步拒绝同设备/inode 的硬链接别名。全部目标及配置文件排除检查在添加第一个 mark 前完成。mark 通过固定 FD 建立，重命名保留订阅，原路径换成不同 inode 不继承订阅。

每个目标保留一个 FD，另有一个共享 group。最多 4096 个已交付 pending 请求，pidfd 模式中每条请求另持有一个请求方引用；分析器仍最多处理一个活动请求。多目标不会乘大 pending 上限。任一目标检查或 mark 添加失败，构造失败并关闭整个 group，已添加的 mark 和所有引用由 RAII 回收；此清理保证不等于启动过程中没有短暂订阅。

接收事件时 fstat 事件 FD，与最多 64 项固定目标身份核对，再把设备/inode 快照和进程引用、revision、接收时刻一起存入请求。延迟、分析、容量、超时和停止回复使用该请求的对象快照，不借用“当前目标”，不按路径或数字 PID 重建对象/主体。未知对象或事件 FD 检查失败会终止该实例并关闭 group，不补造身份。

审计 JSON 字段保持原意，major/minor/inode 是本条请求的对象。管理状态新增 `fanotify_targets`，表示固定订阅对象数；本地管理 ABI 为 v4/360 字节，客户端与服务端应使用同一构建，不提供历史协议转换。BPF 事件 ABI 和分析器 ABI 未因此调整。

## 重载合同

在线裁决更新要求已交付请求队列和分析器空闲。后续已加入[即时静态 allow 模式的受限目标切换](FANOTIFY_HANDOVER.md)：旧门满足条件时可增删或重排列表，保留共同路径的原 inode；拒绝、延迟或分析模式下改变目标仍要求重启。事件入口、分析器及扫描参数的重启要求不变。

协调器先验证 fanotify 候选并准备资源，再准备/提交 BPF，最后无异常提交裁决和 revision。候选语法错误、不支持的目标变化、busy 或 BPF 准备失败均保留旧活动配置及全部旧 mark。这不是跨内核钩子的全局原子事务。

加载配置时必须先以 O_PATH 固定来源，再与**所有**目标比较，排除硬链接到任意次要目标的来源后才打开读取，避免服务等待自己裁决。其他服务订阅此配置的依赖不在本服务保证内。固定 fanotify mark 不随 BPF reload 对同路径的重新解析而迁移；部署时应明确路径替换和重启流程。

## 验证入口

```sh
sudo python3 -B tests/fanotify_multiple.py --build-dir build
sudo python3 -B tests/behavior_chains.py --build-dir build --mark-all --objects 8 \
  --artifact-dir /tmp/secmon-multitarget-captures
sudo python3 -B tests/behavior_chains.py --build-dir build --mark-all --objects 64 \
  --duration 600 --artifact-dir /tmp/secmon-multitarget-soak
```

`fanotify-multiple` 专题覆盖并发裁决重载、目标变更拒绝、BPF 准备失败、所有目标的配置自我等待防护、忙时版本保持、重命名/路径替换，另核对分析器、超时、共享容量、停止及 exec。启动失败测试覆盖硬链接重复、符号链接、目录、缺失文件、配置自身和部分 mark 添加后失败清理。CLI 和解析测试验证重复路径及 64/65 边界。

多对象行为专题仍默认只标记第一个文件，以保留证据缺失对照。`--mark-all` 才订阅全部对象；`--objects` 为 3..64，`--duration` 为 0..1200 秒。配对容量固定 128，可保留本负载同对象的全部受控历史。正常批量保存与受控覆盖即使都出现完整多对象配对，仍不构成独立恶意判据，classification 保持 undetermined，response 保持 none。
