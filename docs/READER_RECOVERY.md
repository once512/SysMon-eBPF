# 读取者离线隔离与条件恢复（2026-10-28）

读取者通信断连、格式错误、传输错误或主进程无法分配事件代理时，现在进入离线隔离，保留主服务及其独立BPF文件/进程保护。仅进度超过两秒仍沿用unresponsive合同，不自动杀死或重建卡住的读取者。

## 故障处理

检测失败时，对仍在主进程有效队列中的请求立即尝试FAN_DENY，理由为reader_error，不采用可能为allow的分析错误回退。成功写回才累计denied/reader_error_requests及逐请求审计。若写回不能确认，丢弃本地代理/身份引用并累计reader_unconfirmed_requests；不会伪造已经拒绝的记录。该计数表示无法确认，不推断内核已经允许或拒绝。

停止读取者和扫描器，但主进程继续持有原fanotify group及目标引用。内核未交付请求和未确认请求可能继续等待，管理、独立BPF策略和已有绝对期限继续推进。读取者关闭真实事件文件不等于关闭整个权限组；本机已经验证原数值令牌仍可写入拒绝。

`fanotify_reader_failure`记录当前listener/实例、订阅代际、revision、原因和未确认计数，明确group_held=true、individual_audit_complete=false。故障发生前已经按既有超时/策略写回的裁决不会被追溯改变；读失败期间由内核自行拒绝的事件也不会补造本服务的逐请求成功记录。

此处理只覆盖指定读取者错误路径；内核队列溢出、其他未处理异常/内存耗尽或整个服务退出仍不能据此宣称持续保护。未知队列没有新增端到端期限，保留group可能意味着请求持续等待，不能称为通用自动恢复。

## 状态

当前同包管理协议为v11/528字节，BPF事件和分析协议未改变。新增：

| 字段 | 含义 |
| --- | --- |
| reader_state=offline | 已确认读取者不可用，主服务保留group；reader_pid为-1 |
| reader_failure | none、disconnected、protocol、transport或resource；当前门恢复后为none |
| reader_failures | 跨订阅替换累计故障次数 |
| reader_error_requests | 因读取者故障确认写回拒绝的累计请求数，已包含在denied中 |
| reader_unconfirmed_requests | 故障拒绝写回无法确认的累计有效队列条目数，不包含在成功裁决总量中 |

`secmon-policyctl --require-ready`对offline返回reader_offline和退出1。进度年龄继续显示最近确认距今时长，不把离线伪装为一般超时。新订阅恢复后保留累计计数；状态为responsive不清空历史。

## 允许的恢复与更新

- 普通同订阅重载不恢复读取者；fanotify裁决参数完全不变时，仍允许更新独立BPF策略，例如关闭不同对象的vault会话。
- 离线时不允许先修改原门的裁决参数再绕过恢复条件：deny、延迟或分析门不能先改成allow再关闭原group。
- 仅故障前就是即时静态allow、且有效队列空闲的门，允许使用原[显式重绑定](FANOTIFY_REBIND.md)合同：提高fanotify-rebind-epoch，准备新group/读取者，与BPF完成原事务后替换。候选失败不消耗代际，也不释放旧group。
- 同样符合既有条件的显式目标集合切换也可准备新订阅。没有自动重启、自动修改revision或自动接管提供进程。
- 新门可以改为deny。旧group释放按故障前allow合同；同一个在途系统调用仍可能遇到新门并被拒绝。group级允许不等于系统调用最终成功，更不能凭新审计推断旧未知请求已完整记账。

旧门为deny/延迟/分析时继续报告restart_required，保留旧group及BPF。管理员授权stop/完整重启会关闭group，未知请求可能由内核释放；这是已有停止合同，不能把“重启恢复”写成未知请求全部被拒绝。D状态或其他最后group引用也可能延长实际释放，不保证恢复耗时。

## 验证

reader-recovery覆盖legacy/pidfd两种模式，各有即时allow、deny、延迟、分析及组合BPF资源故障，共十种场景；另有真实FAN_DENY写回EIO的测试专用拦截器，以及读取者离线期间仍能通过vaultctl关闭独立保险箱会话的联合场景。验证故障后的主服务、BPF文件拒绝及信号自保护保留，已交付队列拒绝，未知请求等待、普通重载不恢复、禁止改变离线拒绝合同、显式代际恢复及审计序列。

组合模式通过限制本次读取子进程RLIMIT_NOFILE触发真实读取失败，未禁用自保护。资源限制操作不在当前信号/ptrace保护范围内，这也再次说明现有自保护不是完整管理员威胁防护。测试专用动态库只在明确传入LD_PRELOAD的测试服务中失败真实fanotify拒绝写回，不安装、不提供生产故障开关。

内核行为依据：[Linux 6.12 fanotify_user.c](https://raw.githubusercontent.com/torvalds/linux/v6.12/fs/notify/fanotify/fanotify_user.c)中的权限响应匹配、读取失败拒绝和group释放。最终定向回归与不同构建验证记录单独列出。
