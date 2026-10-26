# 显式同路径对象重新绑定（2026-10-26）

普通重载继续保留共同路径原先固定的inode。管理员已经恢复/替换路径，并明确希望重新固定对象时，可以在更高revision中提高`fanotify-rebind-epoch`：

```conf
revision 2
fanotify-file "/absolute/view/accounts.csv"
fanotify-event access
fanotify-decision allow
fanotify-rebind-epoch 1
```

该示例仍须带上需要保留的全部BPF/其他策略字段，使用原有root管理reload提交。它不是挂载操作或自动故障恢复。

## 触发与限制

- 字段最多一次，显式值为1..18446744073709551615；未使用时隐式为0。启动时给出的值是初始基线。
- 候选代际高于活动值，重新固定候选的全部fanotify目标，包括相同路径；共享路径不再复制旧引用。若目标列表同时变化，合并为一次group替换。
- 代际相同，不强制重新绑定，沿用原有共同路径保留规则。发布正值后降低或省略该字段按invalid_policy拒绝；新服务实例不提供代际的持久防回滚。
- 旧权限门必须是无延迟静态allow，且已交付请求为空。繁忙返回busy；旧deny、延迟或分析模式即使空闲也要求restart_required。候选可使用不同静态裁决，下一次再绑定仍按当时旧门判断。
- 纯配置/队列条件在进入VFS准备前先检查，准备后再次检查。新增字段不放宽既有[切换安全条件](FANOTIFY_HANDOVER.md)。

## 提交、回滚和审计

需要重新绑定的全部路径进入原有约2秒的有期限对象准备。fanotify mark与BPF候选使用同一批O_PATH引用，减少两个模块分别解析到不同对象的机会。新group先准备好，BPF候选成功后才无异常切换group、活动revision和代际。

路径缺失、符号链接、提供进程暂停、mark失败或BPF安装拒绝均保留旧活动策略。失败不消耗重新绑定代际或订阅代际，恢复后可重试相同候选值。引用固定的是准备时对象，不认证提交后路径一直未变。

成功替换group继续发出`fanotify_target_handover`，添加from_rebind_epoch/to_rebind_epoch；显式重新绑定时retained_targets为0。subscription_generation、请求序列和累计统计沿用原合同；同路径更新也计入一次target_updates。活动revision/原始配置摘要及切换审计可核对请求是否已发布，管理线格式仍为同包v9/472字节。

关闭旧group可能按先前allow语义释放未交付内核事件，因此不能用于旧deny/分析门的无损恢复。D状态可能延迟旧最后引用释放，准备/提交也不是跨内核钩子的全局原子操作；这些既有边界不变。

## 与虚拟视图的关系

实测在旧FUSE视图被管理员显式detach、提供进程死亡、相同路径挂上新视图后，普通重载仍保留旧fanotify对象；提高代际后，BPF canary与fanotify可同时固定到新对象。canary-response epoch仍独立控制旧进程响应的解除，不由本字段自动推进。

本字段不会重启、接管或重新认定提供进程身份，也不改变托管提供进程已观测的offline状态。外部重挂载的进程不会因此自动进入托管自保护；挂载归属检查、自动清理/重启及拒绝/分析模式的安全恢复仍待推进。
