# 显式重新绑定增量验收（2026-10-26）

在`7c7d998`后推进半小时增量，功能提交`3ca4dc9`。新增fanotify-rebind-epoch，保持原有即时allow/空闲条件，以递增代际显式刷新同路径全部目标，与BPF共用候选对象引用。合同见[重新绑定](FANOTIFY_REBIND.md)。当前管理协议仍为v9/472字节，无BPF Map/事件布局变化。

## 环境与结果

环境沿用本机Linux6.12.0-211.67.1.el10_2.x86_64、GNU++17/GCC14.3.1、libbpf1.7.0及fuse3 3.16.2。

| 范围 | 结果 |
| --- | --- |
| 普通与Release CTest | 各34/34通过，含代际数字边界及重复字段解析 |
| 关闭可选FUSE的核心Release | 构建完成，33/33通过 |
| 普通构建相关专题 | virtual-preparation、fanotify-multiple、fanotify-handover、fanotify-rebind、virtual-rebind五项通过 |
| 更新后的真实FUSE暂停准备专题 | 单独补测通过，失败准备保留原代际及响应 |
| Release相关专题 | fanotify-policy、fanotify-rebind、virtual-rebind、subscription-lifecycle、management-live、policy-consistency六项通过 |

未重跑上一阶段完整72项名单，也未增加持续长测。普通五项记录中的FUSE专题是初始版本，随后加入暂停准备用例，普通补测和Release六项使用更新后的版本。

原始日志、构建输出及程序摘要位于本机`/tmp/secmon-rebind-20261026-1248`，临时目录不保证长期保存。普通主程序SHA-256为`240988b3627c3d9ed2571223273120eb6bf97785fe8b36080c4a2fbc85612b6d`。

## 核对的行为

- 独立/联合服务与legacy/pidfd四个变体：先替换同路径文件，普通重载仍对旧别名生效；提高代际后，订阅才移动到新对象。BPF对新对象的已有写FD执行拒绝，旧对象不被误认成新对象。
- 同代际普通重载不创建新group；降低/省略已发布正代际被拒绝。成功切换的订阅代际、权限request_id、对象、revision及实际decision与审计逐条对应。
- 符号链接准备失败、BPF vault/listener读冲突均回滚；后者覆盖候选group已准备但BPF安装拒绝的路径。相同代际可重试成功，失败不生成handover，也不消耗代际。
- FD数量按配置核对：独立模式回到原数量；联合模式新增一个BPF保护目标，仅有预期的一个稳定引用增量。
- 繁忙返回busy，旧deny/延迟/空闲分析模式拒绝重新绑定，保留活动revision。
- 真实FUSE旧视图显式detach并终止后，在原路径挂新视图：普通重载保留旧fanotify对象；提高代际后，BPF canary和fanotify权限审计都对应新设备/inode。测试同时核对独立canary-response epoch的显式解除行为。
- 暂停提供进程时，重新绑定的对象准备约2秒失败；原revision、fanotify代际和已有响应保留，恢复后可重试。三个权限记录分别属于原挂载、原挂载和新挂载的实际调用方。

开发夹具首次错误假设两个protect硬链接会拒绝，实际实现会保守合并相同inode；已改为现有vault/fanotify读冲突来测试BPF阶段拒绝。该开发失败保留在原始日志中，不当作验收通过；功能代码没有为迁就测试而改变别名规则。

## 保留范围

本字段不执行重挂载、自动恢复或提供进程接管，不能把外部提供进程自动纳入托管自保护，也不清除已有托管offline状态。旧拒绝/分析门的无损恢复、挂载归属认证及不可中断D状态仍未解决。普通重载对象保留、未知内核事件及group关闭边界继续遵循现有合同。
