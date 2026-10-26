# 静态 fanotify 事件读取隔离（2026-10-23）

本增量隔离静态allow/deny（包括延迟与超时回退）的事件读取和真实事件文件FD生命周期。内容分析模式仍走原读取链，不能据此称所有FUSE等待已解决。目标准备继续使用[上轮有期限准备](BOUNDED_PREPARATION.md)。

## 所有权和裁决

- 每个静态PermissionGate有一个读取子进程，处理fanotify read、创建/持有真实事件FD、缓存身份提取及最终close。它不持有BPF Map、控制socket或其他继承的服务FD；fork后只用固定存储和系统调用，不使用服务输出、分配器或应用锁。初始化先回复Ready，失败时关闭该候选。
- 主进程保留group、目标集合、策略版本、预算、期限及裁决。队列中持有的是本地eventfd句柄，退出不会对FUSE执行flush；真实文件不会传回主进程。请求者pidfd可通过SCM_RIGHTS传回并验证PIDFS，PID namespace坐标不因同namespace的读取子进程改变。
- 权限回复直接由主进程写group，使用内核最初记录的读取者FD令牌，而不是把另一进程的FD当作本地文件访问。内核按group和令牌匹配事件，不需要在主进程fget该数字，参照[Linux fanotify回复实现](https://kernel.googlesource.com/pub/scm/linux/kernel/git/stable/linux.git/+/399254aaf4892113c806816f7e64cf40c804d46d/fs/notify/fanotify/fanotify_user.c)。原始FD保持打开直到内核回复成功，随后以单调序号通知子进程释放，避免FD复用错误关闭其他请求。
- 清理消息异步、有界；文件close即使等待提供进程，也只阻塞读取者。主进程不等待清理完成才计量已经成功的内核裁决。已进入主队列的旧请求可以在读取者卡住时继续超时/拒绝。
- 子进程最多持有4097个真实事件引用；主进程最多有4097条待清理消息。全服务最多16个活动/尚未回收读取者槽，阻止不可中断内核等待导致无限创建进程。停止发送SIGKILL并仅进行约20ms的回收尝试；父进程死亡也触发SIGKILL。普通内核等待可解除，但不可中断D状态不能保证立即死亡或立即释放group最后引用。
- 主进程先保留裁决句柄，再接收可选pidfd。只有一个空闲FD时，仍能裁决，请求者引用按既有缺失附加引用合同报告error、inode/errno为0，不伪造可信身份。共享传输函数仅对此调用显式允许控制附件截断；分析协议默认仍严格拒绝截断。

## 接收和失败合同

pending、接收时间、revision和请求号均以主裁决队列接收为准；读取者/传输中尚未交付的事件不计入pending，也没有端到端系统调用时限。一个FUSE事件卡住读取者后，同group后续事件可能仍有队首阻塞；已交付的请求和管理循环不受这个读取等待拖住。

关闭/切换group时，读取者缓冲或正在创建FD的请求可能没有逐条审计；不能补造这些请求的原因、版本或回复数。实验中，停止期间尚未交付的FUSE读取由内核返回EPERM，但没有被计作主进程已经发送的一条deny。健康后端的即时allow目标切换仍有专项回归，不能扩大为故障后端上的无损承诺。

读取者断连、非法帧或严重资源不足仍按现有后端致命错误路径退出服务，没有新增持久拒绝或自动重启保证。静态路径已经隔离，分析模式的事件FD获取/主进程关闭仍待后续迁移；配置源、启动和其他VFS调用的既有边界也未改变。

## 本轮验证

```bash
sudo python3 -B tests/run_privileged.py --only virtual-reader
```

新专题使用同group的FUSE与本地目标，分别覆盖legacy/pidfd模式：先建立本地延迟请求，再暂停FUSE并触发另一读取；确认旧本地请求仍按700ms期限拒绝、status可用、重载准备约2秒失败、恢复后工作、FD回基线和暂停期间stop可用，并核对四条实际裁决的主体、原因与版本。

首轮夹具把FAN_DENY误当作BPF的EACCES，实际内核返回EPERM；修正预期后通过。另在现有FD压力专题发现仅剩一槽时服务退出，已通过优先保留裁决句柄、可选pidfd错误降级修补。不同失败路径各自复测，不以长期重复命令数量作为完成依据。

验收结果：原生与Release各33项CTest通过，读取者源文件Clang静态分析0诊断。特权专题中，新增virtual-reader通过（legacy/pidfd两种模式，暂停期间status约11ms、stop确认约2–12ms）；既有deferred、virtual-preparation、virtual-fanotify、handover、permission-audit及permission-namespace的legacy模式通过。修补FD压力问题后，requester-pidfd的open/access各七种场景及exec场景、shutdown-order均复测通过。未宣称完整特权套件全部重跑，未追加持续压力测试。原始输出位于本机`/tmp/secmon-reader-validation-20261023`，临时目录不保证长期保存。

后续增量：2026-10-26已扩展到[内容分析路径](ANALYSIS_EVENT_READER.md)。上文静态限定描述本轮原始验收，不代表后续版本仍使用同步分析读取。
