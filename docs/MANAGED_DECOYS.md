# 主服务托管虚拟诱饵视图（2026-10-26）

主服务可显式启动一个FUSE提供进程，等待就绪后再读取活动策略、固定inode及创建fanotify订阅。视图仍是没有磁盘后端的不可修改合成文件，不向已有业务目录透明插入文件。独立`secmon-decoyfs`用法继续保留。

## 启动示例

先构建本包，创建root所有的空挂载点及私有管理目录：

```bash
sudo install -d -m 0755 /run/secmon-demo /run/secmon-demo/view
sudo install -d -m 0700 /run/secmon-demo/management
sudo install -m 0600 examples/managed-decoy-policy.conf /run/secmon-demo/policy.conf
sudo ./build/secmon --policy /run/secmon-demo/policy.conf \
  --control /run/secmon-demo/management/control.sock \
  --decoy-provider "$PWD/build/secmon-decoyfs" \
  --decoy-mount /run/secmon-demo/view \
  --decoy-file accounts.csv --decoy-file notes.txt \
  --decoy-allow-other --audit-permissions --requester-pidfd
```

`--decoy-provider`和`--decoy-mount`须绝对路径，须有1..64个不同的合法`--decoy-file`名字；挂载点沿用原有空目录、所有权及路径校验。程序不创建该目录，也不接管已有挂载。提供程序由root启动配置显式选择，属于可信同包组件，不是任意不可信插件的沙箱。配置仍须逐项选择canary和fanotify目标；发布文件不会自动认定其已被策略选中。

`--decoy-allow-other`默认关闭，只有明确指定才向其他用户开放FUSE访问。未开启时，降权内容分析器访问root视图的新鲜属性会得到EACCES，记录metadata_failed并采用配置的分析错误回退；不能把它误认为扫描器已死亡。选用内容分析器并需要正常扫描时应明确开启。该选项不会开放管理socket，管理目录仍为0700。

另一终端可查询或授权停止：

```bash
sudo ./build/secmon --status /run/secmon-demo/management/control.sock
sudo ./build/secmon-policyctl --socket /run/secmon-demo/management/control.sock \
  --expect-revision 1 --require-ready --require-decoy
cat /run/secmon-demo/view/accounts.csv
sudo ./build/secmon --stop /run/secmon-demo/management/control.sock
```

诱饵修改响应按触发线程组生效；实验修改应放在单独测试进程中，避免让交互shell自己触发文件修改及fork/exec限制。示例不会自动安装服务或开机启动。

## 生命周期与协议

主服务启动时先恢复SIGCHLD的可回收状态，避免继承忽略/自动回收破坏未回收子PID的所有权。主服务拥有提供进程的私有SOCK_SEQPACKET和pidfd。spawn只保留约定FD3及指向/dev/null的标准流，不继承管理、BPF或fanotify引用。提供进程核对socket类型、创建端身份和实际父进程，安装父死亡信号；完成FUSE初始化回调后发送Ready。spawn完成后的Ready等待最多约2秒；可执行程序路径的exec、配置源读取等仍不具有全局启动硬期限。

托管模式在同一个FUSE请求循环中轮询控制通道，约250ms一个未确认探测，避免单独“心跳线程仍活着”掩盖回调循环停滞。FUSE设备使用非阻塞读取，处理就绪与取消之间的竞态。接收/处理缓冲区按[libfuse 3.16.2单线程循环](https://raw.githubusercontent.com/libfuse/libfuse/fuse-3.16.2/lib/fuse_loop.c)的生命周期释放；不新增逐文件磁盘后端。

停止先完成主服务原有资源关闭，并在释放策略/订阅对象引用后停止提供进程。正常请求SIGTERM，最多约200ms尝试回收，再定向SIGKILL并做短暂非阻塞回收；等待上限不能保证立即解除不可中断D状态。提供进程为特权直接子进程时，随主服务[自保护](HELPER_PROTECTION.md)，父服务仍有清理权限。独立启动的提供进程不自动归入这一关系。

## 状态与失败

当前管理协议为同包v9/472字节；BPF及分析协议未因此改变。新增字段在所有后端可查询：

| 字段 | 含义 |
| --- | --- |
| decoy_files | 本次启动声明的文件数；未托管为0，不是实时目录扫描 |
| decoy_provider_pid | 当前尚未回收的子进程PID；未配置/已回收为-1，仅供诊断 |
| decoy_provider_state | none、responsive、unresponsive或offline |
| decoy_provider_progress_age_ms | 最近Ready/匹配确认距今的单调毫秒数 |
| decoy_provider_error | none、disconnected、protocol、transport或sequence |

两秒未确认显示unresponsive；恢复后同一进程可以重新responsive。真实断连或协议错误显示offline，停止该后端并保留其他主服务策略。查询不等待FUSE、不重启、不重新绑定目标，也不据此认定当前路径仍可见或inode未变。

提供进程意外死亡、启动阶段强制杀死或暂停期间强制停止，可能留下断开的FUSE挂载；本轮故障实验实际观察到这一情况。不自动lazy detach可能被外部更换的挂载点。管理员应先授权停止主服务，核对自己拥有的挂载，再清理残留并显式重新启动。正常停止验收已核对进程回收、挂载解除和空目录恢复。

重挂载会产生新对象。相同路径的fanotify目标默认保留原inode，更高revision本身不保证刷新该订阅；本模块没有自动重挂载/重绑定。显式完整重启可重新固定并订阅新视图，同时遵循现有服务重启、策略计数和响应状态不持久的合同。已有BPF拒绝与主队列期限不应因提供进程的健康状态被取消。

## 验证

`virtual-managed`覆盖真实视图的策略前就绪、静态/内容分析、默认访问限制及显式allow-other、64文件边界、canary响应、自保护、空闲进度、暂停/恢复、真实死亡和暂停期间有界停止；另以不挂载文件系统的测试协议对端覆盖Ready超时/附件/版本/断连及运行期错误，核对独立BPF文件策略继续拒绝。后者是协议故障注入，不冒充真实挂载验收。失败策略后的真实视图回滚也检查卸载。

后续增量：现已支持管理员以更高fanotify-rebind-epoch[显式重新绑定同路径对象](FANOTIFY_REBIND.md)，仅限旧门即时静态allow且空闲。它不执行重挂载，也不接管新提供进程或清除托管offline状态；此前“同路径保留旧inode”继续描述普通重载。
