# 有期限的策略对象准备（2026-10-23）

本增量将**重载中的候选文件路径解析和新鲜属性查询**移到一个短命辅助进程。主线程等待其结果时继续推进管理、BPF事件和既有fanotify权限队列；拿到完整候选后停止让出执行，再执行原有后端准备/发布顺序。没有新增内核Map、配置语法或公开管理ABI。

## 行为

- 一次准备最多一个子进程、400个去重路径，等待预算为整批2000ms，不按每个文件重新计时。覆盖BPF目标、授权程序、当前启动的保险箱会话程序和新增fanotify目标；保留的fanotify路径仍固定旧inode，不按路径重新绑定。
- 子进程关闭继承的服务FD和标准流，仅保留私有socket；在多线程fork后只做不分配内存的系统调用及固定消息操作，以O_PATH|O_NOFOLLOW打开、fstat取新鲜属性，传回固定消息与SCM_RIGHTS。父进程复核消息、FD、实际设备/inode和类型，再保存为本次事务的句柄缓存。
- 后端从缓存复制原始O_PATH引用，不重新按路径打开；程序所有者/权限认证使用子进程的新鲜fstat，不能用缓存属性代替授权检查。过期启动的会话仍不要求旧程序存在。
- 等待期间status返回旧活动版本；第二个reload立即返回busy并计入拒绝数。stop取消准备，候选不发布，旧epoch及已触发响应不被失败候选解除。恢复提供进程后可重试原revision/epoch。
- 超时/取消向子进程发送SIGKILL，waitpid只用WNOHANG，常规循环回收退出子进程。不可中断内核等待无法保证立即死亡，因此未回收的准备者最多保留一个，禁止继续堆积辅助进程；子进程还设置父进程死亡信号。它不持有BPF Map/链接或fanotify group。
- `/proc/self`、`/proc/thread-self`的直接路径在准备阶段拒绝，避免把调用者对象错误替换为辅助进程对象；需要使用显式进程坐标，不能依赖调用者相关proc别名。普通文件及显式PID的proc/root路径另行验证。

固定FD的对象身份比较采用statx(AT_EMPTY_PATH|AT_STATX_DONT_SYNC)，只取设备、inode和类型，避免为身份检查再次向FUSE请求GETATTR。它用于fanotify事件/已有目标和来源排除检查，**不用于配置内容或程序权限认证**。该缓存语义参照[Linux statx说明](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.12.pdf)。

## 范围与下一项

本次修复已验证的部署是：配置源位于健康本地文件系统，FUSE对象作为BPF保护/诱饵目标；旧权限门处理健康本地文件。在FUSE提供进程暂停期间，status、stop和本地文件裁决仍可推进，候选约2秒失败，旧策略保留。

**尚未解决另一条FUSE权限事件阻塞路径。** 联合测试将暂停的FUSE文件本身作为fanotify目标并触发读取时，管理响应仍超时；恢复提供进程后才能继续。非阻塞fanotify group只保证无队列事件时不等，事件FD的创建仍会经过文件打开等VFS操作，内核路径可参见[fanotify_user.c](https://github.com/torvalds/linux/blob/master/fs/notify/fanotify/fanotify_user.c)。因此不能宣称主循环的所有FUSE等待已隔离；下一步应隔离权限事件读取/事件FD生命周期，不能通过放宽权限或偷偷禁用FUSE订阅掩盖问题。

配置源本身的打开/读取、初次启动以及尚未隔离的其他VFS操作也没有获得全局硬期限。整批2000ms是准备者等待预算，进度回调若陷入上述其他内核等待，仍不能保证端到端墙钟时限。提供进程监督、自动重挂载绑定及完整恶意判定没有在本次增量实现。

## 验证

```bash
ctest --test-dir build --output-on-failure
sudo python3 -B tests/run_privileged.py --only virtual-preparation
```

`bounded_preparation.py`的两个场景分别使用BPF-only和联合模式：暂停提供进程、查询旧版本、并发reload返回busy、正常本地读取完成旧裁决、约2秒失败、FD回基线、旧响应保留、恢复后重试原epoch成功、proc/self拒绝以及stop取消。它不把被暂停FUSE本身的数据读取完成计作已解决。

本轮只运行相关专题和短程检查，不做持续重复负载；结果见[本轮验收](VALIDATION_PREPARATION_2026_10_23.md)。
