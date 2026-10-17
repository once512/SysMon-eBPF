# 文件对象策略与私有挂载命名空间

文件策略按 inode 身份匹配，不把用户路径当作唯一身份。新专题验证两种与部署有关的情况：

1. 在私有 mount namespace 将源目录 bind 到另一路径。别名的设备号和 inode 不变，BPF 只读与 fanotify 打开拒绝仍生效；关闭任意一层后另一层继续工作，邻近未标记文件不受扩大保护。
2. 子进程在私有 mount namespace 建立新的 1 MiB tmpfs，宿主原路径看不到其中的文件。父测试通过存活子进程的 `/proc/PID/root/...` 取得同一对象，分别给 BPF/fanotify 固定并安装策略，子进程在自己的普通路径上实际尝试读写。

第二种场景同时核对新文件系统实例的设备身份，并验证 Map 设备号拆分与用户态 major/minor 组合一致。O_PATH 保存的是文件/挂载对象引用，策略判断不要求业务进程使用宿主配置里的同一字符串路径。

```bash
sudo python3 tests/run_privileged.py --build-dir build --only namespace-policy
```

要求 `unshare`、`mount`、私有挂载权限、BPF 与 fanotify。每个命名空间通过 `unshare --mount --propagation private` 创建，不修改宿主挂载表或全局 sysctl；tmpfs 使用 size=1m,nodev,nosuid,noexec，场景仅测试读写。测试退出后命名空间和私有挂载由内核清理，并检查宿主目录始终未出现私有文件。

源码为 `tests/namespace_policy.py`。控制子进程保持存活期间再通过 proc root 固定对象，避免把已退出/复用的数字 PID 当成目标。先释放监听器与策略，再结束私有 tmpfs 所有者。

本专题覆盖绑定别名与私有 tmpfs 文件对象，不等于完整容器支持。overlay/NFS/FUSE 等文件系统、user namespace 身份与完整 PID namespace 部署、容器管理进程、权限委派和跨命名空间的管理客户端仍需分别验证；也没有证明 namespace 管理员无法卸载、替换或绕过全部防护入口。


## PID namespace 中的任务编号

```bash
sudo python3 tests/run_privileged.py --build-dir build --only pid-namespace
```

`tests/pid_namespace.py` 连续启动两个私有 PID/mount namespace，内部的 Python init 都报告 getpid()=1、getppid()=0，私有 proc 的 self/stat 也报告 1。宿主通过存活 unshare 监督进程的 children 和 NSpid 关联实际宿主 PID，核对凭证 Map 的全局 TGID/TID、start_boottime 键、子进程自报凭证和 exec_success 事件；每次退出后检查对应基线已删除。

BPF helper 的 pid_tgid 与 task 原始 pid/tgid 是初始 PID namespace 的任务标识，不能直接拿容器内 getpid() 与审计记录相等比较。本测试让两次相同的局部 PID 对应不同宿主键，未强制真实宿主 PID 回绕/复用。服务和管理客户端仍在宿主：跨 PID namespace 的 SO_PEERCRED/管理 PID 坐标、user namespace UID 映射与完整容器部署仍未验证。

命名空间使用私有 proc 挂载，并用 unshare --kill-child=KILL 约束监督进程结束时的 init 清理；不改宿主 proc 挂载或 pid_max。
