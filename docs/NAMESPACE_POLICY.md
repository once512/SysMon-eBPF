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

本专题覆盖绑定别名与私有 tmpfs 文件对象，不等于完整容器支持。overlay/NFS/FUSE 等文件系统、user/PID namespace 身份、容器管理进程、权限委派和跨命名空间的管理客户端仍需分别验证；也没有证明 namespace 管理员无法卸载、替换或绕过全部防护入口。
