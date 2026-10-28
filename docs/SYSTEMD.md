# systemd就绪通知与服务模板（2026-10-28）

主服务支持可选NOTIFY_SOCKET的Unix数据报通知，不链接libsystemd。未设置时沿用原有前台运行；设置有效的绝对路径或@抽象地址时，主进程在启动线程和辅助进程之前保存并从环境中移除该变量，避免辅助程序意外报告主服务就绪。

BPF/fanotify/托管提供进程及管理资源完成初始化后，在进入主循环前发送READY=1。它表示本次启动的资源初始化完成，不是持续健康承诺；运行期仍用secmon-policyctl --require-ready/--require-decoy查看后端进度和挂载归属。初始化失败不发送READY；显式配置的通知地址无法接收初始READY时，主服务启动失败并回收已经创建的资源。

正常停止先尽力发送STOPPING=1，再按既有顺序关闭权限门、BPF和辅助进程。通知套接字非阻塞，不等待接收方腾出空间；接收方消失或队列满不会阻止停止。数据报未被接收不等于管理器已经处理，未实现barrier、watchdog或notify-reload握手。

## 生成与审阅模板

CMake生成build/secmon.service，路径来自配置时的安装前缀。暂存/正式安装只把它放入share/doc/SecMon/examples，不写入systemd单元目录，也不会daemon-reload、enable或start。

模板使用Type=notify及NotifyAccess=main，前台单主进程、root私有/run/secmon/management、现有root管理命令ExecReload和ExecStop。策略文件须由管理员先配置为/etc/secmon/policy.conf；模板不猜测保护文件，也不自动挂载诱饵。安装前缀在cmake --install时被另外覆盖不会重写已生成的模板，需重新配置或审阅路径。

确实部署时，管理员在审阅之后自行复制模板到/etc/systemd/system/secmon.service并按常规管理服务。本轮没有在开发机执行这些启用步骤。配置中的辅助程序路径、真实目标和访问权限仍以实际部署为准。

模板保留运行目录到正常停止以后，避免把目录清理当作未知/断开的FUSE挂载清理；管理socket仍由服务按所有权解除。Restart=on-failure只恢复整个退出的服务，有三次/60秒的启动速率限制；它不修复断开的FUSE挂载、恢复旧canary响应或跨实例会话墓碑，也不保证重启间隙持续保护。既有绝对会话期限不会因重启续期。

## 自保护与管理器边界

正常停止使用管理socket，不依赖外部信号。主服务和特权辅助的自保护也可能拒绝systemd/其他root任务的外部信号；TimeoutStartSec/TimeoutStopSec不是能强制终止D状态或绕过LSM保护的保证。模板不配置watchdog重启，不把服务管理器当作完整防挂起/持续保护方案。

运行期提供进程离线不等于主服务退出，systemd的进程重启策略不会因此自动重挂载。不得为恢复方便自动卸载归属未知的挂载；见[挂载归属](MOUNT_IDENTITY.md)。权限组未交付事件和停止释放语义继续遵循fanotify合同。

## 验证与协议依据

service-notify无特权检查覆盖路径/抽象地址、环境移除、完整消息、队列饱和和管理端消失。virtual-service-notify使用真实BPF、fanotify、托管FUSE及降权分析器，核对内核SCM_CREDENTIALS中的主进程身份，验证资源就绪后通知、正常停止、管理端消失及启动失败回滚；使用私有接收套接字，不实际注册systemd服务。

协议依据为[systemd sd_notify文档](https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html)及[systemd.service文档](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)。模板语法另用本机systemd-analyze verify检查，不能以私有套接字实验替代真实开机、升级、掉电和自动重启验收。
