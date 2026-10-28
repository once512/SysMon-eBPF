# 构建与安装交付

运行产物按同一构建交付：主服务、管理工具、保险箱会话工具、降权分析器，以及可选的FUSE提供进程。BPF对象嵌入主程序；运行环境要求沿用[README](../README.md)的当前内核、BTF及BPF LSM条件。

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local
cmake --build build -j
ctest --test-dir build --output-on-failure
sudo cmake --install build
```

默认前缀下的运行文件：

| 路径 | 用途 |
| --- | --- |
| /usr/local/bin/secmon | 主服务及status/reload/stop客户端 |
| /usr/local/bin/secmon-policyctl | 只读策略/就绪核对 |
| /usr/local/bin/secmon-vaultctl | 管理员保险箱操作与核对重载 |
| /usr/local/bin/secmon-vault-session | 会话配置行签发工具 |
| /usr/local/libexec/secmon/secmon-analyzer | 私有降权扫描器 |
| /usr/local/libexec/secmon/secmon-decoyfs | 可选合成视图提供进程，也可独立挂载 |

文档、已有许可文件及配置示例位于`share/doc/SecMon`。路径可通过GNUInstallDirs及CMake安装前缀调整。配置中的`fanotify-analyzer`和启动时的`--decoy-provider`应显式指向实际安装的辅助程序路径；它们不按当前工作目录猜测位置。活动策略由管理员按实际已存在文件配置，示例见[托管视图](MANAGED_DECOYS.md)及[策略配置](POLICY_CONFIG.md)。

关闭可选FUSE构建时，核心服务及分析器仍可构建/安装：

```bash
cmake -S . -B build/core -DCMAKE_BUILD_TYPE=Release -DSECMON_BUILD_DECOYFS=OFF
cmake --build build/core -j
ctest --test-dir build/core --output-on-failure
```

该构建的安装集合没有secmon-decoyfs，主程序也不链接libfuse；已有BPF/fanotify能力保持独立。

## 暂存安装验证

打包时可先写入暂存目录：

```bash
DESTDIR="$PWD/build/stage" cmake --install build --prefix /usr/local
```

默认前缀会落在`build/stage/usr/local`。本轮实际核对了5个运行程序，关闭FUSE后为4个；测试程序和内部静态库不属于运行安装集合。安装产物的帮助入口均从`/`工作目录执行通过；随后用暂存主程序、扫描器和提供进程完成真实FUSE/分析/canary响应及授权停止，核对原文件不变、挂载解除。详见[本轮验收](VALIDATION_RUNTIME_2026_10_26.md)。

新增secmon-vaultctl后，运行安装集合为完整6个/核心5个；此前5/4集合描述2026-10-26验收。操作合同见[保险箱管理](VAULT_ADMIN.md)。
