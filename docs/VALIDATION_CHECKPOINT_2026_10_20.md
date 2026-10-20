# 工作区整理与提交前验证（2026-10-20）

本次将 `6f59a3b` 之后积累在工作区的源码、测试、工具和文档统一整理为检查点；不把此前未提交的成果遗漏，也不将历史长测视为本轮重新运行。

## 提交范围

- 固定多目标 fanotify 订阅及即时静态 allow 条件下的受限在线目标切换；包含对象快照、共享请求序列、累计统计、候选失败回滚及管理 ABI v4。
- 离线证据归组、行为观察、采集重放、覆盖评估和多对象分析工具，及正常应用、受控修改、身份和订阅实验。
- 对应阶段验收文档、规划复核报告及 DESIGN 追加记录。
- 修正 TESTING 开头过时的测试数量：当前为 29 项 CTest。

构建产物、Python 缓存和本地 Qt Creator 配置继续由已有 .gitignore 排除，保留在本机，不纳入提交。

## 本轮实际结果

环境：`6.12.0-211.61.1.el10_2.x86_64`，`x86_64`。

- CMake 重新配置和构建成功。
- CTest：29/29 通过，耗时 2.14 秒。
- 默认特权 runner：45/45 专题及模式通过，退出码 0，各项耗时合计 372.983 秒；未增加可选持续负载。
- 68 个 Python 文件 AST 语法检查通过，Markdown 相对链接检查无缺失，git diff --check 通过。

本机完整特权日志：`/tmp/secmon-checkpoint-20261020.log`。该路径不是永久归档；测试结果限于当前环境与各专题断言，不证明真实攻击检测、生产误报率或完整文件系统覆盖。

## 本次验证的生产产物

| 产物 | SHA-256 |
| --- | --- |
| secmon | `8f493ef0d517f77638ce7f617ed0df72f7e42eff4f149bfc5474453428769d5d` |
| secmon-analyzer | `c99aad5add45d93d27dc6bd4df24e7a15452f20706b81015bf8913ea08ce361f` |
| secmon-policyctl | `75619831954610a95df6c8935dbd3f5ec2d3f1fd095f5b5f8ce3224371ae9571` |

## 复现命令

```sh
cmake -S . -B build
cmake --build build -j2
ctest --test-dir build --output-on-failure
sudo python3 -B tests/run_privileged.py --build-dir build
```

未在本轮重跑 Release、sanitizer、fuzzer 或此前的长时间负载；历史结果仍按各自冻结快照解释。剩余产品目标与边界见 [阶段复核](PLAN_REVIEW_2026_10_20.md) 和 [下一步](NEXT_STEPS.md)。
