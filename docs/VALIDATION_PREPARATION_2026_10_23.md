# 策略准备隔离验收（2026-10-23）

环境：开发机Linux6.12.0-211.67.1.el10_2，GNU++17；具体合同和未解决路径见[有期限准备](BOUNDED_PREPARATION.md)。

- 普通/Release构建各33/33 CTest通过。
- 普通构建9个相关专题通过：policy-reload、writer-identity、metadata-identity、virtual-preparation、virtual-fanotify、vault-restart、writer-scope、fanotify-policy、fanotify-handover。各项合计约87秒；没有重新运行整套回归或长测。
- 最终补充的准备专题通过BPF-only/联合两种场景：status耗时3.14/4.49ms；候选分别在2.051/2.013秒返回prepare_failed，活动revision/epoch保留；busy计数、FD68/70回基线、恢复后重试、proc/self拒绝和stop取消通过。
- 辅助进程翻译单元clang静态分析0诊断。Release另通过virtual-preparation、namespace-policy、writer-identity三个重点专题（合计19.193秒）。

发现的失败没有抹去：最初联合夹具直接读取被暂停的FUSE订阅对象，预期权限读取完成，但实际先发生读取等待，进一步查询status也超时。恢复提供进程后清理完成。随后将“健康本地权限队列继续推进”和“暂停FUSE自身的事件路径”分开验收；前者已通过，后者仍未解决，不能把更换夹具解释为修复后者。

原始结果在本机`/tmp/secmon-bounded-validation-20261023`：related.log、final-bounded.log、ctest.log、release相关结果、静态分析输出与构建日志。验证集中在不同故障路径，不累计重复命令数量。下一项优先隔离FUSE fanotify事件读取，再推进提供进程监督和挂载绑定。
