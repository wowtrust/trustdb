# TrustDB 性能优化实现说明（2026-07）

本文只说明实现结构，不提供第二套性能数字。当前、唯一的双机性能口径见 [TrustDB 双机多语义持续流与证据路径性能评估](trustdb-sustained-stream-persistence-assessment-2026-07-23.zh-CN.md)。

## 已实现

- L2 批次规划只构建 Merkle root、L2 record index 和紧凑树快照，不再提前生成或签名 committed receipt。
- L3 receipt/proof 使用有界并行 worker，签名输入通过池化 buffer 编码，签名字节与旧实现保持一致。
- async materializer 使用持久化 manifest 状态机：`preparing -> prepared -> committed/failed`。
- materializer 默认 2 个 worker、4 个内存任务槽；队列仅是唤醒机制，prepared manifest 才是任务事实来源。
- 瞬时失败按指数退避重试，确定性数据损坏进入 `failed`；重启可从 WAL 幂等修复初始 L2 artifacts。
- async L3 提升只写 ProofBundle、主索引和 L2→L3 proof-level key，不再重写 root、树和不变的二级索引。
- Pebble 批次树改为 512-entry v2 tile；8192 条记录写 16 个 leaf tile 和 24 个非叶 node tile。
- level-0 node API 从 leaf tile 派生，不再持久化重复 hash。
- global log 支持一次顺序规划并批量提交最多 128 个 leaves/nodes/STHs。
- anchor 与 OTS upgrader 使用默认 4-worker 的有界并发。

## 验证口径

- 组件级 benchmark 用于发现热点和防止局部回退，不作为对外容量数字。
- 双机结果只从当前唯一评估文档及其机器可读摘要引用。
- Submit、L3、L4、L5 必须分别标注，不能把不同完成边界合并为一个 TPS。
- WAL、索引、artifact、proof mode 和 anchor 的语义必须随结果一起给出。
- Linux profiling 继续用于定位 Ed25519、编码复制、Pebble WAL/SST 和 compaction 热点，但 profiling 百分比不单独形成另一套性能口径。

## 兼容性

HTTP、gRPC、SDK 和 proof schema 不变。以下 v2 描述记录的是本次历史优化当时的边界；当前实现已统一升级为 proofstore storage schema v4。旧版本或无标记但非空的存储会返回 failed precondition，系统不会自动删除、迁移或双读旧 proofstore。
