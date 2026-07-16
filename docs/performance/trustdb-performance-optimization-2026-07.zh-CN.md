# TrustDB 性能优化实现说明（2026-07）

本轮改造针对 2026-04-30 报告中 L2 提交吞吐与 L3 proof 物化吞吐之间的差距。

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

## 本地验证结果

测试环境为 Apple M1，结果用于判断相对热点，不与双机 32 vCPU 报告做绝对值比较。

| Benchmark | 优化前 | 优化后 |
| --- | ---: | ---: |
| `CommitBatchIndexes` / 1024 | 约 23.6 ms、3.34 MB | 约 1.20-1.31 ms、0.79 MB |
| L2 plan + compact tree snapshot / 1024 | 约 23.6 ms、3.34 MB | 约 1.46-1.57 ms、1.06 MB |
| materialized time-only / 1024 | 约 33-36 ms、12.9 MB | 约 26-29 ms、4.7 MB |
| batch tree / 8192 | 约 24,575 objects | 40 tiles |

新物化路径的 CPU profile 已不再以 storage token 生成/删除为主，剩余主要成本来自 Pebble WAL/SST 写入与 compaction。完整的 100k 双机 Matrix 仍需在原 32 vCPU 环境使用三套独立 benchmark profile 复测。

## 兼容性

HTTP、gRPC、SDK 和 proof schema 不变。Pebble 物理 key schema 升级为 v2；启动时若发现没有 v2 schema 标记但已有数据，会返回 failed precondition。系统不会自动删除或迁移旧 proofstore。
