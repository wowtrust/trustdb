# TrustDB 全链路双机性能报告

报告日期：2026-07-16

测试范围：磁盘文件系统 A/B、HTTP/gRPC、L2/L3/L4/L5、真实 OpenTimestamps、1 KiB/16 KiB/64 KiB payload、瞬时与持续写入、严格 fsync、Go microbenchmark、Linux `perf` 与故障边界。

本报告基于 `perf(batch): optimize proof materialization pipeline (#196)` 之后的主分支，并包含本轮测试中发现的配置、指标和 L4/L5 批量提交修复。密码、SSH 私钥、TrustDB 签名私钥和公网地址均不写入报告。

## 结论摘要

- 最终有效档位累计提交 2,675,000 条，`failed=0`、`batch_errors=0`、`proof_timeouts=0`、post-proof 查询失败为 0。
- 另有一次故意使用 131,072 batch queue 的 300k 饱和实验产生 5,015 个 `batch queue is full`，据此将持续高写 profile 调整为 262,144；修正后的 300k case 零错误。
- 1 KiB 持续高写 HTTP：Submit 55,125/s，L3 全量物化 14,797/s。相对 2026-04-30 同类 HTTP c128 基线，最终 100k 调优 case 的 Submit 提升 16.1%，L3 提升 4.84 倍。
- 1 KiB 持续高写 gRPC：Submit 60,528/s，L3 20,127/s。
- 瞬时突发 HTTP：Submit 62,319/s；极限 on-demand HTTP：63,105/s。后者不后台物化 proof，不可作为 proof-ready 或生产耐久性数字使用。
- 综合档位（group fsync、L4、无 storage token 索引）：Submit 37,443/s，L4 全量就绪 6,377/s。
- 生产安全档位（group fsync、full index、chunk sync、L4）：Submit 23,562/s，L4 4,569/s。
- 生产保证档位（每条 strict fsync、full index、chunk sync、L4）：Submit 1,043/s，L4 1,033/s。瓶颈是云盘同步写，不是 CPU。
- strict fsync + 真实 OTS：L5 143.7/s，10/10 批次锚定成功；所有抽样 proof 可用。
- 8192 条批次树从约 24,575 个对象降至 40 个 tile，达到存储对象目标。
- `CommitBatchIndexes/1024` 降至约 1.35 ms、792 KiB，相对旧实现时间降低约 94%、分配降低约 76%。
- 该 70 GiB 云盘上 ext4 的随机写显著优于 XFS：4 KiB 50.1k 对 22.8k IOPS，且 p99 为 3.19 ms 对 62.13 ms，因此最终采用 ext4。

## 测试环境

| 项目 | 服务端 | 压测端 |
| --- | --- | --- |
| CPU | 32 vCPU，AMD EPYC 9K84 | 32 vCPU，AMD EPYC 9K84 |
| 内存 | 61 GiB，无 swap | 61 GiB，无 swap |
| 虚拟化 | KVM，单 NUMA node | KVM，单 NUMA node |
| OS | OpenCloudOS Server 9.6 | OpenCloudOS Server 9.6 |
| Kernel | `6.6.119-49.23.oc9.x86_64` | `6.6.119-49.23.oc9.x86_64` |
| Go | 1.26.3 | 使用同一 linux/amd64 TrustDB 二进制 |
| 网络 | 同 VPC 内网 | 同 VPC 内网 |
| 网络 RTT | 20 次 ping 平均 0.158 ms，0% 丢包 | 20 次 ping 平均 0.158 ms，0% 丢包 |

服务端数据盘为独立 70 GiB 云盘，TrustDB WAL、Pebble WAL、SST 和 proof artifact 均位于该盘。它仍是单盘测试，不代表 WAL 与 proofstore 分盘后的上限。

## 磁盘格式 A/B

测试在同一块空盘上依次格式化 XFS 和 ext4。顺序写为 1 MiB block；随机写使用 4 jobs、iodepth 32；同步写为 4 KiB `fdatasync`。

| 文件系统 | Case | 吞吐 / IOPS | p95 | p99 |
| --- | --- | ---: | ---: | ---: |
| XFS | 1 MiB 顺序写 | 351.80 MiB/s | 92.80 ms | 94.90 ms |
| ext4 | 1 MiB 顺序写 | 351.77 MiB/s | 92.80 ms | 139.46 ms |
| XFS | 4 KiB 随机写 | 22.82k IOPS | 9.50 ms | 62.13 ms |
| ext4 | 4 KiB 随机写 | 50.11k IOPS | 2.74 ms | 3.19 ms |
| XFS | 16 KiB 随机写 | 17.44k IOPS | 3.82 ms | 24.77 ms |
| ext4 | 16 KiB 随机写 | 22.32k IOPS | 2.93 ms | 3.26 ms |
| XFS | 4 KiB fdatasync | 1,534 IOPS | 0.897 ms | 1.319 ms |
| ext4 | 4 KiB fdatasync | 1,152 IOPS | 0.979 ms | 1.286 ms |

最终选择 ext4。XFS 的单次同步写中位数略好，但随机混合写的吞吐和尾延迟明显不适合本盘上的 Pebble workload。

最终挂载和内核设置：

```text
/dev/vdb ext4 rw,noatime,nodiratime,stripe=64
I/O scheduler: none
vm.dirty_background_bytes = 134217728
vm.dirty_bytes = 1073741824
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
```

保留 ext4 默认 ordered data、journal 和 barrier 语义。没有使用 `nobarrier`、关闭 journal 等会伪造耐久性数字的设置。

## 指标口径

| 指标 | 完成条件 |
| --- | --- |
| Submit TPS | 服务端返回 signed accepted receipt；不等待 proof。 |
| L3 TPS | 本 case 的 materialized records 达标，ingest/batch/materializer queue 和 in-flight 全为 0。 |
| L4 TPS | L3 完成，且新增 batch root 均计入 `trustdb_global_log_published_roots_total`。 |
| L5 TPS | L4 完成，且新增 STH 均进入 published anchor，anchor in-flight 为 0。 |
| 正确性 | 提交、batch、proof wait、post-proof query 四类错误分别统计。 |

旧报告以最新 STH tree size 近似 L4 边界；本轮增加独立 published-root counter，避免把“已规划”误算为“已发布”。

## 推荐档位

| 档位 | 主要参数 | 适用场景 | 本机结果 |
| --- | --- | --- | ---: |
| 极限 `extreme` | batch fsync、on-demand proof、time-only、L4 off、32 ingest workers | 只测 L2 上限、允许 proof 首次查询变慢 | 63,105 Submit/s |
| 瞬时 `burst` | batch fsync、16,384 records/batch、500 ms、32 workers | 短峰吸收，后台继续完成 L3 | 62,319 Submit/s |
| 持续高写 `l3-throughput` | batch fsync、8,192 records、200 ms、16 ingest、4 materializer | L2/L3 综合吞吐 | 55,125 Submit/s；14,797 L3/s |
| Proof 优先 `proof-ready` | 8 ingest、8 materializer | 压低 proof backlog 和 p99 | 46,393 Submit/s；18,487 L3/s |
| 综合 `balanced` | group fsync、no-storage-token、L4、8/3 workers | 有界异步 WAL 窗口 + L4 + 较低写放大 | 37,443 Submit/s；6,377 L4/s |
| 生产安全 `production-safe` | group fsync、full index、chunk sync、L4/OTS、4/2 workers | 默认推荐生产性能基线 | 23,562 Submit/s；4,569 L4/s |
| 生产保证 `production-guaranteed` | strict fsync、full index、chunk sync、L4/OTS | 每条 accepted receipt 对应一次 WAL fsync | 1,043 Submit/s；1,033 L4/s |
| 大载荷 `large-payload` | batch fsync、4,096 records、16/4 workers | 16/64 KiB claim 压测 | 见下表 |

这些 YAML 都使用独立数据目录。`benchmark` run profile 只负责显式标注测试语义；生产部署仍需按故障模型选择 fsync、索引和 L4/L5，不能按 TPS 最高项直接抄配置。

## 1 KiB 结果

| Profile | 协议 | 数量 / 并发 | Submit TPS | p95 / p99 | L3 TPS | L4 TPS | L5 TPS |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| 持续高写 | HTTP | 300k / 256 | 55,125 | 10 / 10 ms | 14,797 | - | - |
| 持续高写 | gRPC | 100k / 256 | 60,528 | 10 / 10 ms | 20,127 | - | - |
| 瞬时突发 | HTTP | 100k / 256 | 62,319 | 10 / 10 ms | 15,640 | - | - |
| Proof 优先 | HTTP | 100k / 128 | 46,393 | 5 / 5 ms | 18,487 | - | - |
| 综合 | HTTP | 100k / 128 | 37,443 | 10 / 10 ms | 9,408 | 6,377 | - |
| 生产安全 | HTTP | 50k / 64 | 23,562 | 5 / 10 ms | 5,331 | 4,569 | - |
| 生产安全 + file anchor | HTTP | 20k / 64 | 24,142 | 5 / 10 ms | 7,977 | 3,781 | 3,226 |
| 生产安全 + OTS | HTTP | 1k / 16 | 17,883 | 5 / 10 ms | 2,569 | 1,926 | 368.0 |
| 生产保证 | HTTP | 20k / 32 | 1,043 | 50 / 50 ms | 1,033 | 1,033 | - |
| 生产保证 + OTS | HTTP | 1k / 16 | 993 | 20 / 20 ms | 881 | 879 | 143.7 |

`production-safe` 的 materializer worker 从 2 增加到 4 后，L4 从 4,569/s 增至 5,132/s，但 Submit 从 23,562/s 降至 21,646/s。默认保留 2 个 worker，以免 proofstore 写入和 compaction 抢占提交路径。

## 极限与 On-demand 代价

`extreme` 在 300k、并发 256 下：

- Submit 63,105/s，p50 5 ms、p95/p99 10 ms、max 72.18 ms。
- `materialized_records_total=0`，符合 on-demand 模式；此数值不能宣称 proof ready。
- 后续对新提交的 16 个样本请求 L3，16/16 成功，无 timeout。
- 首次 proof 平均 64.2 ms，max 1.018 s；已物化后的 record 查询平均 0.187 ms。
- 该档位使用 batch fsync，主机掉电窗口内可能丢失已返回的 accepted receipt，不能用于审计合规承诺。

## 大载荷

以下为最终 16 ingest workers / 4 materializer workers 配置。64 KiB gRPC 的 L3 采用独立空库复测，避免前序 case 的 compaction 干扰。

| 协议 | Payload | 数量 / 并发 | Submit TPS | p95 / p99 | L3 TPS |
| --- | ---: | --- | ---: | ---: | ---: |
| HTTP | 16 KiB | 20k / 32 | 34,165 | 2 / 5 ms | 22,072 |
| gRPC | 16 KiB | 20k / 32 | 36,309 | 2 / 2 ms | 22,394 |
| HTTP | 64 KiB | 10k / 32 | 31,896 | 2 / 5 ms | 15,338 |
| gRPC | 64 KiB | 10k / 32 | 33,140 | 2 / 2 ms | 15,627 |

大 payload 下网络并非首要瓶颈；L3 下降主要来自 claim CBOR、bundle 编码、Snappy 判断和 Pebble artifact bytes 增长。gRPC 的提交吞吐和尾延迟稳定优于 HTTP，但 proofstore 完成速度接近。

## L4/L5 与 OTS

- global-log worker 一次最多规划并顺序追加 128 个 root，写入 leaves/nodes/STHs 后批量更新 outbox。
- 本轮将 global published 状态和 anchor outbox 放进同一个 proofstore batch，消除“L4 已发布但 L5 任务未入队”的崩溃窗口。
- file anchor 本身约为本地同步写，L5 端到端仍受 L4 record promotion、worker 调度和 proof 查询可见性影响。
- 真实 OTS case 使用公共 calendars。生产安全单批次测试中 3 个 calendar 接受，另一个域名 DNS 失败；`min_accepted=1` 下 proof 正常发布。
- strict + OTS 的 10 个 anchor 平均 sink latency 约 1.56 s，L5 全部完成，无 pending batch。
- 公共 OTS 依赖互联网 DNS 和 calendar 服务，不应把单次 L5 TPS 当成固定容量 SLA；生产应持续监控 accepted calendar 数、pending age、retry 和 upgrade backlog。

## Go Microbenchmark

32 vCPU 服务端，Go 1.26.3，结果区间来自多次运行：

| Benchmark | 时间 | 分配 | 说明 |
| --- | ---: | ---: | --- |
| `CommitBatchSynthetic1024` | 5.38-5.46 ms | 2.73 MB / 9,386 allocs | 完整 L3 materialized |
| `CommitBatchIndexesSynthetic1024` | 1.35-1.36 ms | 792.5 KB / 3,092 allocs | plan-only |
| inline batch / 1024 | 5.73-5.80 ms | 3.77 MB / 9,350 allocs | 一次构树并生成 bundle |
| async plan + tree / 1024 | 1.62-1.64 ms | 1.07 MB / 3,101 allocs | 无 receipt 签名 |
| incremental time-only / 1024 | 9.49-14.62 ms | 4.77-5.74 MB | 只增量提升 L2→L3 |
| 旧式全量重写 time-only / 1024 | 22.33-24.66 ms | 12.69-14.00 MB | 对照组 |
| incremental time-only / 8192 | 78.4-81.7 ms | 40.2-41.5 MB | 增量路径 |
| 旧式全量重写 time-only / 8192 | 175.8-177.7 ms | 103-108 MB | 对照组 |

验收判断：

- `CommitBatchIndexes/1024` 时间下降约 94%，分配下降约 76%，超过 80%/70% 目标。
- `PutBatchArtifacts/time_only` 增量路径在 1024 和 8192 档的时间、分配均下降超过 40%。
- 8192 records 写 16 个 leaf tile + 24 个 node tile，共 40 个 tile，达到“不超过 40”目标。

## CPU、内存与 I/O

Linux `perf` 捕获 17,547 samples，丢失 0：

- Ed25519 field square 11.57%、field multiply 9.60%，调用链覆盖 accepted receipt 签名、committed receipt 签名和 client claim 验签。
- Snappy encode block 约 5.01%，是大 bundle 路径的第二梯队热点。
- `memmove` 约 2.67%，说明编码和 proof artifact 仍有复制成本。
- Ed25519 是不可绕过的协议成本；通过 ingest/proof worker 分离和固定并发池利用多核，而不是改变签名或 proof 字节。

代表性 100k 高写采样中，TrustDB 峰值约 9.13 CPU cores、RSS 约 1.08 GiB，数据盘瞬时写入约 340 MiB/s。最终 16-worker gRPC case 的 systemd MemoryPeak 为 1.36 GiB。32 核仍未全部被单一阶段吃满，瓶颈会在签名、Pebble 写入和 compaction 间移动。

队列调优：

- 1,048,576 batch queue 空载就会带来约 782 MB heap，不适合常驻服务。
- 131,072 在 300k sustained case 出现 5,015 个 queue-full。
- 262,144 是本机持续高写的折中，空载内存约 200 MB，修正后 300k 零错误。
- 生产安全和生产保证档位保留更小队列，优先有界内存和背压。

## 与 2026-04-30 对比

选择语义最接近的 HTTP 100k/c128 case：

| 指标 | 2026-04-30 | 2026-07-16 | 变化 |
| --- | ---: | ---: | ---: |
| Submit TPS | 49,150 | 57,051 | +16.1% |
| L3 materialized TPS | 3,357 | 16,248 | 4.84x |
| Submit p95 | 5 ms | 5 ms | 持平 |
| 错误 | 0 | 0 | 持平 |

持续 300k HTTP case 的 L3 为 14,797/s，仍是旧基线的 4.41 倍。L2 未发生目标中的 5% 回退，L3 超过 2 倍验收目标。

## 已落地优化

- 统一 plan-only/materialized 批次计算，避免规划阶段签名和重复构树。
- committed receipt 固定并发签名池、池化签名输入 buffer、稳定输出顺序。
- `preparing -> prepared -> committed/failed` 持久化 manifest 与有界 materializer。
- 指数退避、重启恢复、prepared manifest 扫描和 per-batch singleflight。
- `PutPreparedBatch`、`PutMaterializedBatch`、`PutInlineBatch` 分离不变 artifact 与增量索引提升。
- Pebble batch 预分配、分级 buffer pool、小 bundle 跳过压缩、压缩收益阈值。
- 512-entry batch tree v2 tile，不持久化 level-0 node。
- global-log 批量追加、批量 outbox 状态更新、原子 anchor outbox 创建。
- anchor 与 OTS upgrader 有界 worker。
- 增加 materializer、阶段延迟、artifact、tree tile、global-log、anchor 指标。
- 修复 `anchor.sink`/`anchor.path` YAML 未被 typed config 读取的问题。
- 新增 `anchor.poll_interval`，benchmark 可用 250 ms 恢复轮询，生产可保留较低后台压力。
- 修复 Pebble zombie bytes 指标的无符号下溢展示。

## 生产建议

1. 默认从 `benchmark-production-safe.yaml` 的语义出发，不要从 extreme/burst 开始删安全项。
2. 需要“accepted 后主机掉电也不丢”时使用 strict；本盘上应预期约 1k/s，若要更高需要低延迟本地 NVMe、企业云盘或 group commit 的业务取舍。
3. 业务只按 record ID 和时间检索时可评估 `no_storage_tokens`；需要 tenant/client/hash/storage-token 完整查询时保留 `full`。
4. L4/L5 开启时优先保持 ingest workers 4-8、materializer 2；盲目增加 worker 会争用 Pebble 和 compaction。
5. 监控 prepared backlog、oldest age、retry、queue depth、Pebble compaction debt、global-log backlog、anchor in-flight 和 OTS pending。
6. 生产容量测试至少运行 30-60 分钟，并覆盖数据库增长后的 compaction steady state；本报告的短 case 用于横向选型，不替代长期 soak。
7. 更高上限优先考虑 WAL 与 Pebble/SST 分盘，其次才是继续扩大队列。

## 限制

- 单服务端、单 Pebble 数据盘；没有在本轮远程环境部署 TiKV 集群。
- 云盘仅 70 GiB，无法模拟数百 GiB 数据和多层 compaction 的长期稳态。
- 多数调优 case 单次运行，关键异常 case 做了隔离复测；正式 SLA 应使用多轮 benchstat 和长时间 soak。
- 公共 OTS、DNS 和互联网延迟不受 TrustDB 控制。
- extreme/burst/high-write 使用 batch fsync，不代表生产审计耐久性。

## 代码验证

| 验证项 | 结果 |
| --- | --- |
| `go test ./...` | 通过 |
| `go test -race ./...` | 通过 |
| `go vet ./...` | 通过 |
| `go test -tags=e2e ./cmd/trustdb` | 通过 |
| app/WAL/objectstore/HTTP integration tests | 通过 |
| Pebble/TiKV proofstore conformance | 通过 |
| `bash -n scripts/perf/run-drain-case.sh` | 通过 |
| 机器可读摘要 `jq empty` | 通过 |
| `git diff --check` | 通过 |

TiKV 的远程多节点吞吐没有在本轮两台机器上测试；此处 TiKV “通过”仅指 Store conformance、单元测试和 race 检查。

机器可读摘要见 [`results/2026-07-16-summary.json`](results/2026-07-16-summary.json)。测试脚本为 [`scripts/perf/run-drain-case.sh`](../../scripts/perf/run-drain-case.sh)。
