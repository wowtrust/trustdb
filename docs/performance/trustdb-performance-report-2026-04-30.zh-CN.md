# TrustDB 性能优先双机内网复测报告

![TrustDB 性能优先复测概览](assets/perf-highwrite-ai-overview.png)

报告日期：2026-04-30

测试 Run ID：`perf-semantic-20260430T071902Z`

测试范围：语义可变性能开关、性能优先写入 profile、HTTP/gRPC 内网链路、旧 payload matrix 与 100k 大并发 matrix。

测试目标：在不记录密码、密钥等敏感信息的前提下，验证两台 CVM 通过内网连接时，TrustDB 单服务端在性能优先配置下的提交能力与 L3 proof 物化能力。

本报告替换上一版 `perf-v3` 报告。上一版以默认安全语义和 L4 proof-ready 为主；本版采用显式开启的性能优先 profile，最高 proof level 为 L3，因此不应与默认安全 profile 或 L4/L5 报告直接混读。

## 结论摘要

本次有效 drain-aware 工作负载共覆盖 850,000 条记录：

- 100k 大并发 matrix：HTTP 300,000 条，gRPC 300,000 条。
- 旧 payload matrix：HTTP 185,000 条，gRPC 65,000 条。
- 所有有效 case 的 `failed=0`、`batch_errors=0`、`proof_timeouts=0`、`post_proof_query_failed=0`。

| 指标 | HTTP | gRPC | 合计 / 范围 |
| --- | ---: | ---: | ---: |
| 有效提交记录数 | 485,000 | 365,000 | 850,000 |
| 提交失败 | 0 | 0 | 0 |
| Batch 错误 | 0 | 0 | 0 |
| Proof timeout | 0 | 0 | 0 |
| Proof 后查询失败 | 0 | 0 | 0 |
| 大并发 Submit TPS | 48,186-49,150/s | 46,497-51,409/s | 46k-51k/s |
| 旧 case Submit TPS | 17,471-53,366/s | 26,282-50,767/s | 17k-53k/s |
| L3 materialized TPS | 2,958-5,754/s | 1,247-3,856/s | 1.2k-5.8k/s |

核心判断：提交路径表现很好，当前主要瓶颈已经转移到异步 L3 proof materialization 和 Pebble proof artifact 写入。也就是说，系统可以很快返回 L2 accepted receipt，但若业务要求“proof 全量就绪吞吐”，瓶颈仍在 proofstore artifact 物化阶段。

![Submit 与 L3 物化吞吐对比](assets/perf-highwrite-submit-proof.png)

## 测试环境

| 项目 | 配置 |
| --- | --- |
| 机器数量 | 2 台 CVM，一台服务端，一台客户端 |
| 服务端 | 32 vCPU / 64 GiB，TencentOS Server 4 |
| 客户端 | 32 vCPU / 64 GiB，TencentOS Server 4 |
| 网络 | 同 VPC / 同子网，客户端通过内网 IP 访问服务端 |
| 服务端监听 | HTTP `10.206.0.9:8080`，gRPC `10.206.0.9:9090` |
| 客户端内网 IP | `10.206.0.4` |
| 数据盘 | `/mnt/datadisk0`，ext4，约 70 GiB |
| 运行目录 | `/mnt/datadisk0/trustdb-perf-semantic-20260430T071902Z` |
| 二进制 | 当前分支交叉编译 linux/amd64 |
| Go 版本 | `go1.26.2` |

本报告不记录服务器密码、私钥、客户端私钥或其它敏感凭据。

## 性能优先 Profile

| 配置项 | 值 | 语义影响 |
| --- | --- | --- |
| `wal.fsync_mode` | `batch` | unsafe 高吞吐模式；机器崩溃或掉电窗口内可能丢失已返回成功的记录 |
| `batch.proof_mode` | `async` | L2 提交返回与 L3 proof 物化解耦 |
| `proofstore.record_index_mode` | `time_only` | 只写基础索引与时间索引，减少写入放大；复杂查询可能更慢 |
| `proofstore.artifact_sync_mode` | `batch` | artifact 依赖 manifest + WAL 恢复补齐，减少逐 chunk sync 压力 |
| `global_log.enabled` | `false` | 关闭 L4 global log，最高 proof level 为 L3 |
| `anchor-sink` | `off` | 关闭 L5 anchor |
| `batch_queue_size` | `1,048,576` | 避免 10 万条瞬时提交下 batch queue full |
| `batch_max_records` | `8,192` | 减少 batch 数量和 proofstore 写入批次 |

这组配置适合高写入压测，不是默认生产安全 profile。`wal.fsync_mode=group` 可限制异步未刷盘窗口；若要求每条 accepted record 在确认前完成 WAL 文件 fsync，必须使用 `strict` 并重新按安全 profile 测试。端到端崩溃耐久性还取决于文件系统与存储设备保证。

## 测试口径

| 指标 | 含义 |
| --- | --- |
| Submit TPS | 只统计提交 signed claim 并返回 accepted receipt 的 L2 路径，不等待 proof。 |
| L3 materialized TPS | 每个 case 提交后继续等待 WAL checkpoint 增加满本 case 记录数，并确认队列深度归零，表示该 case 已完成 L3 proof 物化。 |
| Immediate 查询失败 | 提交后立即 `GetRecord` 的采样未命中，只表示异步可见性延迟，不等于提交失败。 |
| Post-proof 查询失败 | proof ready 后再次 `GetRecord` 的失败数，这是异步 proof 架构下更关键的正确性指标。 |
| Proof timeout | 等待目标 proof level，本轮目标为 L3。 |

## 100k 大并发 Matrix

每个 case 提交 100,000 条、payload 为 1 KiB。该组用于观察高并发下纯提交路径与全量 L3 物化之间的差距。

| 协议 | 并发 | 提交数 | Submit TPS | Submit p95 | L3 materialized TPS | Drain 秒 | 失败 | Batch 错误 | Proof timeout | Post-proof 查询失败 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| HTTP | 64 | 100,000 | 48,186/s | 5 ms | 3,880/s | 25.8 | 0 | 0 | 0 | 0 |
| HTTP | 128 | 100,000 | 49,150/s | 5 ms | 3,357/s | 29.8 | 0 | 0 | 0 | 0 |
| HTTP | 256 | 100,000 | 48,616/s | 10 ms | 3,459/s | 28.9 | 0 | 0 | 0 | 0 |
| gRPC | 64 | 100,000 | 46,497/s | 5 ms | 3,444/s | 29.0 | 0 | 0 | 0 | 0 |
| gRPC | 128 | 100,000 | 51,122/s | 5 ms | 2,723/s | 36.7 | 0 | 0 | 0 | 0 |
| gRPC | 256 | 100,000 | 51,409/s | 10 ms | 2,128/s | 47.0 | 0 | 0 | 0 | 0 |

## 旧 Payload Matrix 复测

`p1k-c32` 表示 payload 为 1 KiB、并发为 32。本组复用上一版报告里的 case 口径，但按新的性能优先 profile 重新测。

![旧 Payload Matrix 复测](assets/perf-highwrite-legacy-cases.png)

### HTTP

| Case | 提交数 | 并发 | Payload | Submit TPS | Submit p95 | L3 materialized TPS | 失败 | Batch 错误 | Proof timeout | Post-proof 查询失败 | Immediate 查询失败 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `p1k-c8` | 10,000 | 8 | 1 KiB | 17,471/s | 1 ms | 5,133/s | 0 | 0 | 0 | 0 | 0 |
| `p1k-c16` | 20,000 | 16 | 1 KiB | 28,584/s | 1 ms | 3,067/s | 0 | 0 | 0 | 0 | 0 |
| `p1k-c32` | 30,000 | 32 | 1 KiB | 41,568/s | 2 ms | 3,441/s | 0 | 0 | 0 | 0 | 0 |
| `p1k-c64` | 30,000 | 64 | 1 KiB | 44,506/s | 5 ms | 3,053/s | 0 | 0 | 0 | 0 | 0 |
| `p1k-c128` | 30,000 | 128 | 1 KiB | 53,366/s | 5 ms | 4,688/s | 0 | 0 | 0 | 0 | 0 |
| `p4k-c32` | 20,000 | 32 | 4 KiB | 39,895/s | 2 ms | 3,876/s | 0 | 0 | 0 | 0 | 0 |
| `p4k-c64` | 20,000 | 64 | 4 KiB | 46,475/s | 5 ms | 3,049/s | 0 | 0 | 0 | 0 | 0 |
| `p16k-c32` | 10,000 | 32 | 16 KiB | 39,589/s | 2 ms | 3,514/s | 0 | 0 | 0 | 0 | 0 |
| `p16k-c64` | 10,000 | 64 | 16 KiB | 46,792/s | 5 ms | 5,754/s | 0 | 0 | 0 | 0 | 0 |
| `p64k-c32` | 5,000 | 32 | 64 KiB | 36,323/s | 2 ms | 2,958/s | 0 | 0 | 0 | 0 | 1 |

### gRPC

| Case | 提交数 | 并发 | Payload | Submit TPS | Submit p95 | L3 materialized TPS | 失败 | Batch 错误 | Proof timeout | Post-proof 查询失败 | Immediate 查询失败 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `p1k-c16` | 10,000 | 16 | 1 KiB | 26,282/s | 1 ms | 3,255/s | 0 | 0 | 0 | 0 | 0 |
| `p1k-c32` | 20,000 | 32 | 1 KiB | 40,104/s | 2 ms | 3,856/s | 0 | 0 | 0 | 0 | 0 |
| `p1k-c64` | 20,000 | 64 | 1 KiB | 50,767/s | 2 ms | 3,639/s | 0 | 0 | 0 | 0 | 1 |
| `p4k-c32` | 10,000 | 32 | 4 KiB | 38,005/s | 2 ms | 3,500/s | 0 | 0 | 0 | 0 | 0 |
| `p16k-c32` | 5,000 | 32 | 16 KiB | 34,675/s | 2 ms | 1,247/s | 0 | 0 | 0 | 0 | 1 |

## 正确性与可见性

![复测正确性信号](assets/perf-highwrite-correctness.png)

本轮复测中，post-proof 查询失败为 0。这比 immediate 查询更重要，因为当前 profile 明确采用异步 L3 proof 物化。少量 immediate miss 出现在 HTTP `p64k-c32`、gRPC `p1k-c64`、gRPC `p16k-c32` 等 case 中，属于提交后立即读取时索引尚未完成的可见性窗口；等待 proof ready 后均可读取成功。

## 性能解读

这次结果可以概括为：写入入口已经足够快，proof artifact 物化是下一阶段重点。

- 如果看业务提交：HTTP/gRPC 在 64-256 并发下能稳定达到约 46k-51k/s，旧 case 中最高 Submit TPS 为 HTTP `p1k-c128` 的 53,366/s 和 gRPC `p1k-c64` 的 50,767/s。
- 如果看 proof 全量就绪：L3 materialized TPS 多数在 3k-5k/s，gRPC `p16k-c32` 降到 1,247/s，说明大 payload 和 proofstore 写入仍会压低物化吞吐。
- 如果看延迟：Submit p95 大多为 1-5 ms，100k 大并发 256 档到 10 ms，仍处于低毫秒级。
- 如果看稳定性：提交失败、batch 错误、proof timeout、post-proof 查询失败均为 0。之前标准 matrix 中出现的 batch queue full 已通过扩大 batch 队列后消除。

## 本轮代码修复

复测过程中发现并修复了一个真实稳定性问题：当 `global_log.enabled=false` 时，HTTP/gRPC 的 optional global-log service 可能以 typed nil interface 形式进入 handler/server，导致 L4/L5 探测路径 panic。修复后，关闭 L4/L5 时相关 HTTP 路由不注册，gRPC 返回明确的 failed precondition，而不是 panic。

修复提交：`f947823 fix: handle disabled global log services`。

## 验证状态

| 验证项 | 结果 |
| --- | --- |
| 服务端 `/healthz` | `{"ok":true}` |
| 服务端 panic/fatal/segfault 检查 | 未发现 |
| 最终 batch queue depth | 0 |
| 最终 ingest queue depth | 0 |
| 最终 WAL checkpoint | `1,451,000` |
| `go test -p 1 ./...` | 通过 |
| `go test -p 1 -tags=e2e ./cmd/trustdb` | 通过 |
| `git diff --check` | 通过 |

## 后续优化建议

1. 继续优化 `PutBatchArtifacts`：重点减少 ProofBundle CBOR/snappy 编码、record index 写入和 Pebble batch staging 的分配与写放大。
2. 做 proof materializer 并行化专项：当前 L2 提交吞吐远高于 L3 物化吞吐，需要让 materialization 能更充分利用 32 vCPU。
3. 对大 payload 单独建压测 profile：`p16k` / `p64k` 的 L3 materialized TPS 更容易暴露 artifact 路径瓶颈。
4. 分离 WAL 与 Pebble 数据盘：当前虽然使用了数据盘目录，但 WAL、Pebble WAL、SST、proof artifact 和 compaction 仍共享同一块盘；生产压测建议分盘或至少做 IO profile。
5. 默认安全 profile 需要单独复测：本报告是性能优先 unsafe profile，不代表 `wal.fsync_mode=group`、L4/L5 开启时的生产安全吞吐。

## 测试产物

```text
.localdeploy/perf-semantic-20260430T071902Z/reports/
.localdeploy/perf-semantic-20260430T071902Z/reports/drain-summary.json
.localdeploy/perf-semantic-20260430T071902Z/reports/legacy-drain-summary.json
```
