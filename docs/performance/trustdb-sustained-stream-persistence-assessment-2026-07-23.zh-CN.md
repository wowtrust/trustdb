# TrustDB 双机多语义持续流与证据路径性能评估

评估日期：2026-07-23

代码版本：`f29addd64e5c77df2a51c7a337a2a6649e1dd70d`

本轮在两台独立 48 logical CPU 主机上测试当前主分支，覆盖瞬时 L2 接收、持续 L3、完整索引 L4、不同 WAL 边界、不同索引和 artifact 语义、HTTP/gRPC、文件哈希输入、coalesced file anchor、公共 OpenTimestamps，以及队列饱和后的阻塞式背压。

所有名称都直接描述配置语义，不把配置划分为部署等级。不同组合可以独立部署，区别在于主机故障窗口、索引范围、proof 就绪时点和最终交付到 L3/L4/L5 的证据层级。

## 结论摘要

- 当前主分支纳入最终口径的 case 累计完成 7,311,000 次提交，`failed=0`、`batch_errors=0`，共 192 个 proof/evidence 检查全部成功，无 timeout。
- 1 KiB、256 并发、on-demand proof 的 gRPC 瞬时 L2 曲线为：10k 记录 56.6k/s、50k 37.0k/s、100k 21.8k/s、500k 12.6k/s。HTTP 对应 10k 44.3k/s、50k 34.0k/s、500k 12.2k/s。
- `batch WAL + time_only index + artifact batch + async proof + L3` 的 500k 持续流：gRPC submit 7.70k/s、L3 5.47k/s；HTTP submit 6.84k/s、L3 5.23k/s。
- `group-10ms WAL + full index + chunk sync + async proof + L4` 的空库 500k：3 ingest workers gRPC L4 为 2,237/s；同配置 HTTP 为 2,206/s。2/4/8 workers 分别为 2,068/1,983/1,960 L4/s。
- 2 workers 的同一数据库从 500k 增长到 1M 后，L4 从 2,068/s 降到 1,648/s，peak compaction debt 从 2.14 GiB 增至 3.76 GiB。
- `strict WAL + full index + chunk sync + async proof + L4`：gRPC 667/s，HTTP 665/s；两种协议几乎一致，完成速度由逐条 WAL fsync 路径主导。
- `group-10ms WAL + no_storage_tokens index + artifact batch + async proof + L4`：300k gRPC 为 4,207 L4/s。它与 full/chunk 组合的索引范围和 artifact 同步边界不同，不能把差值解释成单一参数收益。
- 50k file-anchor case 在 5 秒固定窗口下生成 53 个 Global Log leaves，只发布 4 个 anchor results；最终 anchor TreeSize=53，8/8 evidence 精确绑定 covering STH。
- 1k 公共 OTS case 在 4.80 秒形成 covering anchor，8/8 evidence 完整。该时间包含 2 秒测试窗口和外部 calendar 响应，只对应本次网络观测。

## 配置语义索引

报告使用以下中性简称，表格中的完整参数才是判断依据：

| 简称 | WAL | Record index | Artifact | Proof | Global Log / Anchor |
| --- | --- | --- | --- | --- | --- |
| `BTO-L2` | `batch` | `time_only` | `batch` | `on_demand` | off |
| `BTA-L3` | `batch` | `time_only` | `batch` | `async` | L3 |
| `GFCI-L3` | `group` 10 ms | `full` | `chunk` | `inline` batch materialization | L3 |
| `GNA-L4` | `group` 10 ms | `no_storage_tokens` | `batch` | `async` | L4 |
| `GFCA-L4` | `group` 10 ms | `full` | `chunk` | `async` | L4 |
| `SFCA-L4` | `strict` | `full` | `chunk` | `async` | L4 |
| `GFCA-L5-file` | `group` 10 ms | `full` | `chunk` | `async` | L4 + file anchor |
| `GFCA-L5-OTS` | `group` 10 ms | `full` | `chunk` | `async` | L4 + OTS |

各参数的语义：

- `wal.fsync_mode=batch`：append 不逐条等待 fsync，依赖 WAL rotate 和 close 边界；主机异常退出或掉电时，最后同步边界后的 accepted records 可能需要按该故障模型处理。
- `wal.fsync_mode=group`：多个 append 合并 fsync，本轮间隔为 10 ms；它限制未同步时间窗口，同时减少逐条同步次数。
- `wal.fsync_mode=strict`：每个 accepted receipt 返回前等待该 WAL append 的 fsync。
- `record_index_mode=time_only`：保留 record ID 和时间索引。
- `record_index_mode=no_storage_tokens`：在 time-only 之上保留 batch、proof level、tenant、client 和 content hash 等索引，不写 storage token 索引。
- `record_index_mode=full`：写入全部记录索引，包括 storage URI / file name token。
- `artifact_sync_mode=batch`：artifact batch 使用非同步写，依靠 WAL、manifest 和恢复流程补齐。
- `artifact_sync_mode=chunk`：proof artifact 写批次使用同步写。
- `proof_mode=async`：accepted receipt 与 L3 materialization 解耦，后台 materializer 完成 proof。
- `proof_mode=inline`：proof 在 batch commit 内物化，不进入独立 materializer queue；accepted receipt 仍然可以早于 batch commit，因此 Submit TPS 与 L3 TPS仍需分开。
- `proof_mode=on_demand`：常态只保存批次索引，首次请求 proof 时再物化。

## 测试环境

| 项目 | 服务端 | 压测端 |
| --- | --- | --- |
| CPU | 48 logical CPUs，AMD EPYC 9K84，24 cores / SMT2 | 同规格 |
| 内存 | 192 GiB 标称，Linux 可见约 184 GiB | 同规格 |
| NUMA | 单 socket、单 NUMA node | 单 socket、单 NUMA node |
| OS | OpenCloudOS Server 9 | OpenCloudOS Server 9 |
| Kernel | `6.6.119-49.23.oc9.x86_64` | 同版本 |
| Go | 1.26.5 | 使用同一静态 linux/amd64 二进制 |
| Binary SHA-256 | `949270da54dce7ec5469b6b5052698db1dc70192a7a48cfb533a9bc393e8acbd` | 同一文件 |
| 网络 | 同 VPC 内网 | 同 VPC 内网 |

网络基线：

- 100 次 ping：平均 0.126 ms，最大 0.410 ms，丢包 0%。
- iperf3：单流、8 流、32 流和反向测试均约 16.44-16.50 Gbit/s。

服务端数据盘为独立 70 GiB ext4，挂载参数 `rw,noatime,nodiratime,stripe=64`，I/O scheduler 为 `none`。TrustDB WAL、Pebble WAL/SST 和 proof artifact 位于同一数据盘。

```text
vm.dirty_background_bytes = 134217728
vm.dirty_bytes = 1073741824
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
```

## 存储基线

同一 ext4 数据盘的两轮 fio：

| Case | Round A | Round B | 尾延迟 |
| --- | ---: | ---: | --- |
| 4 KiB random write | 28,350 IOPS | 50,091 IOPS | A p95/p99 7.90/20.05 ms；B 3.88/4.23 ms |
| 1 MiB sequential write | 351.51 MiB/s | 351.47 MiB/s | 吞吐稳定 |
| 4 KiB fdatasync | 1,463 IOPS | 1,202 IOPS | sync p95 1.04-1.16 ms，p99 1.43-1.60 ms |

顺序吞吐较稳定，随机写和同步写随云盘状态波动。full index、artifact 和 compaction 同盘运行，TrustDB 结果应结合该存储范围解释。

## 指标口径

| 指标 | 完成条件 |
| --- | --- |
| Submit TPS | 客户端收到 signed accepted receipt；不等待异步 batch/proof。 |
| L3 TPS | 本 case 的 records 全部 materialized，相关 queue 和 in-flight 清空。inline 模式以 batch records 全量完成为准。 |
| L4 TPS | L3 完成，且该 case 的 batch roots 全部进入 Global Log published 状态。 |
| L5 TPS | 最新成功 anchor 的 TreeSize 覆盖该 case 的最终 STH，并且抽样 evidence 返回精确匹配的 anchor result。 |
| Batch error | accepted receipt 中的异步 batch 错误，与 HTTP/gRPC transport failure 分开。 |

异步模式下 Submit、L3、L4、L5 是不同完成边界。只比较具有相同交付物的数字，才能得到有效结论。

## L2 瞬时吸收曲线

`BTO-L2` 使用 131,072 ingest queue、32 ingest workers、1,048,576 batch queue、32,768 records/batch、256 客户端并发。测试输入为 1 KiB 文件内容；SDK 在压测端计算哈希，只向 TrustDB 发送 signed claim。

| Transport | Records | Duration | Submit TPS | p50 / p95 / p99 | Errors |
| --- | ---: | ---: | ---: | ---: | ---: |
| gRPC | 10k | 0.177 s | 56,576 | 5 / 10 / 20 ms | 0 |
| gRPC | 50k | 1.352 s | 36,991 | 5 / 50 / 50 ms | 0 |
| gRPC | 100k | 4.592 s | 21,779 | 20 / 50 / 50 ms | 0 |
| gRPC | 500k | 39.581 s | 12,632 | 20 / 50 / 50 ms | 0 |
| HTTP | 10k | 0.225 s | 44,348 | 5 / 10 / 50 ms | 0 |
| HTTP | 50k | 1.472 s | 33,965 | 5 / 50 / 50 ms | 0 |
| HTTP | 500k | 40.919 s | 12,219 | 50 / 50 / 50 ms | 0 |

这条曲线说明“极限吞吐”必须带上 burst 大小：10k gRPC 的 56.6k/s 是 177 ms 的瞬时吸收；500k case 已让后台批次索引、WAL 和提交路径长时间并行，最终稳定到约 12.6k/s。

将 500k case 的 batch queue 从 1,048,576 降到 262,144 后，gRPC 仍为 12,729/s，HTTP 为 12,862/s。大缓冲没有提高长 case，说明此时限制不在 queue capacity，而在持续执行的 WAL、签名、索引和 batch 工作。

## 持续 L3：async proof

`BTA-L3` 使用 65,536 ingest queue、16 ingest workers、262,144 batch queue、8,192 records/batch、4 materializers、256 并发，输入 500k 条 1 KiB 文件 claim。

| Transport | Submit TPS | p50 / p95 / p99 | L3 TPS | Total drain | Batches |
| --- | ---: | ---: | ---: | ---: | ---: |
| gRPC | 7,702 | 10 / 100 / 1,000 ms | 5,473 | 91.35 s | 111 |
| HTTP | 6,840 | 10 / 100 / 1,000 ms | 5,231 | 95.59 s | 123 |

两种协议均 `failed=0`、`batch_errors=0`，每轮 proof samples 8/8。gRPC 在本轮 submit 高 12.6%，L3 高 4.6%；后台 proofstore 收口后差距明显小于前台提交差距。

## Inline batch materialization

`GFCI-L3` 使用 group-10ms、full index、chunk sync、1,024 records/batch、3 ingest workers。它不创建独立 materializer backlog，proof 在 batch commit 内完成。

| Transport | Records | Submit TPS | L3 TPS | Proof sample avg | Errors |
| --- | ---: | ---: | ---: | ---: | ---: |
| gRPC | 100k | 8,911 | 5,229 | 0.72 ms | 0 |
| HTTP | 100k | 9,042 | 5,264 | 0.57 ms | 0 |

Submit 仍早于 batch commit，所以 8.9-9.0k/s 不是 L3 完成速度；完整 L3 为约 5.23-5.26k/s。

## On-demand proof 首次访问

`BTO-L2` 的 100k gRPC case 在 submit 后抽样请求 8 个 L3 proof：

- Submit 21,779/s，100k 全部 accepted。
- record index 首次查询平均 0.344 ms。
- 8/8 proof 最终可用，无 timeout；proof wait 平均 1.827 s，最大 14.598 s。
- proof 完成后的 record query 平均 0.359 ms。

on-demand 把常态 materialization 成本移到首次 proof 请求；首次等待取决于目标 record 所属 batch 和当时后台工作，不应只看 p50。

## L4：完整索引、chunk sync 与 worker 数

`GFCA-L4` 固定使用 gRPC、500k、并发 64、1 KiB、group-10ms、full index、chunk sync、async proof、4 materializers、batch queue 65,536，只改变 ingest workers。

### 空数据库 r1

| Ingest workers | Submit TPS | p50 / p95 / p99 | L3 TPS | L4 TPS | Total drain | Batches |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 2 | 2,463 | 10 / 200 / 500 ms | 2,069 | 2,068 | 241.74 s | 537 |
| 3 | 2,760 | 10 / 200 / 500 ms | 2,239 | 2,237 | 223.49 s | 509 |
| 4 | 2,413 | 10 / 200 / 500 ms | 1,984 | 1,983 | 252.10 s | 509 |
| 8 | 2,352 | 5 / 200 / 1,000 ms | 1,961 | 1,960 | 255.11 s | 498 |

3 workers 的空库 L4 比 2 workers 高 8.2%，比 4 workers 高 12.8%，比 8 workers 高 14.1%。这是本轮单盘、full index、chunk sync 和 compaction 组合的观测点，不是 CPU 核数的静态映射。

相同 3 ingest / 4 materializer 配置的 HTTP 500k：Submit 2,666/s、L3 2,207/s、L4 2,206/s；比 gRPC 的 2,237 L4/s 低 1.4%。完整持久化路径成为主要限制后，传输协议差异很小。

### 同一数据库增长：累计 1M

| Ingest workers | Submit TPS | L3 TPS | L4 TPS | Total drain | Peak compaction debt |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 2 | 1,964 | 1,649 | 1,648 | 303.40 s | 3.76 GiB |

相对同一数据库的空库 r1，2 workers 的 L4 下降 20.3%，peak compaction debt 从 2.14 GiB 增至 3.76 GiB。数据库规模、SST 分层和 compaction 会改变同一配置的短时完成速度。

## L4：减少 storage token 索引与 artifact batch

`GNA-L4` 使用 group-10ms、`no_storage_tokens`、artifact batch、async proof、8 ingest / 3 materializer、8,192 records/batch。300k gRPC 结果：

| Submit TPS | L3 TPS | L4 TPS | p50 / p95 / p99 | Batches | Errors |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 4,317 | 4,222 | 4,207 | 10 / 100 / 1,000 ms | 101 | 0 |

该组合保留 record ID、time、batch、proof level、tenant、client 和 content hash 查询，不写 storage token 索引；artifact 写入也使用 batch 语义。它的 L4 高于 `GFCA-L4`，但同时改变了索引范围、artifact sync、batch size、worker 数和 case 长度，因此这里只报告完整组合的结果，不把 4,207 与 2,237 的差值归因于单一开关。

## L4：逐条 WAL fsync

`SFCA-L4` 使用 strict WAL、full index、chunk sync、async proof、4 ingest / 2 materializer、4,096 max records/batch、50k records。

| Transport | Submit TPS | L3 TPS | L4 TPS | p50 / p95 / p99 | Batches |
| --- | ---: | ---: | ---: | ---: | ---: |
| gRPC | 668 | 667 | 667 | 100 / 200 / 200 ms | 698 |
| HTTP | 666 | 665 | 665 | 100 / 200 / 200 ms | 699 |

两种协议仅相差 0.3%。本盘 fio 的 4 KiB fdatasync 基线为 1.2-1.46k IOPS，而 TrustDB 每条记录还包含 claim 验证、accepted receipt 签名、WAL 编码和并发协调，因此应用层结果低于裸 fdatasync IOPS。

## 文件大小参数的真实含义

`trustdb bench ingest --payload-bytes` 在压测端生成文件内容，SDK 计算 content hash 和 length，再提交 signed claim；TrustDB 服务端不接收或存储原始文件字节。因此这里测的是“客户端文件哈希 + 固定大小 claim + L3 路径”，不是服务端上传 16/64 KiB blob。

| Transport | File bytes / records | Submit TPS | L3 TPS | 输入哈希与提交折算 | 说明 |
| --- | --- | ---: | ---: | ---: | --- |
| gRPC | 16 KiB / 50k | 8,834 | 7,473 | 116.8 MiB/s | 6.69 s 短 case |
| HTTP | 16 KiB / 50k | 7,983 | 7,065 | 110.4 MiB/s | 7.08 s 短 case |
| gRPC | 64 KiB / 20k | 14,019 | 7,900 | 493.7 MiB/s | 2.53 s 短 case |
| HTTP | 64 KiB / 20k | 13,939 | 7,861 | 491.2 MiB/s | 2.54 s 短 case |
| gRPC | 16 KiB / 200k | 6,774 | 6,516 | 101.8 MiB/s | 30.69 s 较长 case |
| gRPC | 64 KiB / 100k | 7,371 | 7,103 | 443.9 MiB/s | 14.08 s 较长 case |

这些 case 的 count 和 concurrency 不完全相同，不能用于推导“文件越大 record/s 越高”。更可靠的结论是：文件内容只在客户端参与哈希，服务端容量应按 claim 数、索引和 proof 语义衡量；文件预处理能力则按压测端 MiB/s 单独衡量。

## L5：covering STH 与 anchor 合并

### File anchor

`GFCA-L5-file` 使用 50k gRPC、1,024 records/batch、5 秒固定非滑动 anchor window。该窗口为了缩短测试时间，算法与默认 5 分钟窗口相同，但时间结果不能替代默认窗口的等待时间。

| Submit TPS | L4 TPS | L5 covering TPS | Batch roots / STH leaves | Anchor results | Final binding |
| ---: | ---: | ---: | ---: | ---: | --- |
| 3,094 | 2,776 | 2,322 | 53 | 4 | anchor TreeSize 53 = final STH TreeSize 53 |

L4 在 18.01 秒完成，最终 covering anchor 在 21.53 秒完成。53 个 batch roots 只产生 4 次外部提交；窗口内新的 STH 单调提升 Pending target，没有为每个 STH 建立独立任务。8 个历史 record 的 GlobalEvidence 均返回针对 covering STH 的 inclusion proof 和同 TreeSize/root 的 anchor result，8 次 evidence 查询合计 82.4 ms。

### Public OpenTimestamps

`GFCA-L5-OTS` 使用 1k gRPC、单 batch、2 秒测试窗口、`min_accepted=1`：

| Submit TPS | L4 ready | L5 covering ready | Anchor results | Evidence |
| ---: | ---: | ---: | ---: | ---: |
| 18,939 | 0.405 s | 4.799 s | 1 | 8/8 |

该值包含测试窗口、DNS、TLS 和公共 calendar 响应。它说明当前版本能够形成并返回 OTS anchor evidence，不代表外部服务的固定延迟。

## 有界队列与阻塞式背压表现

当前实现用固定容量许可控制 batch queue。提交路径在队列达到容量时等待，worker 取走任务后释放许可；context 取消和 shutdown 会唤醒等待者。

- batch queue 多次达到精确上限 65,536；纳入该项统计的五轮 500k case 共 2,500,000 条，全部最终到达 L4，`failed=0`、`batch_errors=0`。
- peak accepted-to-materialized lag 约 67,718，包含 batch、ingest 和正在处理的工作。
- peak heap 约 520-554 MiB，peak RSS 约 619-696 MiB，队列饱和时内存仍保持有界。

## CPU、内存、数据盘与 compaction

`GFCA-L4` worker case 的代表性资源数据：

| Case | Avg / peak process CPU | Peak RSS | Avg / peak disk util | Peak write await | Peak compaction debt |
| --- | ---: | ---: | ---: | ---: | ---: |
| i2 r1 | 247% / 451% | 626 MiB | 58.47% / 96.60% | 16.14 ms | 2.14 GiB |
| i3 r1 | 319% / 607% | 620 MiB | 53.52% / 96.80% | 18.42 ms | 2.06 GiB |
| i2 r2 | 222% / 479% | 646 MiB | 61.73% / 96.60% | 16.92 ms | 3.76 GiB |
| i4 r1 | 250% / 641% | 619 MiB | 60.90% / 97.40% | 17.71 ms | 2.03 GiB |
| i8 r1 | 251% / 756% | 696 MiB | 63.76% / 95.20% | 15.47 ms | 2.06 GiB |

48 个 logical CPU 不等于 ingest worker 应接近 48：

1. ingest workers 只控制接收阶段，后续仍共享 WAL writer、Pebble、proof artifact 和 Global Log；
2. i8 把 CPU 峰值提高到 7.56 cores，但 L4 低于 i3；
3. 数据盘 util 频繁瞬时达到 95-98%，write await 达到 15-19 ms；
4. 数据库增长后 compaction debt 达 3.7 GiB，L4 同步下降。

`BTO-L2` 100k on-demand case 的服务端 CPU 约 3.6-4.1 cores，RSS 约 1.90 GiB；大 queue 本身会增加常驻内存。500k batch-WAL case 的 WAL append 累计约 40 µs/record，单 writer 串行路径与后台 batch 工作共同把长 burst 限制在约 12-13k/s。

## 结果解释

- **瞬时与持续必须分开。** 10k gRPC burst 为 56.6k/s，500k 为 12.6k/s；两者都准确，但描述不同时间尺度。
- **Submit 与证据完成必须分开。** async/on-demand 下，accepted receipt、L3、L4、L5 有独立完成时点。
- **配置名称应体现语义。** WAL、索引、artifact、proof 和 anchor 的组合决定交付物，不应压缩成单一等级词。
- **协议差异会随后端路径变化。** BTA-L3 中 gRPC 有可见优势；full/chunk L4 和 strict L4 中，HTTP/gRPC 几乎一致。
- **worker 数由共享阶段决定。** 本轮 GFCA-L4 的 3 ingest workers 高于 2/4/8，不能从 48 CPU 直接推导 worker 数。
- **数据库规模会改变结果。** i2 空库和累计 1M 的同配置 L4 相差 20.3%，应结合 compaction debt 观察。
- **文件字节不进入 TrustDB。** SDK 对文件做本地哈希，服务端存的是 signed claim、receipts、indexes 和 proof artifacts。
- **anchor 合并保持证明语义。** 后续 covering STH 直接为历史 leaf 生成 inclusion proof，并返回精确匹配该 STH 的 anchor result；不是用 `anchor.TreeSize >= proof.TreeSize` 放宽校验。

## 测试边界

- 单 TrustDB 服务端、单 Pebble 数据盘；未覆盖 TiKV 多节点。
- worker/backpressure 的 2 workers 延伸到同库 1M，其余纳入口径的 case 使用独立空目录；不是更大数据集的长期稳态。
- 10k/50k burst 很短，适合描述瞬时吸收，不适合描述长时间容量。
- 云盘 fio 两轮随机写差异较大，结果只对应本次实例与时间窗口。
- file anchor 使用 5 秒窗口、OTS 使用 2 秒窗口；默认 `anchor.max_delay=5m` 的端到端等待应加上默认固定窗口。
- 公共 OTS 依赖外部 DNS、TLS、calendar 和后续 Bitcoin attestation；本轮只测 calendar 接受后的 L5 evidence。
- `run_profile` 只用于记录测试标签，实际语义由逐项配置决定。

机器可读摘要见 [`results/2026-07-23-performance-summary.json`](results/2026-07-23-performance-summary.json)。
