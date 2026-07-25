# 生产部署与运维手册

本文给出当前 `main` 的生产运行方法。所有示例路径都应替换为部署自己的受控路径；
在变更前先阅读[功能与配置](FEATURES_AND_CONFIGURATION.md)和
[备份与恢复](BACKUP_AND_RECOVERY.md)。

## 1. 生产身份与目录规划

一个 TrustDB 写入流由 suite、NodeID、LogID、proofstore namespace 和 WAL identity
共同约束。以下变化必须建立新日志，不能原地复用旧目录：

- `INTL_V1` 与 `CN_SM_V1` 互换；
- NodeID 或 Global LogID 变化；
- proofstore namespace 被其他 writer 使用；
- 从 v1/schema v4 切到当前 V2/proofstore schema v5。

建议独立目录：

```text
/etc/trustdb/                 配置、公开证书、TrustConfig
/var/lib/trustdb/wal/         WAL
/var/lib/trustdb/proofs/      proofstore
/var/lib/trustdb/objects/     可选本地对象
/var/log/trustdb/             文件日志（若启用）
/var/backups/trustdb/         逻辑备份，生产应另有异地副本
```

运行用户只获得所需目录权限。私钥、PIN、token 和生产 endpoint 不进入源码库、
日志或 metric label。

## 2. 配置生成和上线门禁

```bash
trustdb config init --out /etc/trustdb/production.yaml
trustdb config validate --config /etc/trustdb/production.yaml
trustdb config show --config /etc/trustdb/production.yaml
trustdb doctor --config /etc/trustdb/production.yaml
```

`config show` 是去敏后的合并结果，适合审查，但不是 secret 备份。上线记录应保存：
版本、配置 digest、suite、公开 key descriptor、NodeID、LogID、backend/namespace、
anchor sink/TrustConfig digest、审批单和回退方案。

## 3. 启动、就绪和停止

### 启动

```bash
trustdb serve --config /etc/trustdb/production.yaml
```

服务进入流量前必须满足：

1. 日志没有 schema、suite、WAL namespace、key descriptor 或 transport 错误；
2. `GET /healthz` 成功；
3. `/metrics` 可采集，队列和错误计数处于预期初值；
4. 外部 signer/anchor 已完成身份和 quorum probe；
5. 提交 canary，达到目标 L3/L4/L5，并成功导出和离线验证 `.sproof v2`。

### 优雅停止

1. 从负载均衡移除实例，停止 NATS publisher 或等待 consumer drain；
2. 观察 ingest、batch、materializer 和 durable outbox 收敛；
3. 向进程发送正常终止信号并等待 `server.shutdown_timeout`；
4. 确认 Pebble 锁和监听端口释放；
5. 需要时创建并验证备份。

不要用删除 WAL、checkpoint、Pending/InFlight 或锁文件的方式强制“收口”。

## 4. 容量和性能基线

生产调优从安全基线开始，不从 `benchmark-extreme.yaml` 开始。至少记录：

- HTTP/gRPC/NATS 每入口吞吐、错误率和 p50/p95/p99；
- `server.queue_size`、worker 饱和度、NATS `MaxAckPending`；
- batch close 频率、records/batch、proof-ready 延迟、materializer queue；
- WAL 追加/fsync/segment/checkpoint，proofstore 写入与磁盘延迟；
- Global Log outbox、STH、anchor Pending/InFlight、quorum/retry/published；
- CPU、RSS、GC、文件句柄、磁盘容量/IOPS、网络和外部 provider 延迟。

48 核机器不等于应配置 48 个 ingest worker。worker 数受签名验签、batch 串行边界、
WAL/proofstore 同步、下游队列和外部 provider 限制共同约束。用固定数据集逐级增加
并发，出现 p99、上下文切换、锁等待或磁盘队列恶化时停止；保存完整配置和原始数据。

## 5. 日常检查

### 每日

- `/healthz`、进程重启次数、错误日志和证书剩余有效期；
- ingest/rejected、queue saturation、proof-ready、WAL/proofstore 错误；
- 最新 STH tree size 单调增加；anchor quorum 和 published 进度符合窗口预期；
- 磁盘、水位、备份任务和最近一次 `backup verify`。

### 每周

- 抽样导出 `.sproof v2` 并在另一台、断网环境验证；
- 使用错误原文件/公钥/TrustConfig 做负向验证；
- 核对 registry 生命周期事件、signer/provider 版本和访问审计；
- 检查 NATS DLQ、redelivery 和长期未完成的 durable outcome。

### 每月

- 恢复最新备份到全新目录并完成离线证据验收；
- 检查容量趋势、索引需求、WAL 裁剪和保留策略；
- 演练单 endpoint、单 BCOS validator、signer plugin、磁盘和网络故障；
- 复核 trust root、证书、BCOS checkpoint 和责任人。

## 6. 功能启停的变更方法

每项变更都按同一顺序执行：

1. 保存当前配置、digest、metrics 和可离线验证样本；
2. 在副本上 `config validate`、`config show`、`doctor`；
3. 若涉及存储、suite、WAL、Global Log、anchor 或密钥，先备份；
4. 摘流、优雅停止、修改一项配置并启动；
5. canary 正向/负向验证；
6. 观察一个完整 batch/anchor 窗口；
7. 失败时恢复旧配置和旧实例，不删除新产生的审计材料。

常见启停入口见[功能与配置](FEATURES_AND_CONFIGURATION.md)。尤其注意：

- 关闭 gRPC：清空 `server.grpc_listen`；HTTP 不受影响。
- 关闭 NATS：先 drain，再设 `nats.enabled=false`，保留 stream/result/DLQ。
- 关闭 L5：设 `anchor.sink=off`；历史 anchor result 仍不可变。
- 关闭 Admin Web：设 `admin.enabled=false`；不影响核心 API。
- Global Log 关闭后新记录最高只能停在 L2/L3，不应用作生产 L4/L5 路径。

## 7. 升级和回退

### 同一格式代际内

1. 阅读 changelog 和迁移说明；固定二进制/镜像 digest。
2. 备份并验证，记录 WAL checkpoint 和外部 provider 状态。
3. 在恢复副本运行新版本，完成历史查询和离线验证。
4. 滚动替换 reader；writer 仍遵守单 namespace 单写入者边界。
5. 升级后生成新证据，与升级前样本一起验证。

### v1/schema v4 到 V2/schema v5

当前主线是破坏性切换，不读取、迁移或回退旧对象。正确做法是保留旧版本和旧
LogID 作为历史验证环境，使用新密钥、新 LogID、新 proofstore namespace、新 WAL
建立 V2/V5 写入流。不得把 v1 对象重新编码为 v2 后声称密码学身份未变化。

回退只允许切回旧实例继续旧日志，不能让旧二进制打开已经写入 V2/V5 的目录。

## 8. 密钥、证书和 TrustConfig 轮换

- 业务 key 使用 registry 的 rotate/revoke/compromise 事件，保留历史 descriptor。
- TLS/mTLS 证书采用新文件和可审查 generation，先在隔离实例验证再切换。
- 外部 signer plugin 先验证公开 key/algorithm/suite binding，再切换 handle。
- FISCO BCOS validator/checkpoint 变化使用完整离线 `.sproof` 执行
  `trust-config advance`；必须提供当前 digest，禁止手改 canonical CBOR。
- 轮换完成后验证旧证据仍可按历史时点建立信任，新证据使用新材料。

## 9. 故障分流表

| 症状 | 先检查 | 安全处理 |
| --- | --- | --- |
| `connection refused` | 进程、监听地址、TLS 模式、端口和启动日志 | 修正启动/探针脚本；不要循环压测一个未监听端口。 |
| health 正常但证明停在 L2 | batch close、proof mode、materializer queue | 等待/恢复 durable job；不要删除 accepted record。 |
| 证明停在 L3 | `global_log.enabled`、outbox、LogID/suite marker | 修复 Global Log 发布；不要伪报 L4。 |
| L4 长期不升 L5 | anchor sink、Pending/InFlight、provider quorum/retry | 保留 scheduler/journal，按失败阶段恢复。 |
| Pebble lock | 是否有服务/备份/恢复进程 | 找到 owner 并优雅停止；不强删锁文件。 |
| WAL namespace mismatch | NodeID、LogID、suite、proofstore marker | 使用正确目录，或为新日志建立空 namespace。 |
| signer public key mismatch | descriptor、provider handle、证书/SM2 user ID | 停止写入，恢复正确 provider；禁止自动回退软件 key。 |
| FISCO endpoint disagreement | chain/group/genesis/checkpoint/code hash | 作为安全事件隔离，保留冲突响应，不继续发布。 |
| 备份可读但恢复不完整 | create/restore count、checkpoint、外部材料 | 保持目标隔离，重新验证配对材料。 |
| 磁盘接近满 | WAL、proofstore、日志、临时备份、测试缓存 | 先摘流；只按保留策略清理可再生数据，不删证明对象。 |

## 10. 事故证据包

事故期间收集去密后的：版本/commit、配置 digest、NodeID/LogID/suite、时间线、
关键 metrics、结构化日志、WAL/checkpoint 状态、scheduler generation、provider 阶段、
BCOS endpoint index/height/quorum、最近 BackupID 和独立验证结果。不要收集私钥、
PIN、token、客户原文件或带 credential 的 URL。

## 11. 上线验收清单

- [ ] 版本、镜像 digest、配置和 trust roots 已冻结并双人复核。
- [ ] file/Pebble/TiKV、WAL、Global Log、anchor 和 signer 边界与设计一致。
- [ ] TLS/mTLS/TLCP、Admin Web 和网络 ACL 已按需启停。
- [ ] 正向证据达到目标等级，篡改/错误 trust root 全部失败。
- [ ] `.tdbackup` 创建、验证、恢复及外部系统恢复已经演练。
- [ ] 告警覆盖 ingest、proof、WAL、存储、anchor、provider、容量和证书。
- [ ] RPO/RTO、值班、升级、回退和安全事件责任人明确。

