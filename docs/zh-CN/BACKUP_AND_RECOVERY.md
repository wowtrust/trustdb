# 备份、恢复与灾难恢复

本文描述当前 `main` 的 `.tdbackup v4`。它是 proofstore 的逻辑备份，不是整机
快照，也不是私钥托管系统的恢复包。恢复成功的标准不是“命令退出为 0”，而是：
目标存储能启动、历史证据可离线验证、不可变 anchor result 与备份前一致。

## 1. 先划清备份边界

`.tdbackup` 包含确定性 CBOR 形式的：

- batch manifest、ProofBundle 和 batch root；
- Global Log leaf、node、state、Signed Tree Head、history tile 和 durable outbox；
- 精确的 immutable `STHAnchorResult`；
- STH anchor scheduler 的 Pending、InFlight、generation、重试和 provider state。

它不包含：

- 客户端、服务端、registry 或 anchor publisher 私钥；
- signer plugin 的 credential、PIN、token、HSM/SDF 设备状态；
- SDF recovery bundle；
- TrustDB YAML、证书、TLCP manifest、FISCO BCOS TrustConfig；
- WAL、对象存储中的原文件、NATS stream/result/DLQ；
- TiKV 集群自身的物理备份和 PD 元数据。

因此完整恢复至少需要五组独立材料：proofstore 逻辑备份、配置及其 digest、公开
信任根、私钥 provider 恢复材料、外部系统备份。不得把 `.tdbackup` 单独宣传为
“TrustDB 全量灾备”。

## 2. 当前格式与密码套件

- schema 固定为 `trustdb.backup.v4`；每个 entry 都绑定同一 `crypto_suite`，并带
  ordinal、类型、大小和 SHA-256 完整性值。
- 当前只允许 `INTL_V1` 创建和恢复 backup v4。
- `CN_SM_V1` 会明确失败，不会降级为国际算法，也不会产生未加密的国密备份。
  SM4 加密、认证的 backup v5 由
  [#473](https://github.com/wowtrust/trustdb/issues/473) 跟踪。
- 当前读取器不提供旧格式迁移或回退。升级前应在旧版本完成导出、恢复演练，
  再按目标版本文档建立新数据代际。

## 3. 备份前检查

1. 记录 `trustdb version`、Git tag/commit、`crypto_suite`、NodeID、LogID、backend、
   proofstore 路径和配置 digest。
2. 对 Pebble 执行优雅停服，确认目录锁已经释放。不要直接复制一个仍在写入的
   Pebble 目录。
3. 对 file backend 停止写入，避免业务写入和备份枚举跨越不同恢复点。
4. 确认备份目标不在 proofstore/WAL 同一故障域，并有足够空间容纳临时文件和
   最终 archive。
5. 在变更记录里保存最近一份可离线验证的 `.sproof v2`、对应原文件和独立信任根，
   作为恢复后的验收样本。

## 4. 创建备份

### 4.1 Pebble

```bash
sudo systemctl stop trustdb

trustdb backup create \
  --metastore pebble \
  --metastore-path /var/lib/trustdb/proofs/pebble \
  --crypto-suite INTL_V1 \
  --compression gzip \
  --out /var/backups/trustdb/proofstore-$(date -u +%Y%m%dT%H%M%SZ).tdbackup
```

### 4.2 file backend

```bash
trustdb backup create \
  --metastore file \
  --proof-dir /var/lib/trustdb/proofs \
  --crypto-suite INTL_V1 \
  --compression gzip \
  --out /var/backups/trustdb/proofstore-$(date -u +%Y%m%dT%H%M%SZ).tdbackup
```

输出采用同目录临时文件加原子替换。成功后保留 JSON 报告，至少核对 suite、
BackupID、manifest/bundle/root/STH/anchor result/schedule 计数不是意外的零或下降。

## 5. 每次都要验证 archive

```bash
trustdb backup verify \
  --file /var/backups/trustdb/proofstore-20260725T020000Z.tdbackup

sha256sum /var/backups/trustdb/proofstore-20260725T020000Z.tdbackup \
  > /var/backups/trustdb/proofstore-20260725T020000Z.tdbackup.sha256
```

`backup verify` 检查 archive 可读性、entry 类型、suite 一致性、PAX metadata、
大小和摘要。外部 SHA-256 用于介质传输核对，不替代 archive 内部验证。验证失败的
文件不能进入保留集，也不能覆盖最后一份已验证备份。

## 6. 恢复到全新目标

恢复目标应为空目录或同一 BackupID 的中断恢复目标。不要对正在服务的生产目录
原地覆盖。

### 6.1 恢复到 Pebble

```bash
trustdb backup restore \
  --file /var/backups/trustdb/proofstore-20260725T020000Z.tdbackup \
  --metastore pebble \
  --metastore-path /var/lib/trustdb-restore/proofs/pebble \
  --crypto-suite INTL_V1 \
  --checkpoint /var/lib/trustdb-restore/restore-checkpoint.json \
  --resume
```

### 6.2 恢复到 file backend

```bash
trustdb backup restore \
  --file /var/backups/trustdb/proofstore-20260725T020000Z.tdbackup \
  --metastore file \
  --proof-dir /var/lib/trustdb-restore/proofs \
  --crypto-suite INTL_V1 \
  --checkpoint /var/lib/trustdb-restore/restore-checkpoint.json \
  --resume
```

`--resume` 默认启用。checkpoint 绑定 BackupID 和最后完成的 ordinal；恢复中断后
使用同一 archive、目标和 checkpoint 继续。不要让两个进程共享 checkpoint，也
不要删除未调查的 checkpoint 后直接重跑。

## 7. 恢复验收

按以下顺序验收，不要先切流量：

1. 使用恢复目录启动一个隔离实例，NodeID、LogID、suite 和 namespace 必须与
   被恢复的日志身份一致。
2. 请求 `/healthz` 和 `/metrics`，确认 proofstore 无 schema/suite/namespace 错误。
3. 查询备份前记录、STH 和 anchor result；对照 create 报告的对象计数。
4. 使用备份前样本导出或读取 `.sproof v2`，在服务关闭、网络断开的环境里验证。
5. 分别用错误原文件、错误服务端公钥和错误 FISCO BCOS TrustConfig 做负向测试。
6. 检查 Pending/InFlight scheduler 是否继续恢复，而不是重复替换可能已产生外部
   副作用的提交。
7. 验收通过后再修改服务配置和负载均衡；旧目录保持只读，直到回退窗口结束。

## 8. WAL、对象和外部系统怎么备份

| 状态 | 建议 |
| --- | --- |
| WAL | 独立保护；记录 namespace binding 与 checkpoint。逻辑备份不包含 WAL。恢复后不要把其他 LogID/suite 的 WAL 指向新 proofstore。 |
| 原文件/对象 | 使用业务对象存储的版本化、保留锁与灾备。TrustDB 证明通常只绑定摘要和选定元数据。 |
| NATS JetStream | 独立备份 stream、consumer、result 和 DLQ；恢复点与 TrustDB proofstore 对齐。 |
| FISCO BCOS | 保护节点数据、证书、部署记录和 canonical TrustConfig；链上数据不进入 `.tdbackup`。 |
| 软件私钥 | 开发环境单独保护 key envelope 与 KEK；不要把私钥放进 proofstore archive。 |
| remote/PKCS#11/SDF | 按 provider 的 key ceremony、HA 和恢复流程保护；保留公开 descriptor 与 provider 版本。 |
| 配置和证书 | 在受控配置库保存去密配置、digest、证书链、TrustConfig 和变更记录；secret 使用专用 secret 管理。 |

## 9. TiKV

`trustdb backup` 当前只直接打开 file 和 Pebble。TiKV 应使用经过验证的集群级
备份，并保留 PD endpoints、keyspace、namespace marker、LogID、suite 和本地
WAL identity binding。恢复演练必须在隔离 keyspace/namespace 完成；不能把
Air/Pebble 的恢复结论自动套用到 TiKV。

## 10. 保留策略和演练

- 每次发布、密钥/证书轮换、TrustConfig advance、backend 变更前后创建备份。
- 日常至少保留最近完整备份、跨日/周/月恢复点和一份异地不可变副本。
- 保留周期要覆盖最慢验证方推进 checkpoint 的周期；否则历史验证方可能失去所需
  trust material。
- 每月至少执行一次恢复到全新目录；每季度做一次包含 proofstore、provider、链、
  NATS 和对象存储的联合灾备演练。
- 演练报告记录 RPO、RTO、BackupID、版本、suite、对象计数、离线验证结果、失败
  注入和责任人。

## 11. 常见错误

| 症状 | 原因与处理 |
| --- | --- |
| Pebble lock 被占用 | 服务仍在运行或有另一个备份进程；停止并确认 owner，不要强删锁文件。 |
| `CN_SM_V1` backup 被拒绝 | 当前 backup v4 的预期 fail-closed 行为；不要改标成 `INTL_V1`。 |
| restore suite mismatch | archive 与目标 namespace suite 不同；建立正确 suite 的全新目标。 |
| checkpoint BackupID mismatch | 混用了 archive/checkpoint；恢复正确配对，保留现场调查。 |
| 恢复后 anchor 重试 | scheduler 被完整恢复；先检查是否已有 immutable result 和外部交易，再决定是否继续。 |
| archive 可验证但业务不能恢复 | 缺少配置、密钥 provider、WAL/对象/NATS/BCOS 材料；按本文第 1、8 节补齐。 |
