# TrustDB 中文文档中心

本目录面向使用者、集成开发者和生产运维人员，描述当前 `main` 分支的
V2/V5 实现。它不是 v1.0.0 发布包的兼容说明：v1.0.0 发布于 V2/V5
破坏性切换之前，仍使用旧对象代际；当前代码只接受 suite-bound V2
对象、proofstore schema v5 与 `.sproof v2`，不会读取、迁移或回退到旧格式。

## 按目标选择阅读路径

| 目标 | 先读 | 完成后继续 |
| --- | --- | --- |
| 先理解系统能解决什么 | [README 中文首页](../../README.zh-CN.md) | [功能与配置](FEATURES_AND_CONFIGURATION.md) |
| 从零生成和验证证据 | 官网[快速开始](https://www.trustdb.ryan-wong.cn/docs/quick-start) | 官网[Go SDK 教程](https://www.trustdb.ryan-wong.cn/docs/sdk) |
| 部署服务器 | [功能与配置](FEATURES_AND_CONFIGURATION.md) | [生产运维](OPERATIONS.md) |
| 设计备份与灾备 | [备份与恢复](BACKUP_AND_RECOVERY.md) | [生产运维](OPERATIONS.md) |
| 启用国密与 FISCO BCOS | [FISCO BCOS 中文指南](FISCO_BCOS.md) | [国密合规边界](../compliance/CHINA_COMPLIANCE_SCOPE_AND_CONTROL_MATRIX.zh-CN.md) |
| 接入 NATS / JetStream | [NATS 中文指南](../integrations/NATS_INGRESS.zh-CN.md) | [功能与配置](FEATURES_AND_CONFIGURATION.md#nats--jetstream-入口) |
| 配置 TLS/mTLS/TLCP | [功能与配置](FEATURES_AND_CONFIGURATION.md#传输安全与管理入口) | [TLCP 网关](../integrations/TLCP_GATEWAY.md) |
| 排查故障 | [生产运维](OPERATIONS.md#故障分流表) | 官网[故障排查](https://www.trustdb.ryan-wong.cn/docs/troubleshooting) |

## 当前能力分类

| 分类 | 已支持能力 | 开启与关闭入口 |
| --- | --- | --- |
| 证据生成 | `INTL_V1`、`CN_SM_V1`，L1–L5，`.sproof v2` | suite 由服务端 signer descriptor 固定；一个 namespace 不可切换 suite |
| 接入 | HTTP、可选 gRPC、可选 NATS JetStream、Go SDK、CLI、桌面客户端 | `server.listen`、`server.grpc_listen`、`nats.enabled` |
| 批次与证明 | inline、async、on-demand；Global Log 与 STH | `batch.proof_mode`；生产证据路径保持 `global_log.enabled=true` |
| 存储 | file、Pebble、TiKV；有界索引与同步策略 | `metastore`、`proofstore.*`；更换 backend 使用新目录/namespace |
| WAL | strict、group、batch，目录分段、checkpoint、裁剪 | `wal.fsync_mode`；生产通常用 group，逐条 fsync 契约用 strict |
| L5 锚定 | off、file、noop、OpenTimestamps、外部插件、FISCO BCOS | `anchor.sink`；关闭设为 `off`，已有结果仍保持不可变 |
| 私钥托管 | 软件 envelope（开发）、remote、PKCS#11、SDF | `crypto.signer_plugins.*` 与 descriptor/provider；生产不回退软件 key |
| 传输 | 本地明文限制、TLS/mTLS、TLCP 网关 | `server.transport.*`、`tlcp.*`、`--tlcp-gateway-profile` |
| 管理与观察 | `/healthz`、`/metrics`、只读 API、Admin Web、结构化日志 | `admin.enabled`、`log.*`；Admin Web 默认关闭 |
| 备份恢复 | `.tdbackup v4` create/verify/resumable restore（当前仅 `INTL_V1`） | `trustdb backup`; `CN_SM_V1` 在 backup/restore 入口明确失败 |

## 统一的功能操作方法

本目录对所有可选能力都使用同一套说明顺序：

1. **用途与边界**：该能力解决什么问题，不能被解释成什么。
2. **开启**：需要修改的配置键、启动参数和外部依赖。
3. **验证**：健康检查、指标、CLI 或离线证据如何确认能力真正生效。
4. **关闭或回退**：如何停止新写入而不删除历史证据和信任根。
5. **备份与运维**：哪些状态进入 `.tdbackup`，哪些必须单独保护。

不要通过删除 WAL、proofstore marker、checkpoint、provider journal、密钥或
`.sproof` 来“关闭”功能。关闭只改变后续行为；已经签发的证据和历史信任
材料必须继续保留，才能验证过去的记录。

## 上线前最小检查

```bash
trustdb version
trustdb config validate --config /etc/trustdb/production.yaml
trustdb config show --config /etc/trustdb/production.yaml
trustdb doctor --config /etc/trustdb/production.yaml
```

随后至少完成：

- 用真实 signer 与目标 suite 提交一条记录并等到目标证明等级；
- 导出 `.sproof v2`，停止服务并使用独立信任根离线验证；
- 验证原文篡改、错误公钥和错误 anchor trust config 都会失败；
- 优雅停止服务，创建并验证备份，恢复到全新目录；
- 记录所有持久路径、信任根、私钥 provider、备份和恢复责任人。

## 进一步参考

- [`.sproof v2` 格式](../../formats/SPROOF_V2.md)
- [分布式架构边界](../../formats/DISTRIBUTED_ARCHITECTURE.md)
- [Signer Plugin V1](../../formats/SIGNER_PLUGIN_V1.md)
- [FISCO BCOS 英文完整运维手册](../integrations/FISCO_BCOS_OPERATIONS.md)
- [贡献指南](../../CONTRIBUTING.md)
