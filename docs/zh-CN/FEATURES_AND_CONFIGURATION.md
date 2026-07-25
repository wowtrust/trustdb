# 功能与配置：开启、验证、关闭和回退

本文是当前 `main` 分支的功能开关手册。所有配置先通过
`trustdb config validate`，再由 `trustdb config show` 查看合并后的实际值；
不要只看 YAML 中是否写了某个字段。

## 1. 配置生命周期

```bash
trustdb config init --out ./trustdb.yaml
trustdb config validate --config ./trustdb.yaml
trustdb config show --config ./trustdb.yaml
trustdb doctor --config ./trustdb.yaml
```

- `config init` 创建入门配置，不覆盖已有文件。
- `config validate` 校验模式、路径、duration、队列、transport、provider 和
  互斥关系，不启动服务。
- `config show` 输出去敏后的合并结果，适合变更审查；不要把输出当成可恢复
  私钥或完整 secret 备份。
- `doctor` 检查本地路径、权限和配置前置条件。

配置变更遵循：保存旧文件与 digest → 在副本执行 validate/doctor → 停止或
滚动替换服务 → 启动并观察 → 导出一份新证据离线验证。不要直接修改正在被
进程读取的私钥、registry 或 canonical TrustConfig。

## 2. 服务入口

### HTTP

- **开启**：设置 `server.listen`，或使用 `trustdb serve --listen`。
- **验证**：请求 `/healthz`、`/v2/records?limit=1` 和 `/metrics`。业务写入是
  deterministic CBOR，推荐使用 Go SDK/桌面客户端，不要手写 JSON claim。
- **关闭**：停止服务或把入口从负载均衡/网关摘除；没有单独“关闭 HTTP、保留
  同进程其他服务”的模式。
- **运维**：生产入口必须位于 TLS/mTLS、API gateway、防火墙或受控网络后。

### gRPC

- **开启**：设置 `server.grpc_listen` 或 `--grpc-listen` 为非空地址。
- **验证**：使用项目 SDK 的 gRPC transport 执行提交、查询和证明导出；协议
  使用项目定义的 deterministic CBOR codec。
- **关闭**：把 `server.grpc_listen` 设为空并重启。HTTP 行为不受影响。
- **备份**：gRPC 无独立持久状态；证据仍进入同一 WAL/proofstore。

## 3. NATS / JetStream 入口

- **用途**：把已签名 claim 从 broker 耐久汇聚到同一 submission service，提供
  有界背压、ack/redelivery、不可变结果流与 DLQ。
- **开启**：配置 `nats.enabled=true`、servers、stream、subject、durable、result
  subject 和认证材料。完整字段见 [NATS_INGRESS.zh-CN.md](../integrations/NATS_INGRESS.zh-CN.md)。
- **验证**：确认 stream/consumer 已创建；发布同一 message/idempotency key 后，
  result subject 返回稳定的 accepted/rejected 结果；重启后重复投递得到同一结果。
- **关闭**：先停止 publisher，等待 `MaxAckPending` 清空，再将 `nats.enabled=false`
  并重启。保留 JetStream stream、result 和 DLQ，直到审计/保留期结束。
- **备份**：`.tdbackup` 不备份 NATS stream；broker 与 TrustDB proofstore 必须按
  同一恢复点分别保护。

## 4. 批次和证明物化

`batch.max_records` 与 `batch.max_delay` 决定何时关闭批次；
`batch.proof_mode` 决定 L3 ProofBundle 的物化时机。

| 模式 | 开启 | 适用 | 关闭/切换注意 |
| --- | --- | --- | --- |
| `inline` | `batch.proof_mode=inline` | 查询后立即需要完整 L3，默认/最直接 | 切换只影响新批次；历史 bundle 不删除 |
| `async` | `batch.proof_mode=async`，配置 materializer workers/queue/poll | 降低提交关键路径延迟，同时后台生成完整证明 | 关闭前等待 durable prepared jobs 完成；重启可恢复 |
| `on_demand` | `batch.proof_mode=on_demand` | 极端 L2 吞吐或只为少量记录取证明 | 第一次查询会承担物化成本；不得把“尚未物化”误报为数据丢失 |

验证时同时观察提交延迟、proof-ready 延迟、materializer queue 和重启恢复。不要
使用 `benchmark-extreme.yaml` 作为生产配置：它明确牺牲掉电耐久与证明就绪时间。

## 5. Proofstore 与索引

### file

- **开启**：`metastore=file`，设置 `paths.proof_dir` 或 `--proof-dir`。
- **用途**：本地开发、测试和小规模诊断。
- **限制**：缺少 Pebble/TiKV 的完整原子投影与高吞吐保证；WAL 恢复更保守。
- **关闭/迁移**：停服后用逻辑备份导出，恢复到新 backend；不要复制一半目录。

### Pebble

- **开启**：`metastore=pebble` 与独立 `metastore_path`。
- **用途**：推荐的生产单节点 proofstore，支持原子 committed artifacts、幂等
  投影和 checkpoint/cropping 前置条件。
- **验证**：服务独占目录锁；重启后记录、STH、anchor scheduler 与索引一致。
- **关闭/迁移**：优雅停服，确认进程释放锁，创建 `.tdbackup`，恢复到新目录。

### TiKV

- **开启**：`metastore=tikv`，配置 PD endpoints、keyspace 和 namespace。
- **用途**：共享集群中的存算分离。
- **边界**：一个 namespace 只属于一个逻辑 `(node_id, log_id)` 流；当前不支持
  同 namespace active-active writer。只有显式绑定本机 WAL 身份时才启用对应
  checkpoint 跳过/裁剪。
- **关闭/迁移**：停止 writer，保留 namespace marker。当前 `trustdb backup`
  只直接打开 file/Pebble，TiKV 应使用集群级备份和经验证的导出流程。

### 索引和同步策略

- `proofstore.record_index_mode=full`：时间与 storage-token 索引完整。
- `no_storage_tokens`：关闭 StorageURI/FileName token 索引，降低写放大。
- `time_only`：只保留时间方向索引，适合明确不需要其他查询的场景。
- `proofstore.artifact_sync_mode=chunk`：按 chunk 建立耐久边界，生产默认。
- `batch`：减少同步次数、扩大掉电窗口，只用于明确接受该风险的性能场景。

关闭索引只影响后续写入与查询能力，不得删除 proof bundle、manifest、STH 或
anchor result。切换前必须用真实查询验证业务没有依赖被关闭的索引。

## 6. WAL 耐久模式

| 模式 | 回执语义 | 建议 |
| --- | --- | --- |
| `strict` | 每条 accepted record 的 WAL 文件完成 fsync 后才返回 | 对逐条崩溃耐久有明确契约时使用 |
| `group` | 在 `group_commit_interval` 内合并刷盘 | 生产默认，常用 10ms |
| `batch` | 主要在 segment 轮转或关闭时刷盘 | 基准或可丢弃环境，不用于强耐久声明 |

当前 `main` 使用 `wal.max_segment_bytes` 启用按大小分段，并用
`wal.keep_segments` 控制安全 checkpoint 推进后额外保留多少个旧 segment；
两者默认都是零。对应 serve flags 只用于显式临时覆盖，生产基线应写入 YAML。
切换模式只影响新追加；已有 WAL、checkpoint 与 namespace binding 必须保留。
关闭服务必须走优雅 shutdown，等待 writer、batch 和 checkpoint 收口。

## 7. Global Log 与 L4

- **开启**：生产证据路径使用 `global_log.enabled=true` 并固定 `global_log.log_id`。
- **验证**：记录从 L2/L3 升到 L4；可查询 Signed Tree Head、inclusion proof、
  consistency proof 和 history tile。
- **关闭**：只适合明确停在 L2/L3 的 benchmark/开发场景。关闭不会删除已发布
  STH，但新 batch root 不再获得 L4。
- **迁移**：LogID、NodeID、suite 或 storage namespace 变化都表示新日志，不可
  把旧目录改名后继续写。

## 8. L5 锚定

统一开关是 `anchor.sink`；`anchor.max_delay` 是固定、非滑动的 STH 合并窗口。

| sink | 开启条件 | 如何验证 | 如何关闭 |
| --- | --- | --- | --- |
| `off` | 无 | 最高 L4 | 已是关闭状态 |
| `noop` | 无外部依赖 | scheduler/result 管线可运行 | 改为 `off`；不要把 noop 解释成外部时间 |
| `file` | 设置 `anchor.path` | JSONL 中出现与 STH 精确匹配的 result | 改为 `off`，保留 JSONL |
| `ots` | calendars/min accepted/timeout；可选 upgrader | calendar 接受产生 L5；后续升级丰富 Bitcoin 证明 | 先停新提交，再设 `off`；保留 pending/complete results |
| `plugin` | command/args/start/rpc timeout | 子进程握手、发布、离线 verify 均通过 | 设 `off` 并保留插件版本与历史 verifier |
| `fisco-bcos` | native build、canonical TrustConfig、至少两 endpoint/read quorum | receipt inclusion、PBFT finality、exact binding 三阶段都通过 | 设 `off`；保留 TrustConfig、validator/checkpoint 与链证据 |

锚定调度按 `(NodeID, LogID, SinkName)` 持久化最多一个 Pending 和一个不可替换的
InFlight。关闭时不强制提交；重启会恢复窗口与过期任务。不要通过删除 scheduler
状态来取消可能已产生外部副作用的 InFlight。

## 9. 密码套件与 signer

- 服务端证据 suite 由服务端 signer descriptor 的 `crypto_suite` 固定。
- `INTL_V1` 使用当前国际算法 profile；`CN_SM_V1` 使用 suite-bound SM2/SM3
  证据与固定 SM2 user ID。
- 同一 proofstore/WAL/log namespace 不能切换 suite。切换必须使用新密钥、
  新 LogID、空 proofstore namespace 和新 WAL。
- 开发软件 key 使用 `sm4-envelope-v1`；Windows 软件 envelope 当前 fail closed，
  可丢弃评估才显式使用 `plaintext-dev-v1`。
- 生产使用 `remote`、`pkcs11` 或 `sdf` signer plugin；配置
  `crypto.signer_plugins.<provider>`，私钥不得回退到 core 进程。

关闭外部 signer 前必须先停止所有需要签名的新写入，保留公开 descriptor、
registry 事件和历史 provider 版本。删除 provider 不会让历史证据失效，但丢失
对应公开信任材料会让验证方无法建立信任。

## 10. 传输安全与管理入口

### TLS/mTLS

- `server.transport.mode=mtls`，配置 server cert/key、client CA 与可选 pin。
- `allow_local_plaintext` 仅允许明确的本机开发边界，不是公网降级开关。
- 证书轮换使用新文件/新 generation，先验证后切换；不在原文件上部分覆盖。

### TLCP 网关

TLCP 由受监管网关终止，TrustDB 使用严格 profile 与 active identity manifest
认证该网关。配置和轮换见 [TLCP_GATEWAY.md](../integrations/TLCP_GATEWAY.md)。
关闭时先从入口摘流，再移除 `--tlcp-gateway-profile`；保留历史证书和发布记录。

### Admin Web

- **开启**：先用 `trustdb admin policy bootstrap` 创建版本化三员分立策略，再设置
  `admin.enabled=true`、`policy_path`、session secret、构建后的 `web_dir` 与 HTTPS
  场景下的 secure cookie。
- **CLI**：生产设置 `admin.cli_enforce=true`；策略缺失、无权限或认证失败时，高权限
  命令在执行前拒绝。
- **验证**：按接口检查 `system.*`、`security.policy.*` 等权限；配置编辑仍经过 schema
  校验，且通用 YAML 接口禁止修改 `admin` 授权边界。
- **关闭**：`admin.enabled=false` 并重启；核心 HTTP/gRPC/SDK 不受影响。
- **身份扩展**：支持 mTLS SPKI 绑定，并提供 OIDC/MFA 的已验证宿主钩子；不会信任
  裸身份头，也不强制绑定某一家 IdP。

完整角色矩阵、会话失效、锁定、在线策略更新和离线紧急恢复见
[管理 RBAC 手册](ADMINISTRATIVE_RBAC.md)。

## 11. 日志、健康与指标

- `log.output`：stderr、file 或 both。
- `log.format`：json、console、text；生产建议 json。
- `log.async.enabled` 启用有界异步缓冲；`drop_on_full=false` 保留背压，设 true
  会在满载时丢日志，只适合明确接受诊断缺口的场景。
- `/healthz` 表示进程健康，不等于所有外部 anchor/provider 都达到完整语义。
- `/metrics` 应同时监控 ingest queue、batch/materializer、WAL、proofstore、Global
  Log、anchor quorum/retry/published、backup 与进程资源。

关闭 file logging 前先确认 stderr 被采集。不要把私钥、PIN、credential、完整
provider error、生产 endpoint 或客户内容写入日志/metric label。

## 12. 变更后的验证清单

每次开启、关闭或切换能力后至少执行：

1. `config validate`、`config show`、`doctor`；
2. 启动并确认 `/healthz` 与关键 metric；
3. 提交固定测试文件，等待预期 L2/L3/L4/L5；
4. 导出 `.sproof v2`，在服务停止或网络隔离后离线验证；
5. 用错误文件/错误 trust root 做负向测试；
6. 若涉及持久化、suite、backend、WAL 或 anchor，完成备份与恢复演练。
