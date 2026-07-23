# ADR-0002：TrustDB 密码敏捷格式版本与迁移边界

> 状态：Accepted
>
> 日期：2026-07-23
>
> 关联 Issue：[#442](https://github.com/wowtrust/trustdb/issues/442)
>
> 破坏性切换修订：[#529](https://github.com/wowtrust/trustdb/issues/529)
>
> 依赖：[`ADR-0001`](ADR-0001-CRYPTOGRAPHIC-SUITES.zh-CN.md)、[`ADR-0003`](ADR-0003-SM-CRYPTO-DEPENDENCIES-AND-VECTORS.zh-CN.md)
>
> 代码注册表：`internal/formatregistry`

## 1. 决策摘要

TrustDB 不在现有 v1 证据、WAL v1、proofstore v4、backup v4 或 `/v1` API 中追加 `crypto_suite` 字段。密码敏捷能力进入一组新的、彼此绑定的格式代际：

- model evidence v2；
- `.sproof v2`；
- `.tdbackup v5`；
- WAL v2；
- proofstore v5；
- HTTP `/v2`；
- gRPC `trustdb.v2.TrustDB`；
- SDK model v2。

这些目标格式当前全部是 `reserved`，不能用于生产写入。只有实现、golden vectors、断网验证、三种 proofstore 的崩溃恢复测试以及 API/SDK 互操作全部完成后，才可以单独把对应 descriptor 改成 `available`。

v2 格式显式携带大小写敏感的 `crypto_suite`，允许 `INTL_V1` 和 `CN_SM_V1`。允许 `INTL_V1` 使用 v2 的原因是让格式代际与算法套件正交：全新部署可以选择显式 `INTL_V1` 或 `CN_SM_V1`，但每个 LogID/namespace 只能选择一个 suite；这不允许把 v1 历史对象重新编码为 v2 并声称其密码学身份没有变化。

V2/V5 上线采用一次性破坏性切换：删除 v1 model、`.sproof v1`、WAL v1、proofstore v4、backup v4、HTTP/gRPC v1 和 SDK v1 的生产代码，只保留一套 V2/V5 实现。旧数据、旧备份和旧证据不迁移、不双读、不继续提供兼容 verifier；它们作为 unsupported input 明确失败。切换必须使用新的 `LogID` 和新的 storage namespace identity，部署方清空或替换旧数据目录后重新初始化。

禁止把破坏性升级实现成“尽力读取”：不能猜测格式、缺字段回退、同一 namespace 混写、原地补字段，不能重算历史 root/signature/STH/anchor result，也不能因为旧数据没有用户就静默接受。

## 2. 本 ADR 解决的问题

当前实现的确定性 CBOR 解码器会拒绝未知字段。这是正确的 fail-closed 行为，但也意味着不能把 `crypto_suite`、SM2 证书链或 BCOS finality material 塞入现有 v1 对象而不改变格式。

如果仅给个别对象增加字段，会产生不可验证的混合状态：

- claim 声明 `CN_SM_V1`，但 record ID 仍按 v1 SHA-256 framing 计算；
- Signed STH 使用 SM2，Global Log leaf 或 Merkle node 仍按 SHA-256；
- `.sproof` 外层声明一个 suite，内嵌 proof、STH 或 anchor 使用另一个 suite；
- WAL replay 在配置默认值变化后重新解释旧 payload；
- proofstore 依据 key 长度、digest 长度或字段是否存在猜测版本；
- backup restore 把旧对象写入新 namespace，随后由新二进制按新规则读取；
- HTTP、gRPC 与 SDK 各自增加字段，产生同名模型但不同签名输入。

因此 suite 与格式版本必须在证据、持久化和传输边界上同时明确，并在任何分歧处拒绝。项目当前没有生产用户或历史兼容义务，直接替换格式比维护长期兼容层更安全、更易审计。

## 3. 注册表状态和生产 gate

`internal/formatregistry` 是机器可读的设计注册表。每个 descriptor 固定：

- family、identifier 和整数版本；
- `available` 或 `reserved`；
- canonical encoding；
- 允许的 suite；
- suite 字段名；
- 未知字段、未知 suite 和未知 archive entry 的处理规则；
- 迁移策略；
- 适用的最大对象或消息大小。

V2 切换完成后的生产生成或启动路径必须同时通过：

```text
formatregistry.RequireAvailable(format)
formatregistry.RequireSuite(format, suite)
cryptosuite.RequireAvailable(suite)
```

仅仅能在注册表中查到 `ModelV2` 或 `CN_SM_V1` 不代表可用。当前实现阶段 `RequireWritable` 仍只允许现有格式与 `INTL_V1` 的组合；切换 PR 必须原子地将 V2/V5 改为 `available`、将 v1/v4 代码删除并更新所有调用方，不能发布半套代际。

注册表使用无 map 的 `trustdb.format-registry.v1` 确定性 CBOR snapshot；测试固定其 SHA-256。修改任何 identifier、suite 组合、限制或迁移规则都会显式打破 golden digest，要求评审者确认这是协议决策而不是无意漂移。

## 4. 格式代际矩阵

| Family | 当前格式 | 当前 suite 语义 | 目标格式 | 目标 suite 语义 | Canonical encoding | 迁移策略 |
| --- | --- | --- | --- | --- | --- | --- |
| Model evidence | `trustdb.model-generation.v1` | 隐式且仅为 `INTL_V1` | `trustdb.model-generation.v2` | 必填 `crypto_suite`；`INTL_V1` / `CN_SM_V1` | RFC 8949 Core Deterministic CBOR | 删除 v1，空 namespace 初始化 V2 |
| Single proof | `trustdb.sproof.v1` / format 1 | 隐式 `INTL_V1` | `trustdb.sproof.v2` / format 2 | 外层与全部内嵌对象 suite 精确相等 | RFC 8949 Core Deterministic CBOR | 删除 v1 reader/writer，仅接受 V2 |
| Logical backup | `trustdb.backup.v4` | payload 对象仍为 v1；#446 后 PAX control metadata 显式绑定 namespace suite | `trustdb.backup.v5` | manifest、entry 和目标 namespace suite 精确相等 | PAX tar；v5 manifest/entries 为确定性 CBOR | 删除 v4 restore，仅恢复 V5 到空 namespace |
| WAL | header version 1 / `trustdb.wal.v1` | payload 隐式 `INTL_V1` | header version 2 / `trustdb.wal.v2` | segment binding 与 payload suite 必须相等 | versioned WAL frame + deterministic CBOR payload | 删除旧 WAL 目录，初始化 V2 |
| Proofstore | `trustdb-proofstore-v4` | payload 对象仍为 v1；#446 后 namespace schema metadata 显式绑定 suite | `trustdb-proofstore-v5` | durable marker 绑定 suite、format、NodeID、LogID | backend keyspace + deterministic CBOR values | 删除旧 namespace，初始化 v5 |
| HTTP | `/v1` | v1 model | `/v2` | v2 model；不做 content negotiation 回退 | HTTP + `application/cbor` | `/v2` 直接替换 `/v1` |
| gRPC | `trustdb.v1.TrustDB` | v1 model | `trustdb.v2.TrustDB` | v2 model | gRPC + `trustdb-cbor` | v2 service 直接替换 v1 service |
| Go SDK | SDK model v1 | v1 client/server model | SDK model v2 | 构造时必须选择 suite | Go types + deterministic CBOR | v2 types/client 直接替换 v1 |

`identifier` 必须精确匹配。`trustdb.sproof`、`v2`、`CN_SM`、大小写不同的 suite 名、未知 minor 字段或由文件扩展名推断格式都不被接受。

#446 在全量 V2/V5 切换前先建立了后端通用的不可变 suite-marker 控制：当前 generation 4 的 string-only schema 不再被接受，空库改用结构化 marker，backup 和 migration 也必须校验 suite。这是防止配置漂移的前置安全控制，不代表 proofstore v5 或 model/API v2 已启用；最终切换仍必须按本 ADR 删除当前 V1/V4 生产实现并写入包含 NodeID、LogID 和 namespace identity 的 v5 binding。

### 4.1 切换前当前格式的处理规则

在 V2 完整实现并进入切换 PR 之前，当前格式不为国产化新增字段：

- v1 model、`.sproof v1`、WAL v1、HTTP/gRPC v1 和 SDK v1 继续表示 `INTL_V1`；proofstore v4 payload 对象仍是 v1，但 namespace 已由 #446 的 marker 单独绑定 suite。
- `.tdbackup v4` 保留 JSON manifest、确定性 CBOR payload entries、SHA-256 PAX digest 与 128 MiB entry limit；#446 额外要求每个 PAX entry 携带一致的 namespace suite，缺失该 control metadata 的 archive 明确失败。
- backup v4 当前会忽略 manifest 的未知 JSON 字段和未识别的普通 tar entry。注册表如实标记这一行为；v5 必须改为严格拒绝，不能把 v4 的宽松解析带入 v5。
- proofstore v4 内部已有的 legacy bundle decoding 属于冻结的 v4 行为；proofstore v5 不包含该 fallback。
- 切换 PR 删除上述 v1/v4 parser、writer、兼容分支、测试夹具和公开入口；后续版本遇到旧 schema/marker/magic 只返回 unsupported version，不尝试验证或迁移。

## 5. Model evidence v2 schema 清单

每个 v2 对象都必须在其确定性 CBOR map 中包含：

```text
schema_version: exact versioned identifier
crypto_suite: exact suite identifier
```

组合对象必须递归比较所有 suite，不允许只检查外层。目标 schema 如下：

| Artifact | 当前 schema | 目标 schema |
| --- | --- | --- |
| Client claim | `trustdb.claim.v1` | `trustdb.claim.v2` |
| Signed claim | `trustdb.signed-claim.v1` | `trustdb.signed-claim.v2` |
| Server record | `trustdb.server-record.v1` | `trustdb.server-record.v2` |
| Accepted receipt | `trustdb.accepted-receipt.v1` | `trustdb.accepted-receipt.v2` |
| Committed receipt | `trustdb.committed-receipt.v1` | `trustdb.committed-receipt.v2` |
| Proof bundle | `trustdb.proof-bundle.v1` | `trustdb.proof-bundle.v2` |
| Record index | `trustdb.record-index.v1` | `trustdb.record-index.v2` |
| Batch root | `trustdb.batch-root.v1` | `trustdb.batch-root.v2` |
| Batch manifest | `trustdb.batch-manifest.v1` | `trustdb.batch-manifest.v2` |
| Batch tree leaf | `trustdb.batch-tree-leaf.v1` | `trustdb.batch-tree-leaf.v2` |
| Batch tree node | `trustdb.batch-tree-node.v1` | `trustdb.batch-tree-node.v2` |
| Key event | `trustdb.key-event.v1` | `trustdb.key-event.v2` |
| Idempotency decision | `trustdb.idempotency-decision.v1` | `trustdb.idempotency-decision.v2` |
| Global Log leaf | `trustdb.global-log-leaf.v1` | `trustdb.global-log-leaf.v2` |
| Global Log node | `trustdb.global-log-node.v1` | `trustdb.global-log-node.v2` |
| Global Log state | `trustdb.global-log-state.v1` | `trustdb.global-log-state.v2` |
| Signed Tree Head | `trustdb.signed-tree-head.v1` | `trustdb.signed-tree-head.v2` |
| Global Log proof | `trustdb.global-log-proof.v1` | `trustdb.global-log-proof.v2` |
| Global Log tile | `trustdb.global-log-tile.v1` | `trustdb.global-log-tile.v2` |
| Global Log outbox | `trustdb.global-log-outbox.v1` | `trustdb.global-log-outbox.v2` |
| STH anchor result | `trustdb.sth-anchor-result.v1` | `trustdb.sth-anchor-result.v2` |
| STH anchor schedule | `trustdb.sth-anchor-schedule.v1` | `trustdb.sth-anchor-schedule.v2` |
| Latest anchor reference | `trustdb.sth-anchor-latest.v1` | `trustdb.sth-anchor-latest.v2` |
| Empty latest reference | `trustdb.sth-anchor-latest-empty.v1` | `trustdb.sth-anchor-latest-empty.v2` |
| L5 coverage checkpoint | `trustdb.l5-coverage-checkpoint.v1` | `trustdb.l5-coverage-checkpoint.v2` |
| Contiguous WAL checkpoint | `trustdb.wal-checkpoint.v2` | `trustdb.wal-checkpoint.v3` |

WAL checkpoint 使用 v3 是因为当前 v2 已用于“从 sequence 1 到 LastSequence 连续”的 durable 语义；不得覆盖该含义。

`record_id`、signature input、Merkle leaf/node、STH 和 anchor payload 的计算都以 v2 对象及其 suite 为输入。不能先生成 v1 字节，再在外层贴上 `crypto_suite`。

## 6. `.sproof v2` 与离线验证

`.sproof v2` 仍是推荐交换格式，必须完整内嵌：

- v2 ProofBundle；
- batch root 到所引用 Signed STH 的 inclusion path；
- 精确的 v2 Signed STH；
- 同 TreeSize、RootHash、NodeID、LogID、suite 的 anchor result；
- anchor 类型所需的不可变证据材料，例如 BCOS transaction/receipt proof、block header、PBFT quorum signatures 和成员变更链；
- 用于说明证书身份的 leaf/intermediate certificates 和签名时状态材料（如 Profile 要求）。

证据文件自带的 root certificate、BCOS genesis/checkpoint、validator set 或 server public key 不能自动成为 trust root。验证者必须从本地配置提供 trust roots；验证过程不得访问 TrustDB、CA、OCSP、CRL、BCOS RPC、DNS 或任何 provider/network fallback。

验证顺序固定为：

1. 在分配大对象前检查总大小和各 component limit。
2. 解析 exact schema 和 `crypto_suite`，拒绝未知字段、重复 map key、tag、indefinite length、NaN/Inf 和尾随数据。
3. 比较所有嵌套对象的 suite、NodeID、LogID、TreeSize 和 RootHash。
4. 使用 suite registry 复算 claim、record ID、receipt、Merkle、Global Log、STH 和 anchor payload。
5. 使用验证者本地 trust roots 验证签名、证书链及 BCOS finality。
6. 仅依据复算结果报告 L1–L5，不信任文件中的等级标签。

切换后的 CLI 只包含 v2 verifier。遇到 `.sproof v1` 或缺少 `crypto_suite` 的对象立即返回 unsupported version；禁止“先试 v2，失败后试 v1”，也不提供隐藏兼容参数。

## 7. WAL 与 proofstore v5

### 7.1 WAL v2

WAL v2 继续使用现有 magic family，但 header version 固定为 2。v2 reader 只接受 version 2；切换前的 v1 reader 已会拒绝 future version，切换后从代码中删除。WAL 目录首次初始化时必须持久化并校验：

```text
format = trustdb.wal.v2
crypto_suite
node_id
log_id
storage_namespace_id
```

每个 payload 必须是 model v2，payload suite 与目录 binding 不同即 data loss。CRC32C 仍只用于 frame corruption detection，不替代 suite 指定的密码完整性或 hash chain。

### 7.2 Proofstore v5

proofstore v5 marker 为 `trustdb-proofstore-v5`，并在同一 durable initialization boundary 保存 suite、format generation、NodeID 和 LogID。

- Local：临时文件写入、file fsync、atomic rename、directory fsync 完成后才能开放写入。
- Pebble：marker 与初始 metadata 使用一个 `Sync` batch。
- TiKV：marker 与初始 metadata 使用一个事务；只允许空 namespace 初始化，冲突后重新读取，任何不一致都停止启动。

v5 reader 只读 v5 key/value schema，不扫描或尝试 v4 key layout。derived index 可以从 v5 immutable objects 重建，但重建不能改变任何 canonical object bytes、root、signature、STH 或 anchor result。

## 8. `.tdbackup v5`

backup v5 使用 PAX tar 作为流式容器，manifest 与所有结构化 entries 使用确定性 CBOR。manifest 必须包含：

- exact `trustdb.backup.v5`；
- suite、format generation、NodeID、LogID 和 source namespace identity；
- entry ordinal、path、type、size、suite 和 suite 指定的 digest algorithm/value；
- backup lineage、创建时间和压缩方式；
- immutable evidence、Signed STH、anchor result、scheduler state、key reference 和 BCOS evidence 的计数；
- 不包含可导出的软件私钥、HSM/KMS secret 或证据文件自信任的 root。

restore 必须在写第一条数据前完成整个 manifest、entry digest、schema/suite 一致性和目标 namespace 检查。目标必须为空，或是同一次 restore 的同 backup ID checkpoint；不能恢复 v4 backup，也不能把 `INTL_V1` backup 恢复到 `CN_SM_V1` namespace。

不实现 v4-to-v5 offline migration tool。升级前如需保留开发环境材料，可以导出 v4 archive 供人工审计，但新版本不读取它。V2 环境从空 namespace 开始，业务测试数据按 v2 重新提交，产生全新的 record ID、batch、TreeSize、STH 和 anchor 历史。

## 9. HTTP、gRPC 与 SDK v2

HTTP v2 固定 `/v2` 路由前缀和 `application/cbor`。gRPC v2 固定 service name `trustdb.v2.TrustDB`、metadata `trustdb/v2/cbor` 和 v2 request/response types。SDK 直接升级为 v2 model/client。

切换版本不注册 `/v1` route、`trustdb.v1.TrustDB` service 或 v1 SDK client。遇到旧 endpoint 的结果是 404/UNIMPLEMENTED，而不是代理、转换或自动降级。Server、CLI、SDK、Desktop、Admin 和官网示例必须在同一个 release PR 系列中全部改到 v2，避免仓库内部继续生成旧请求。

## 10. 证书、BCOS 证据和传输限制

所有限制在解码和密码验证前执行。超限是确定性的 invalid argument/data loss，不允许截断、跳过或改为在线查询。

| 项目 | v2 上限 | 说明 |
| --- | ---: | --- |
| 单条证书 | 128 KiB | DER 原始字节；先检查长度再解析 ASN.1 |
| 单条证书链数量 | 16 | leaf + intermediates；trust root 由验证者本地提供 |
| 单条证书链总字节 | 1 MiB | 同时满足单证书和数量限制 |
| BCOS transaction/receipt Merkle proof | 4 MiB | 包括路径与必要编码，不含 finality aggregate |
| BCOS finality material | 8 MiB | block/header、quorum signatures、validator/member-change material |
| 单个 anchor evidence aggregate | 16 MiB | 所有 sink-specific payload 的总上限 |
| `.sproof v2` | 24 MiB | 包括 ProofBundle、Global proof、STH、anchor、证书和 BCOS material |
| HTTP/gRPC v2 message | 32 MiB | transport hard ceiling；endpoint 可设更低限制 |
| proofstore v5 单对象 | 64 MiB | 解压后的 canonical object 上限 |
| backup v5 单 entry | 128 MiB | archive entry 上限；整个流式 archive 不要求全量载入内存 |

现有 claim 1 MiB、claim batch 16 MiB/1000 items 等更低 endpoint 限制继续有效；32 MiB 不是允许任意请求达到该大小。

## 11. 破坏性切换、回滚与 mixed-version 规则

### 11.1 切换

1. 停止所有 v1 Server、worker、CLI/SDK writer 和 anchor publisher。
2. 可选导出 v4 archive 仅供人工审计；新版本不承诺读取或恢复它。
3. 删除或移走旧 WAL、proofstore、restore checkpoint、scheduler state 和本地客户端缓存。
4. 配置新的 LogID 和新的 storage namespace identity；路径只有在确认完全为空后才可复用。
5. 部署只含 `/v2`、`trustdb.v2.TrustDB`、SDK v2、WAL v2、proofstore v5 和 backup v5 的版本。
6. 初始化并 durable 写入 format/suite/NodeID/LogID markers，再接收第一条 v2 claim。
7. 重新提交所需的开发/测试业务数据，生成全新的证据历史。

### 11.2 回滚

- marker 尚未 durable：删除未发布的空初始化临时文件/事务后，可重新尝试。
- marker 已 durable、尚无 evidence：只能用相同 format/suite 配置重启，或删除整个确认为空的新 namespace 后重新初始化。
- 已写 v2 evidence：不支持回滚到 v1。只能修复/前滚 V2 版本，或明确销毁 V2 数据后从空环境重新部署。
- 二进制回滚不得带回 v1 parser、writer、endpoint 或 SDK；发布系统必须阻止旧制品连接 V2 数据目录。

### 11.3 Mixed version

- 不支持 mixed-version deployment 或滚动升级。
- 集群必须全停、替换数据边界、再全量启动 V2；健康检查必须暴露 format generation 和 suite，负载均衡器只能接入完全一致的节点。
- 同一 Global Log 内不能混合 suite 或 model generation。
- V2 runtime、CLI、SDK 和 verifier 遇到 v1 schema、endpoint、service、WAL、proofstore marker、backup 或 `.sproof` 必须失败。

## 12. 崩溃、恢复和降级测试矩阵

| Backend / phase | 故障注入 | 必须结果 |
| --- | --- | --- |
| Local，marker 写入前 | write/flush 失败 | namespace 不可见为 v5；无 evidence 可写 |
| Local，rename 后 directory fsync 前 | crash | 恢复时只能得到完整 marker 或明确未初始化；不能猜测 |
| Local，marker 后首对象前 | crash | 以相同 binding 重启；v1 binary 拒绝 |
| Local，首对象写入中 | partial file / journal replay | 原子对象恢复或 data loss；不能返回半对象 |
| Pebble，初始化 batch 前/中 | process kill / IO error | marker 与初始 metadata 全有或全无 |
| Pebble，schema mismatch | v4 DB 由 v5 binary 打开 | failed precondition，不做 key scan/migration |
| TiKV，初始化事务冲突 | concurrent initializer | 重读 binding；相同则继续，不同则失败 |
| TiKV，commit response 丢失 | ambiguous transaction result | 重读 exact marker，不重复创建不同 identity |
| TiKV，恢复到错误 prefix | v5 backup + non-empty/mismatched target | 写第一条 entry 前失败 |
| Backup，checkpoint crash | entry N durable、checkpoint 未更新 | 幂等重放 N；immutable equality 检查通过才继续 |
| Upgrade | v1 数据目录直接交给 v2 runtime | failed precondition |
| Downgrade | v5 数据目录交给 v1 runtime | unknown/future schema 失败，不修改目录 |
| Mixed API | v1 SDK 请求 v2 service 或反之 | 明确 version error/UNIMPLEMENTED，不自动转换 |

Local、Pebble 和 TiKV 必须共享同一套 conformance contract；backend 优化不能改变上述结果。

## 13. Golden vectors 和评审 gate

在切换 PR 合并前，现有 `INTL_V1` baseline 继续保护当前 main：

- `test/vectors/sproof-v1-l3.cbor` 与其 SHA-256；
- claim、receipt、record ID、Merkle、Global Log、STH、key event 的现有 reference tests；
- WAL v1、backup v4 与 proofstore v4 的现有恢复和拒绝测试。

切换 PR 用完整 V2 vectors 替换上述 v1 fixture 和测试，不保留兼容测试。代码历史和 release artifact 足以追踪开发阶段旧格式；生产发布不携带旧 parser。

本 ADR 新增机器注册表 canonical snapshot golden。后续把任何 reserved format 改为 available 前，必须加入：

- 每个 model v2 artifact 的 exact CBOR hex 与 digest；
- `INTL_V1` 和 `CN_SM_V1` 各一套 `.sproof v2` L1–L5 vectors；
- WAL v2 header/frame、proofstore v5 marker/value、backup v5 manifest/entry vectors；
- HTTP v2 和 gRPC v2 对同一 request/response 的 canonical bytes；
- SM2 签名 strict DER 正负向、SM3/RFC6962、证书链和 BCOS finality vectors；
- unknown schema、unknown field、unknown suite、mixed suite、oversize 和 trailing-data 负向 vectors；
- 完全断网验证测试，网络调用必须被测试环境主动拒绝。

Golden 变化不能通过直接更新 expected digest 处理。PR 必须说明协议变化、破坏性切换步骤、旧输入拒绝行为和 V2 证据为何可独立复算。

## 14. 后果

正向结果：

- 国产算法不会被塞入旧结构或依赖默认配置解释。
- v2 可以显式承载 `INTL_V1` 与 `CN_SM_V1`，但每条日志仍只绑定一个 suite。
- 不迁移、不重写旧开发证据，避免伪造密码学连续性。
- file、Pebble、TiKV、backup、HTTP、gRPC 和 SDK 使用同一套版本决策。
- 证书链和 BCOS finality 有统一的资源上限，离线验证不会退化为无界解析或在线补材料。

成本与限制：

- v1/v4 数据、备份和证据在切换后不可由当前版本读取，升级必须清空环境。
- 切换产生新的 LogID、record ID、STH 和 anchor 历史，不能伪装成原历史的算法替换。
- backup v5、proofstore v5 和 WAL v2 是 breaking boundary，不支持滚动升级或降级。
- 本 ADR 只固定格式和迁移策略；它不实现 SM2/SM3 provider、持久 suite marker、v2 API 或 BCOS sink。
