# ADR-0001：TrustDB 密码套件标识与算法注册表

> 状态：Accepted
>
> 日期：2026-07-23
>
> 关联 Issue：[#441](https://github.com/wowtrust/trustdb/issues/441)
>
> 代码注册表：`internal/cryptosuite`

## 1. 决策摘要

TrustDB 使用不可变、大小写敏感、不得使用别名的密码套件标识：

- `INTL_V1`：当前实现，固定 SHA-256、Ed25519、RFC6962-SHA256 和确定性 CBOR。
- `CN_SM_V1`：国产密码套件，固定 SM3、SM2-SM3、RFC6962-SM3、确定性 CBOR 和固定 SM2 user ID；在完成依赖、向量、格式与跨组件实现前状态为 `reserved`，生产启动和证据生成必须拒绝。

套件不是可在同一条日志中热切换的算法选项。每个非空 Global Log、WAL/proofstore namespace、key registry 和 backup lineage 只能绑定一个 suite。切换 suite 必须同时创建新的 `LogID` 和新的存储 namespace，旧日志保持只读可验证；禁止在原 namespace 内重算或覆盖历史对象。

本 ADR 固定标识、算法参数和组合边界，不给现有 v1 对象增加字段，也不启用 SM2/SM3。格式版本化由 #442 完成，国密依赖与一致性向量由 [`ADR-0003`](ADR-0003-SM-CRYPTO-DEPENDENCIES-AND-VECTORS.zh-CN.md) 固定，provider 抽象与算法实现由后续 issue 完成。

## 2. 为什么必须是 suite，而不是独立算法开关

TrustDB 的密码语义跨越内容摘要、record ID、客户端签名、服务端 receipt、batch Merkle tree、Global Log、Signed Tree Head、key registry、anchor、备份和离线验证。只替换其中一个 `hash_alg` 或根据 32 字节长度猜测算法，会产生以下不可接受状态：

- 同一个 digest 无法判断是 SHA-256 还是 SM3；
- batch leaf 与 node 使用不同算法，仍可能在长度检查中通过；
- STH 声明一种 tree algorithm，但签名、anchor 或 proof 按另一种算法验证；
- 同一 `LogID` 在不同时间代表不同密码学规则；
- 恢复或离线验证根据本机默认值解释历史数据；
- SDK、Server、Desktop 和 verifier 对同一字节串使用不同 SM2 user ID 或签名编码。

因此 suite 是一组不可拆分的协议参数。对象只能显式属于一个 suite，不能从 key 长度、digest 长度、证书 OID、文件扩展名或当前配置推断。

## 3. 注册表状态与启用规则

| Suite ID | 注册表状态 | 可生成新证据 | 可作为配置启动 | 说明 |
| --- | --- | --- | --- | --- |
| `INTL_V1` | `available` | 是 | 是 | 当前 v1 行为，必须字节级兼容 |
| `CN_SM_V1` | `reserved` | 否 | 否 | 参数、依赖与向量已固定，等待 #445–#460 完成 |

`reserved` 不是“尽力而为”。任何生成路径调用 `RequireAvailable(CN_SM_V1)` 都必须失败。读取器将来可以在具备完整实现后识别该标识，但不得把未知或未实现 suite 回退为 `INTL_V1`。

新增 suite 必须使用新的完整标识，例如 `CN_SM_V2`，并同时提供 ADR、格式版本、向量、迁移边界和离线验证支持。注册表不接受 `intl_v1`、`CN-SM-V1`、`sm2`、空字符串等别名。

## 4. `INTL_V1` 规范

`INTL_V1` 是对当前实现的命名，不改变任何现有字节。它的规范参数如下：

| 参数 | 固定值 |
| --- | --- |
| Suite ID | `INTL_V1` |
| 内容摘要 | SHA-256，32 字节 |
| Claim canonical bytes 摘要 | SHA-256，32 字节 |
| Client signature bytes 摘要 | SHA-256，32 字节 |
| Record ID 摘要 | SHA-256，32 字节；现有 `tr1` 编码保持不变 |
| Key event / key fingerprint | SHA-256，32 字节 |
| WAL/backup 版本化完整性摘要 | SHA-256，32 字节；CRC32C frame checksum 不属于密码证明 |
| 签名 | Ed25519 |
| 签名编码 | RFC 8032 64-byte raw signature |
| 公钥编码 | RFC 8032 32-byte raw public key |
| 私钥编码 | 当前 TrustDB 64-byte Ed25519 private key 表示 |
| 证书 Profile | 使用证书时为 RFC 8410 X.509 Ed25519；当前 raw-key 流程不要求证书 |
| Canonical encoding | RFC 8949 Core Deterministic CBOR |
| Merkle | `rfc6962-sha256`，leaf prefix `0x00`，node prefix `0x01` |
| Anchor digest | STH 的 32-byte SHA-256 root；sink 不得静默转换 |
| SM2 user ID | 不适用，必须为空 |

### 4.1 `INTL_V1` domain registry

| 用途 | Domain |
| --- | --- |
| Client claim signature | `trustdb.client-claim.v1` |
| Record ID | `trustdb.record-id.v1` |
| Accepted receipt signature | `trustdb.accepted-receipt.v1` |
| Committed receipt signature | `trustdb.committed-receipt.v1` |
| Key event signature | `trustdb.key-event.v1` |
| Key event hash | `trustdb.key-event-hash.v1` |
| Global Log leaf hash | `trustdb.global-log-leaf.v1` |
| STH signature | `trustdb.signed-tree-head.v1` |
| Idempotency storage key | `trustdb.idempotency-storage-key.v1` |

现有签名输入继续使用：

```text
ASCII(domain) || 0x00 || deterministic-CBOR(payload)
```

现有 record ID、Global Log leaf、file/OTS anchor ID 的历史 framing 保持原样。不能为了“统一接口”给 `INTL_V1` 增加 suite 字节、长度字段或新 domain；任何此类变化都必须属于新格式或新 suite。

### 4.2 `INTL_V1` Merkle 规则

- Batch leaf：`SHA256(0x00 || deterministic-CBOR(ServerRecord v1))`。
- Global Log leaf：`SHA256(0x00 || ASCII("trustdb.global-log-leaf.v1") || 0x00 || deterministic-CBOR(GlobalLogLeaf v1 without derived fields))`。
- Internal node：`SHA256(0x01 || left[32] || right[32])`。
- Audit path 中每个 digest 必须正好 32 字节，不能仅凭 32 字节长度接受其他算法。

## 5. `CN_SM_V1` 规范

| 参数 | 固定值 |
| --- | --- |
| Suite ID | `CN_SM_V1` |
| 内容摘要 | SM3，32 字节 |
| Claim canonical bytes 摘要 | SM3，32 字节 |
| Client signature bytes 摘要 | SM3，32 字节 |
| Record ID 摘要 | SM3，32 字节；外部字符串前缀和格式由 #442 固定 |
| Key event / key fingerprint | SM3，32 字节 |
| WAL/backup 版本化完整性摘要 | SM3，32 字节；具体格式由 #442/#473 固定 |
| 签名 | SM2 signature over SM3/ZA |
| 签名编码 | 严格 ASN.1 DER `SEQUENCE(INTEGER r, INTEGER s)`；拒绝非最短、负数、零、越界、尾随字节和 raw `r||s` |
| 公钥编码 | 65-byte SEC1 uncompressed point：`0x04 || X[32] || Y[32]`，曲线 SM2 P-256 |
| 私钥编码 | 32-byte big-endian scalar；生产 key handle 不要求导出该字节 |
| 证书 Profile | X.509 SM2/SM3，遵循 GB/T 35276；证书链与本地 trust roots 由验证配置提供 |
| SM2 user ID | 精确 16-byte ASCII `1234567812345678`；不得由 SDK、租户或请求覆盖 |
| Canonical encoding | RFC 8949 Core Deterministic CBOR |
| Merkle | `rfc6962-sm3`，leaf prefix `0x00`，node prefix `0x01` |
| Anchor digest | STH 的 32-byte SM3 root，并与 `CN_SM_V1`、TreeSize、NodeID、LogID 一起进入版本化 anchor payload |

### 5.1 `CN_SM_V1` domain registry

| 用途 | Domain |
| --- | --- |
| Client claim signature | `trustdb.client-claim.v2` |
| Record ID | `trustdb.record-id.v2` |
| Accepted receipt signature | `trustdb.accepted-receipt.v2` |
| Committed receipt signature | `trustdb.committed-receipt.v2` |
| Key event signature | `trustdb.key-event.v2` |
| Key event hash | `trustdb.key-event-hash.v2` |
| Global Log leaf hash | `trustdb.global-log-leaf.v2` |
| STH signature | `trustdb.signed-tree-head.v2` |
| Idempotency storage key | `trustdb.idempotency-storage-key.v2` |

签名输入固定为：

```text
ASCII(domain) || 0x00 || ASCII("CN_SM_V1") || 0x00 || deterministic-CBOR(payload)
```

SM2 的 ZA 计算使用同一个固定 user ID 和签名公钥。应用 domain/suite framing 后的完整字节串作为 SM2 message；库或 HSM provider 不得再次拼接业务 domain，也不得使用调用方自定义 user ID。

Record ID 的可变长度 DER 签名不能沿用 v1 的无长度拼接。#442 必须把 suite、canonical claim bytes、signature algorithm 和 signature bytes 放入一个确定性 CBOR framing 后再计算 SM3，禁止 `claim || signature` 的歧义拼接。

### 5.2 `CN_SM_V1` Merkle 与 Anchor 规则

- Batch leaf：`SM3(0x00 || deterministic-CBOR(ServerRecord v2))`；v2 对象必须显式携带 `CN_SM_V1`。
- Global Log leaf：`SM3(0x00 || ASCII("trustdb.global-log-leaf.v2") || 0x00 || deterministic-CBOR(GlobalLogLeaf v2))`。
- Internal node：`SM3(0x01 || left[32] || right[32])`。
- STH 必须声明 `CN_SM_V1` 和 `rfc6962-sm3`，并由 `sm2-sm3` key 签名。
- Anchor provider 必须声明接收 SM3 digest。仅支持 SHA-256 的 provider（包括当前 OTS 路径）不能把 SM3 root 当作 SHA-256 digest，也不能隐式再哈希后仍声称锚定原 STH。
- FISCO BCOS payload 将由 #462 固定；其必须显式包含 suite、digest algorithm、NodeID、LogID、TreeSize 和 RootHash。

## 6. Namespace 与 LogID 不变量

每个可写运行实例最终必须持久化以下绑定：

```text
suite_id + node_id + log_id + storage_namespace + format_generation
```

规则：

1. 空 namespace 第一次初始化时写入 suite marker，marker durable 后才能接受第一条 WAL/claim。
2. 非空 namespace 没有 suite marker 时 fail closed；不能因为当前默认值是 `INTL_V1` 就补写。
3. 已绑定 suite 的非空 namespace 不允许原地改为另一 suite。
4. 从 `INTL_V1` 切换到 `CN_SM_V1` 必须使用新的 `LogID` 和新的 file/Pebble/TiKV namespace；两者缺一都拒绝。
5. 旧 namespace 可以只读挂载、导出和离线验证，但不能在新 suite 下追加。
6. 备份恢复必须恢复原 suite 绑定；恢复到不同 suite 的 namespace 等同于导入失败，不做算法迁移。
7. 多节点部署中，参与同一逻辑日志的所有节点必须使用相同 suite marker；配置分歧在写入前失败。

`internal/cryptosuite.ValidateNamespaceTransition` 提供上述切换规则的公共校验。file/Pebble/TiKV 的持久 marker、并发初始化、backup/restore 与 metastore migration 约束已由 #446 和 [`ADR-0005`](ADR-0005-IMMUTABLE-PROOFSTORE-SUITE-MARKERS.zh-CN.md) 实现。

## 7. 混用时的 fail-closed 行为

| 组合边界 | 必须比较 | 拒绝条件 |
| --- | --- | --- |
| Claim → validation | claim suite、content hash、client key | 缺失、未知、算法不属于 suite、key suite 不同 |
| Accepted/Committed receipt | record、server key、receipt suite | 任一 suite 不一致 |
| Batch | 全部 records、batch manifest、Merkle profile | 一个 batch 出现多个 suite 或 tree algorithm 不匹配 |
| Global append | BatchRoot、Global Log marker、STH signer | suite、LogID、digest 或 signer 不一致 |
| Proof | bundle、Merkle path、STH、anchor | suite 不一致、未知 tree/signature/hash ID、缺失 marker |
| Key registry | key event、public key、registry signer | key algorithm/profile 与 registry suite 不一致 |
| Backup/restore | manifest、entries、目标 namespace | suite 缺失、混合、目标 namespace 已绑定其他 suite |
| SDK/Desktop | identity、claim、server trust config | 不支持该 suite，或 user ID/encoding 与 registry 不同 |

`internal/cryptosuite.RequireSame` 是格式和组合边界的基础拒绝函数。调用方不能捕获该错误后回退到默认 suite。

## 8. 组件实施顺序

| 后续 Issue | 使用本 ADR 的方式 |
| --- | --- |
| #442 | 给 evidence、WAL、proofstore、backup、HTTP/gRPC 增加显式 suite/format 边界 |
| #443 | 选择 SM2/SM3 依赖并用独立实现、官方/交叉向量验证本 ADR 参数 |
| #445 | 将 hash/sign/verify/key handle 放到 provider-neutral interface 后面 |
| #446 | 在 Local、Pebble、TiKV 持久化不可变 suite marker |
| #447 | 实现 SM3 与 RFC6962-SM3 |
| #448 | 实现固定 user ID、严格 DER 的 SM2-SM3 签名与验签 |
| #454–#457 | Server、`.sproof v2`、SDK、Desktop 使用同一 registry |
| #462–#471 | BCOS payload、standard/Guomi 网络和离线验证绑定 suite |

## 9. `INTL_V1` 字节兼容基线

以下资产被指定为 `INTL_V1` golden baseline，后续重构必须保持结果不变：

- `test/vectors/sproof-v1-l3.cbor` 与 `test/vectors/sproof-v1-l3.sha256`：完整 `.sproof v1` 确定性 CBOR。
- `internal/claim.TestSignMatchesCanonicalSigningInputReference`：claim domain framing 与 Ed25519 签名输入。
- `internal/claim.TestSignVerifyAndRecordID`：record ID 与签名绑定。
- `internal/receipt.TestSignCommittedPreservesDomainEncoding`：receipt domain framing。
- `internal/merkle.TestHashLeafMatchesCanonicalRecordEncoding`：batch leaf 的确定性 CBOR 与 `0x00` prefix。
- `internal/merkle.TestBuildProofAndVerifyManySizes`：RFC6962-SHA256 tree/proof 行为。
- `internal/globallog` 的 leaf、STH、inclusion 和 consistency tests：Global Log leaf/domain/STH 语义。
- `internal/keystore` 的 append/reload/tamper tests：key event domain、hash chain 和签名。

如果 provider-neutral refactor 改变这些字节，不能更新旧向量来“让测试通过”；必须判断这是 bug，或建立新 suite/format 并保留旧验证器。

## 10. 规范依据

- [RFC 8949: Concise Binary Object Representation (CBOR)](https://www.rfc-editor.org/rfc/rfc8949)
- [RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)](https://www.rfc-editor.org/rfc/rfc8032)
- [RFC 8410: Algorithm Identifiers for Ed25519, Ed448, X25519, and X448](https://www.rfc-editor.org/rfc/rfc8410)
- [RFC 6962: Certificate Transparency](https://www.rfc-editor.org/rfc/rfc6962)
- [GB/T 32918.1-2016：SM2 总则](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=3EE2FD47B962578070541ED468497C5B)
- [GB/T 32918.2-2016：SM2 数字签名算法](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=6F1FAEB62F9668F25F38E0BF0291D4AC)
- [GB/T 32918.5-2017：SM2 参数定义](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=728DEA8B8BB32ACFB6EF4BF449BC3077)
- [GB/T 32905-2016：SM3 密码杂凑算法](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=45B1A67F20F3BF339211C391E9278F5E)
- [GB/T 35276-2017：SM2 密码算法使用规范](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=2127A9F19CB5D7F20D17D334ECA63EE5)

## 11. 后果

正向结果：

- 当前国际算法路径获得明确名称，后续抽象不再依赖“默认算法”的隐式含义。
- CN suite 的 user ID、DER、key、Merkle 和 anchor digest 在写代码前固定，SDK/HSM/Server 不会各自选默认值。
- suite 切换天然成为新日志和新 namespace，避免历史证据被重新解释。
- reserved gate 阻止半成品国密实现被误用于生产。

成本与限制：

- proofstore 已持久化不可变 suite marker；SM3 primitive、RFC6962-SM3 Merkle Profile 和 suite-aware proof core 已由 #447 与 [`ADR-0006`](ADR-0006-SM3-AND-RFC6962-MERKLE-PROFILES.zh-CN.md) 实现。server 仍需由 #448/#454 补齐 SM2 并将 suite 显式传播到全部 V2 业务对象后，才能启用 `CN_SM_V1` 端到端写路径。
- 现有 OTS sink 固定 SHA-256，不是 `CN_SM_V1` anchor provider。
- 如果未来需要不同 SM2 user ID、raw signature、其他证书 Profile 或 Merkle framing，必须定义新的 suite，不能覆盖 `CN_SM_V1`。
