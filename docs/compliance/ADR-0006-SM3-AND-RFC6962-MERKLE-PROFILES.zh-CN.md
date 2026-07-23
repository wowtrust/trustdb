# ADR-0006：SM3 哈希与 RFC6962-SM3 Merkle Profile

> 状态：Accepted
>
> 日期：2026-07-24
>
> 关联 Issue：[#447](https://github.com/wowtrust/trustdb/issues/447)
>
> 上位决策：[`ADR-0001`](ADR-0001-CRYPTOGRAPHIC-SUITES.zh-CN.md)、[`ADR-0002`](ADR-0002-CRYPTO-AGILITY-FORMATS.zh-CN.md)、[`ADR-0003`](ADR-0003-SM-CRYPTO-DEPENDENCIES-AND-VECTORS.zh-CN.md)、[`ADR-0004`](ADR-0004-PROVIDER-NEUTRAL-CRYPTO-CONTRACTS.zh-CN.md)、[`ADR-0005`](ADR-0005-IMMUTABLE-PROOFSTORE-SUITE-MARKERS.zh-CN.md)

## 1. 决策

TrustDB 为 `CN_SM_V1` 实现 SM3 byte、fixed-width 和 streaming hash，并实现与 suite 精确绑定的 `rfc6962-sm3` Merkle Profile。Batch tree、Global Log tree、proof verifier、幂等键和内部 batch commit 不再依赖全局 SHA-256 假设，而是从明确的 `(crypto_suite, tree_alg)` 组合取得哈希、摘要长度和 `0x00/0x01` domain prefix。

`INTL_V1` 继续使用 `rfc6962-sha256`，旧 API 只是其薄包装；已有 leaf、root、proof、STH 和 idempotency key 字节保持不变。摘要同为 32 字节不构成兼容条件，suite 或 tree algorithm 不精确匹配时必须在计算 proof path 前拒绝。

本 ADR 不启用 `CN_SM_V1` 生产 Provider，不生成 SM2 签名，也不把当前 V1 model 重新解释成国密证据。完整 CN 写入、V2/V5 对象传播和离线证据发布仍由 #448、#454 和 #455 完成。

## 2. 哈希注册表

`internal/trustcrypto.HashFactoryForSuite` 是 primitive registry：

- `INTL_V1 + sha256` 返回 SHA-256 factory；
- `CN_SM_V1 + sm3` 返回 SM3 factory；
- suite 未知、算法未知或跨 suite 组合一律返回错误；
- `HashBytesForSuite` 与 `HashReaderForSuite` 可用于 reserved suite 的一致性测试，但 `ProviderForSuite(CN_SM_V1)` 仍由 availability gate 拒绝。

区分 primitive 可测试与 production suite 可用性，能够先完成标准向量、Merkle 和格式验证，同时防止“只有 SM3、没有 SM2/V2”的半套实现进入生产。

## 3. Merkle Profile

每个 Profile 固定以下不可变参数：

| Suite | Tree algorithm | Hash | Leaf prefix | Node prefix | Digest |
| --- | --- | --- | --- | --- | --- |
| `INTL_V1` | `rfc6962-sha256` | SHA-256 | `0x00` | `0x01` | 32 bytes |
| `CN_SM_V1` | `rfc6962-sm3` | SM3 | `0x00` | `0x01` | 32 bytes |

运算定义：

```text
empty_root = H("")
leaf       = H(0x00 || payload)
node       = H(0x01 || left[32] || right[32])
```

Batch leaf 的 payload 是 deterministic-CBOR `ServerRecord`。Global Log leaf 继续由 Global Log canonical leaf framing 生成后再进入同一 suite Merkle Profile；V2 的 `trustdb.global-log-leaf.v2` 完整 domain framing 在 #454 的 model cutover 中一次启用，不能提前改变 `INTL_V1` 字节。

`Profile` 字段私有，调用方不能自行拼装 hash、prefix 或 algorithm。验证 API 同时接收 suite 和 tree algorithm，先校验 registry 组合，再验证 O(log N) audit path。

## 4. 固定向量

### 4.1 SM3

| Input | Digest |
| --- | --- |
| `abc` | `66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0` |
| `abcd` repeated 16 times | `debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732` |

### 4.2 RFC6962-SM3

| Operation | Digest |
| --- | --- |
| `SM3("")` | `1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b` |
| `leaf("alpha")` | `8f305348d6bcdb9a12c3ddf6a57f15b0a6dccb6f65844c7697480796f72c7ce3` |
| `leaf("beta")` | `4d90e49bb5066d85b0b0d860111f96b357cddd919146ff82e263f3213dcff5f6` |
| `node(leaf("alpha"), leaf("beta"))` | `dd2c9f9eaa2bddde1dc837ae282f04b9301e668afb98d3281a4b0b0eb49ce1cf` |

Expected bytes 是固定 oracle，不由被测 Merkle 实现动态生成。SM3 digest 和 idempotency framing 还使用 OpenSSL SM3 独立复算。

## 5. 核心路径绑定

- Local batch compute 从 Provider suite 构造 tree，并把实际 `TreeAlg` 传给 manifest 和 `BatchProof`。
- Global Log service 在创建时冻结 Merkle Profile；增量 frontier、internal node、subtree root、STH 和 inclusion verifier 全部使用该 Profile。
- Proof verifier 要求 `BatchProof.TreeAlg`、`SignedTreeHead.TreeAlg` 与 Provider suite 精确相等。
- suite-aware idempotency validation 使用 suite 的 claim/signature digest 长度与签名算法；storage key 使用 suite-specific domain/hash，V2 suite 还加入 suite framing。
- proofstore namespace marker 仍是持久 suite 的唯一来源；#454 启用 CN 业务对象时，store 调用路径必须把该 suite 继续传给所有 idempotency 和 proof 操作。

`CN_SM_V1` idempotency storage key 固定为：

```text
SM3(
  ASCII("trustdb.idempotency-storage-key.v2") || 0x00 ||
  ASCII("CN_SM_V1") || 0x00 ||
  uint64be(len(tenant_id)) || tenant_id ||
  uint64be(len(client_id)) || client_id ||
  uint64be(len(idempotency_key)) || idempotency_key
)
```

固定输入 `tenant/client/key` 的结果为 `c9c4fc9a13e82043c97e461201fdba1faf7286edeee33e5fd89b1b9096262645`。`INTL_V1` 继续使用原 v1 domain、SHA-256 和原有 length-delimited framing，结果保持 `35f7b4a2c0e49e8c72708eba6245c0fcca7107b13953141630f8b286a5947638`。

## 6. 性能与复杂度

- Tree build 为 O(N)，proof 生成和验证为 O(log N)。
- 1、2、3、4、5、8、16、31、32、33、1024、4096 叶均验证全部 audit path，并断言 path 长度不超过 `ceil(log2 N)`。
- SM3 proof verification 使用 fixed-width stack digest，1024 叶 proof 验证为零 heap allocation。
- benchmark 分别覆盖 SHA-256 与 SM3 的 1024 叶 build/verify，便于后续 server cutover 设置回归预算。

## 7. Fail-closed 测试

以下情况必须失败：

- `CN_SM_V1` 搭配 `rfc6962-sha256`；
- `INTL_V1` 搭配 `rfc6962-sm3`；
- 相同 32-byte leaf/root 以错误 suite 验证；
- Global Log 单叶 proof 仅因 path 为空而绕过 suite 检查；
- 未知 suite、未知 hash 或 provider hash 与 suite Profile 不一致；
- `INTL_V1` 旧 API 与显式 suite API 产生不同 root、leaf 或 proof。

## 8. 后续边界

- #448：SM2-SM3、固定 user ID、严格 DER 与 key validation；
- #454：V2 Server 全链路显式传播 `crypto_suite`，启用 `CN_SM_V1` Provider，并将 proofstore suite marker 传入所有业务计算；
- #455：`.sproof v2` 携带 suite、SM3 path、SM2 STH 和完整离线验证材料；
- #456/#457：Go SDK、CLI 与 Desktop 使用同一 suite/tree registry；
- #462–#471：FISCO BCOS payload、国密网络与离线 finality evidence。

在上述端到端 Gate 完成前，项目只能声明“已实现并验证 SM3 与 RFC6962-SM3 核心”，不能声明 `CN_SM_V1` 已可用于生产。
