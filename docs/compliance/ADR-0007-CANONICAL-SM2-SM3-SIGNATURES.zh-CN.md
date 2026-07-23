# ADR-0007：Canonical SM2-SM3 签名与验签

> 状态：Accepted
>
> 日期：2026-07-24
>
> 关联 Issue：[#448](https://github.com/wowtrust/trustdb/issues/448)
>
> 上位决策：[`ADR-0001`](ADR-0001-CRYPTOGRAPHIC-SUITES.zh-CN.md)、[`ADR-0002`](ADR-0002-CRYPTO-AGILITY-FORMATS.zh-CN.md)、[`ADR-0003`](ADR-0003-SM-CRYPTO-DEPENDENCIES-AND-VECTORS.zh-CN.md)、[`ADR-0004`](ADR-0004-PROVIDER-NEUTRAL-CRYPTO-CONTRACTS.zh-CN.md)、[`ADR-0006`](ADR-0006-SM3-AND-RFC6962-MERKLE-PROFILES.zh-CN.md)

## 1. 决策

TrustDB 为 `CN_SM_V1` 实现 provider-neutral 的 SM2-SM3 签名和验签核心，并固定以下不可变参数：

| 参数 | `CN_SM_V1` 取值 |
| --- | --- |
| 曲线 | SM2 P-256 / sm2p256v1 |
| 消息摘要 | SM3，包含标准 ZA 计算 |
| SM2 user ID | 精确 16-byte ASCII `1234567812345678` |
| 签名编码 | canonical ASN.1 DER `SEQUENCE(INTEGER r, INTEGER s)` |
| 公钥编码 | 65-byte SEC1 uncompressed：`0x04 || X[32] || Y[32]` |
| 私钥软件输入 | 32-byte big-endian scalar，仅用于开发、测试和参考实现 |
| 业务签名输入 | `domain || 0x00 || "CN_SM_V1" || 0x00 || deterministic-CBOR(payload)` |

SM2 provider 接收的 message 已经包含 TrustDB 的业务 domain 和 suite framing。Provider 只执行标准 SM2 ZA、SM3 和椭圆曲线签名，不得再次添加业务 domain，不得接受调用方覆盖 user ID，也不得根据公钥、签名长度或运行配置猜测 suite。

## 2. 严格编码与 fail-closed 规则

### 2.1 DER 签名

验签前必须先执行独立的 strict DER 校验：

- 输入必须精确包含一个 DER `SEQUENCE`，后面不能有任何 trailing bytes；
- `r`、`s` 必须是正整数，且满足 `1 <= r,s < n`；
- INTEGER 必须使用 DER 最短编码，不接受冗余前导零、负数、零或超出曲线阶的值；
- 重新 DER 编码后的 bytes 必须与输入逐字节相等；
- 不接受 raw `r || s`、BER、P1363、JSON、base64 文本或库私有格式。

DER 签名长度可变，合法范围为 8–72 bytes。任何依赖固定 64-byte 签名长度的 RecordID、WAL 或协议拼接都不能用于 `CN_SM_V1`；V2 model 必须使用 ADR-0001/0002 定义的确定性、带长度 framing。

### 2.2 公钥

公钥必须是 SM2 曲线上的 canonical 65-byte uncompressed SEC1 point。压缩点、hybrid point、P-256 公钥、无穷远点、越界坐标、错误 OID 或非 canonical bytes 全部拒绝。`PublicKeyDescriptor` 的 suite、algorithm、encoding 和可选 KeyID 必须与 verifier 精确匹配。

### 2.3 User ID 与 suite

user ID 是 suite 参数，不是用户身份字段。SDK、HTTP/gRPC 请求、证据文件、配置、租户和 key metadata 都不能提供覆盖值。错误 user ID、错误 domain、错误 suite、错误 KeyID、修改后的 message 或签名必须验签失败。

证据文件可以声明 `CN_SM_V1`，但不能把文件自带的 user ID 或公钥自动提升为信任根。离线验证者仍从本地 trust configuration 取得可信公钥、证书链或 checkpoint，并精确匹配证据声明。

## 3. Provider 边界

`internal/trustcrypto` 提供：

- `NewSM2Signer`：软件参考 signer，用于向量、测试、开发和未来 SDK adapter；
- `NewSM2PublicKey`：构造并校验 suite-bound 公钥描述；
- `ValidateSM2SignatureDER`：无验签副作用的 strict DER 校验；
- `VerifySignatureForSuite`：对已知 suite 执行显式验签，可用于 conformance 和离线 verifier 开发。

`ProviderForSuite(CN_SM_V1)` 仍必须返回 unavailable。原因不是 SM2 primitive 缺失，而是当前 V1 model、proof、WAL、API 和 `.sproof` 不携带完整 suite 参数；在 #454/#455 完成 V2/V5 全链路之前启用生产签名，会生成无法按声明稳定离线解释的半套证据。

软件 signer 不代表生产私钥边界。中国生产 Profile 的长期客户端、服务端、STH 和 Anchor 发布者私钥仍应进入适用且经批准的 SDF/HSM/KMS provider；核心不得在 provider 失败时回退到软件 signer。

## 4. 统一签名输入

Claim、Accepted Receipt、Committed Receipt、Key Event 和 Signed Tree Head 不再各自维护硬编码 domain 拼接。它们统一通过 suite registry 选择 domain 和 framing：

```text
INTL_V1  = ASCII(domain.v1) || 0x00 || payload
CN_SM_V1 = ASCII(domain.v2) || 0x00 || ASCII("CN_SM_V1") || 0x00 || payload
```

这次重构不得改变任何 `INTL_V1` bytes。已有 claim、receipt、registry、STH 和 `.sproof v1` golden tests 必须继续逐字节通过。`CN_SM_V1` 的 suite bytes 位于被签名 message 内，因此把相同 payload、key 和 signature metadata 改标为其他 suite 不能通过验证。

当前 V1 持久对象不新增 `crypto_suite` 字段。#454 的破坏性 V2 切换负责把 suite 放入所有签名对象、wire/storage model 和 trust context；本 ADR 只完成不可歧义的密码核心与签名输入函数，不能被解释为 V1 已支持国密证据。

## 5. 向量与互操作验证

固定官方向量包括：

- 私钥 `3945208f...df7c5b8`；
- 65-byte uncompressed 公钥 `0409f9df...a9ad13`；
- message `message digest`；
- user ID `1234567812345678`；
- ZA `b2e14c5c...da8a4f3`；
- canonical DER signature `30460221...85bbc1aa`。

Gate 同时要求：

1. TrustDB provider 验证官方签名、ZA 和派生公钥；
2. 软件 signer 生成的签名通过 strict DER 和 provider 验签；
3. Linux OpenSSL 3 使用相同 public key、SM3 和 `distid` 独立验证官方签名；
4. 错误 user ID 在 TrustDB 与 OpenSSL 两侧均失败；
5. malformed DER、raw `r || s`、错误曲线、公钥编码、suite、KeyID、message 和取消 context 全部失败；
6. 并发 signer race test 和 verifier fuzz test 不 panic、不发生数据竞争。

OpenSSL 是测试 oracle，不进入生产路径。`CN_SM_V1` 正式可用前仍需按 ADR-0003 增加固定 digest 的 GmSSL 或 Tongsuo 跨架构、证书和 SDK/CLI/Desktop 互操作 Gate。

## 6. 后续边界

- #449：版本化 software/hardware key descriptor 已完成，见 [`ADR-0008`](ADR-0008-VERSIONED-KEY-DESCRIPTORS.zh-CN.md)；
- #452/#453：真实 PKCS#11 与 SDF/HSM provider；
- #454：V2 Server 全链路携带 suite，并在完整 gate 中启用 `CN_SM_V1`；
- #455：`.sproof v2` 完整携带 SM2 STH、SM3 path 和离线 trust material；
- #456/#457：Go SDK、CLI 和 Desktop 复用同一 user ID、DER、公钥和签名输入契约。

在这些工作完成前，项目可以准确声明“已实现并验证 canonical SM2-SM3 密码核心”，不能声明当前 Server 已支持生产 `CN_SM_V1` 写入或现有 `.sproof v1` 已成为国密证据。
