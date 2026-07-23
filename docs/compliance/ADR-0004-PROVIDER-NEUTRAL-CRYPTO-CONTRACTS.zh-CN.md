# ADR-0004：Provider-neutral 密码接口与不可导出 Key Handle

> 状态：Accepted
>
> 日期：2026-07-24
>
> 对应 Issue：[#445](https://github.com/wowtrust/trustdb/issues/445)
>
> 适用阶段：`CN_SM_V1 Cryptography Core`

## 1. 背景

TrustDB 的 `INTL_V1` 实现原先把 `ed25519.PrivateKey`、`ed25519.PublicKey` 和全局默认 SHA-256 直接传入 LocalEngine、Global Log、Key Registry 和离线验证器。这会让软件密钥表示成为核心服务契约，后续远程 KMS、PKCS#11、SDF/HSM 和 `CN_SM_V1` 无法在不扩散具体类型的情况下接入。

本 ADR 只重构密码调用边界，不启用 SM2、SM3、SM4，不改变任何 `INTL_V1` domain、canonical CBOR、签名输入、RecordID、Merkle、STH、proof 或 `.sproof v1` 字节。

## 2. 决策

### 2.1 Suite-aware 公共运算

核心通过 `trustcrypto.Provider` 选择一个不可变 suite。Provider 暴露：

- `HashFactory(algorithm)`：返回 suite 允许的 streaming hash；
- `Verifier(algorithm, encoding)`：返回与算法及公钥编码精确匹配的 verifier；
- `Suite()`：使调用方在运算前显式绑定 suite。

核心路径必须把 Provider 显式向下传递。`HashBytes`、`HashReader` 等无 suite 参数的函数只保留为 `INTL_V1` 边缘兼容入口，不能用于未来 `CN_SM_V1` 核心路径。

### 2.2 不可导出私钥句柄

核心只接收 `Signer`：

- `Handle()` 返回 `Provider + KeyID + Algorithm`，不包含私钥字节；
- `Capabilities()` 明确声明 `sign` 和 `public_key`；
- `PublicKey()` 返回可验证的公钥描述；
- `Sign()` 返回现有 `model.Signature`。

Signer 接口没有私钥导出、序列化或降级方法。软件 Ed25519 adapter 可以在进程内持有密钥副本，但 LocalEngine、Global Log 和 Key Registry 不再保存或要求 `ed25519.PrivateKey`。远程、PKCS#11 和 SDF 实现必须使用同一契约。

批量 proof worker 会并发调用 `Sign()`，所有生产 Signer 必须保证并发安全；不能在核心层用全局锁把硬件或远程 provider 强制串行化。

### 2.3 公钥描述与 verifier

`PublicKeyDescriptor` 包含：

- `Suite`
- `KeyID`
- `Algorithm`
- `Encoding`
- 公钥 bytes

Verifier 在验签前必须验证 suite、算法、编码、长度和可选 KeyID。未知 suite、reserved suite、混用 suite、未知算法、未知编码、错误长度和 KeyID 不一致全部 fail closed，禁止回退到 Ed25519、默认编码或软件 provider。

本次描述符是运行时边界。持久化、配置和备份中的版本化 software/hardware key descriptor 由 #449 实现。

## 3. 核心接入结果

| 组件 | 新边界 | 保持不变的语义 |
| --- | --- | --- |
| LocalEngine | `ServerSigner`、`ClientPublicKeyDescriptor`、suite Provider | claim hash、signature hash、Accepted/Committed receipt bytes、batch root 和 proof |
| Global Log | `Signer` 与 suite Provider | leaf framing、RFC6962-SHA256、STH domain/signature、inclusion/consistency proof |
| Key Registry | Registry Signer、公钥描述和 Provider | append-only event、event hash chain、签名与 reload/tamper 语义 |
| Offline verifier | 公钥描述与 Provider | 完全离线验证，不访问 signer、HSM、KMS、CA 或网络 |

CLI 和 SDK 的现有 Ed25519 便捷入口可以在边缘把本地私钥包装为软件 Signer，但不能把裸私钥重新注入上述核心结构体。SDK/ Desktop 的 `CN_SM_V1` 公共接口分别由 #456、#457 完成。

## 4. Fail-closed 规则

以下情况必须返回错误并停止运算：

1. suite 未知、reserved 或与公钥描述不一致；
2. signer 缺少 `sign` 或 `public_key` capability；
3. handle 缺少 provider、KeyID 或 algorithm；
4. signer algorithm 与 suite 不一致；
5. provider 返回了错误 algorithm、KeyID 或 signature encoding/length；
6. verifier 收到未知算法、未知编码、错误长度或 KeyID 不一致；
7. context 已取消；
8. provider 不可用时尝试回退到软件密钥或默认 suite。

第 8 项没有实现任何 fallback 分支；后续 provider 也不得增加。

## 5. `INTL_V1` 兼容性

以下既有 golden baseline 必须继续通过，不能通过更新旧向量掩盖变化：

- claim canonical signing input 与 RecordID；
- Accepted/Committed receipt domain encoding；
- batch leaf、root 与 inclusion proof；
- Global Log leaf、STH、inclusion 与 consistency proof；
- Key Registry event hash/signature/reload；
- `test/vectors/sproof-v1-l3.cbor` 及其 SHA-256。

软件 Signer 的 Ed25519 输出还必须与 Go 标准库对相同私钥和消息的结果逐字节一致。

## 6. Provider contract gate

统一 contract tests 对 `software`、`remote`、`pkcs11`、`sdf` 四类 fake provider 执行：

- handle、capability 和公钥描述校验；
- sign/verify round trip；
- 与标准库 Ed25519 的字节比较；
- 并发签名；
- algorithm、encoding、length、KeyID、capability 和 context 负向测试；
- `CN_SM_V1` 仍为 reserved 时拒绝创建生产 Provider。

真实 PKCS#11/SDF provider 在 #452/#453 中必须复用此 gate，不得另建弱化接口。

## 7. 后续工作

- #446：proofstore 持久化不可变 suite marker；
- #447：SM3 与 RFC6962-SM3；
- #448：严格 SM2-SM3；
- #449：版本化 software/hardware key descriptor；
- #452/#453：PKCS#11 与 SDF provider；
- #454：Server 全链路启用 `CN_SM_V1`；
- #455–#457：`.sproof v2`、SDK 和 Desktop。

## 8. 决策后果

正向结果：

- 核心不再依赖软件私钥类型；
- HSM/KMS 接入不需要改变 proof 语义；
- suite、算法、编码和 KeyID 在运行时边界可审计；
- 离线验证与签名 provider 完全解耦；
- provider 长期不可用或配置错误时不会静默降级。

代价与限制：

- 调用方必须显式构造 Signer 和公钥描述；
- Provider 实现必须满足并发与 context 契约；
- 当前只有 `INTL_V1` Provider 可用；#447 已实现可独立测试的 SM3 hash factory 与 RFC6962-SM3 Profile，但 `CN_SM_V1` 生产 Provider 仍被 registry gate 拒绝；
- 软件 adapter 仍在进程内持有 Ed25519 私钥，不能被误宣称为 HSM 级密钥保护。
