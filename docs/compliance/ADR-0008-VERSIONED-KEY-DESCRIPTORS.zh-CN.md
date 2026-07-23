# ADR-0008：版本化软件、硬件与远程密钥描述符

> 状态：Accepted
>
> 日期：2026-07-24
>
> 关联 Issue：[#449](https://github.com/wowtrust/trustdb/issues/449)
>
> 上位决策：[`ADR-0001`](ADR-0001-CRYPTOGRAPHIC-SUITES.zh-CN.md)、[`ADR-0004`](ADR-0004-PROVIDER-NEUTRAL-CRYPTO-CONTRACTS.zh-CN.md)、[`ADR-0007`](ADR-0007-CANONICAL-SM2-SM3-SIGNATURES.zh-CN.md)

## 1. 决策

TrustDB 使用唯一的 `trustdb.key-descriptor.v1` 作为 CLI、Server 和 provider 的持久密钥配置边界。描述符采用 RFC 8949 Core Deterministic CBOR，携带 suite、KeyID、算法、公钥、证书链和 provider 引用，但不携带私钥字节。

旧的“一个文件就是 raw URL-base64 Ed25519 bytes”格式不再读取、迁移、猜测或回退。版本未知、字段未知、非 canonical、provider 不可用或配置不一致时必须明确失败。

完整英文格式规范见 [`formats/KEY_DESCRIPTOR_V1.md`](../../formats/KEY_DESCRIPTOR_V1.md)。

## 2. 类型和 Provider 联合

描述符分为两类：

- `signer`：必须指定 `software`、`pkcs11`、`sdf` 或 `remote` 之一，且只能出现对应的一组引用；
- `verifier`：必须使用 `public`，不能出现任何私钥 provider 引用。

公共字段固定包含：

- `schema_version`；
- `kind` 与 `provider`；
- `crypto_suite`、`key_id`、`algorithm`；
- suite-defined `public_key.encoding` 和公钥 bytes；
- `CN_SM_V1` 下固定的 SM2 user ID；
- 可选、leaf-first 的 DER `certificate_chain`。

同一描述符不能同时出现 software、PKCS#11、SDF 或 remote 引用。未知 provider、错误算法、错误编码、空 KeyID、错误 SM2 user ID 或 provider/reference 不匹配全部 fail closed。

## 3. 私钥与元数据分离

### 3.1 Software

Software 描述符只保存相对路径、私钥编码和 protection ID。当前 `keygen` 生成：

```text
client.key       signer descriptor
client.pub       verifier descriptor
client.material  独立的 private material
```

`client.key` 和 `client.pub` 都是 canonical CBOR，不是私钥 bytes。`client.material` 使用 `plaintext-dev-v1`，只用于开发和参考实现，并要求 Unix 下不得授予 group/other 权限。#451 将实现 `sm4-envelope-v1`；当前 resolver 识别该 ID 但明确返回 unsupported，绝不降级为 plaintext。

Software resolver 还拒绝绝对路径、`..` 穿越、symlink、非普通文件、非 canonical raw URL-base64、错误长度以及私钥派生公钥与描述符不一致。

### 3.2 Hardware 与 remote

- PKCS#11 描述符保存对象 URI，禁止内联 `pin-value`；
- SDF 描述符保存 device reference、非零 key index 和可选 credential reference；
- Remote 描述符保存 HTTPS endpoint、opaque handle 和 credential reference，禁止 URL 用户密码、query 和 fragment。

这些引用只选择 provider，不允许核心导出私钥。真实 PKCS#11、SDF 和 remote provider 分别由 #452/#453 及部署 adapter 实现；未注册 provider 必须在启动或命令执行时失败。

## 4. 解析、解析器和 canonical 边界

Decoder 拒绝：

- 未知字段、重复 map key、CBOR tag、indefinite-length value；
- trailing bytes、超限描述符、NaN/Inf；
- 解码成功但重新 canonical encode 后 bytes 不相等的输入。

描述符最大 2 MiB，证书数量、单证书和证书链总大小同时受 V2 format registry 限制。Parser fuzz 必须保证任意输入不 panic；任何被接受的输入重新编码后必须与原 bytes 完全相等。

## 5. Certificate 规则

证书链必须：

1. 每张证书都是精确 DER；
2. leaf 公钥类型、suite 和 bytes 与描述符完全相同；
3. leaf 若声明 KeyUsage，则必须允许 digital signature；
4. 后续证书必须为 CA，顺序为 leaf 到 root，并逐级通过签名检查；
5. `INTL_V1` 只接受 Ed25519 profile，`CN_SM_V1` 只接受 SM2-with-SM3 profile。

证书链属于 key metadata 和离线证据材料，不是自动信任根。验证者仍必须从本地 trust configuration 取得可信 CA、公钥或 checkpoint。

## 6. Signer 解析契约

`Resolver` 的执行顺序固定为：

1. 完整验证描述符；
2. 检查 suite 已允许生产使用；
3. 精确选择描述符声明的 provider；
4. provider 返回没有 private export 方法的 `trustcrypto.Signer`；
5. 检查 `sign`、`public_key` capabilities；
6. 精确比较 provider、KeyID、algorithm、suite、encoding 和 public key bytes。

任一不一致均返回错误。Resolver 没有“remote 失败后读本地文件”“SM2 失败后使用 Ed25519”或“未知格式尝试旧 base64”分支。

CLI 的 claim、commit、serve、verify、registry 和 benchmark 入口都通过描述符选择 signer 或 verifier。配置中的 `keys.*` 字段名暂时保持不变，但它们现在指向 descriptor 文件；`server.key_id`、`client key-id` 与 descriptor `key_id` 必须精确一致。

## 7. 脱敏与备份边界

`String()`、JSON 和 `key inspect` 对以下字段脱敏：

- software material path；
- 完整 PKCS#11 URI；
- SDF device/credential reference；
- remote endpoint、handle、credential reference。

逻辑备份继续只导出 proofstore 证据和恢复状态，不导出 descriptor 所引用的 private material、PIN、credential 或 remote handle。非软件 provider 从接口层就不存在 private export 方法。密钥备份、复制和灾备必须使用 HSM/KMS/SDF/PKCS#11 provider 自己的受控流程。

## 8. 兼容与迁移

本项目当前无需要保留的生产用户，因此采用破坏性配置升级：

- 不实现旧 raw Ed25519 key file 双读；
- 不在启动时自动生成 descriptor；
- 不根据 key 长度猜测算法或 kind；
- 不提供 provider 或 protection fallback；
- 未知 future schema version 明确失败。

开发环境重新运行 `trustdb keygen`。生产环境应由密钥管理员创建指向目标 provider 的 v1 描述符，并在启用服务前核对公钥、KeyID、suite、证书链和 capability。

## 9. 验证 Gate

- 每种 descriptor/provider kind canonical round trip；
- unknown field、trailing/non-canonical/oversize 和 parser fuzz；
- provider union、path、URI、endpoint、suite、algorithm、encoding 和 SM2 user ID 负向测试；
- Ed25519 与 SM2 certificate/public-key 绑定测试；
- software material permission、symlink、base64、public mismatch 和 protection downgrade 测试；
- fake PKCS#11/SDF/remote provider 的 handle、capability 和 public-key exact-match contract；
- CLI raw legacy key rejection、KeyID mismatch 和 descriptor-relative material resolution；
- `go test ./...`、race 与 Linux/Windows build gate。

## 10. 后续工作

- #451：实现 authenticated `sm4-envelope-v1`，停止新路径持久化 plaintext private material；
- #452：PKCS#11 provider；
- #453：SDF/HSM provider；
- #454：V2 Server 全链路传播并启用 `CN_SM_V1`；
- #455：`.sproof v2` 的 suite/certificate/trust material；
- #456/#457：Go SDK 与 Desktop 的 suite-aware identity 和非导出 signer 接口。

在 #451–#454 完成前，可以准确声明“TrustDB 已完成版本化、不可歧义、provider-neutral 的密钥配置和解析边界”，不能声明当前 `keygen` 的 `plaintext-dev-v1` 已达到生产 HSM 或国密密钥存储要求。
