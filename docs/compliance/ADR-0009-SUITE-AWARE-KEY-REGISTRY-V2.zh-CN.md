# ADR-0009：Suite-aware Key Registry V2 与 SM2 密钥生命周期

状态：Accepted

日期：2026-07-24

Issue：#450

## 1. 决策

TrustDB 将客户端密钥注册表破坏性切换到 `trustdb.key-registry.v2`。每个 registry 文件在不可变 manifest 中绑定一个 `crypto_suite` 和一个 registry signer 公钥；同一文件不得混入其他 suite，也不得在原路径替换 signer。

完整英文格式规范见 [`formats/KEY_REGISTRY_V2.md`](../../formats/KEY_REGISTRY_V2.md)。

Registry V2 支持：

- `INTL_V1` 的 Ed25519/SHA-256 事件链；
- `CN_SM_V1` 的 SM2-SM3/SM3 事件链；
- 注册、原子轮换、撤销、失陷和按有效时点查询；
- 完整 canonical key descriptor，包括证书链和 software/PKCS#11/SDF/remote provider reference；
- 固定格式、确定性 CBOR、CRC32C 帧检测、签名链和 suite-specific hash 链；
- 最终不完整帧的幂等恢复，以及并发初始化时不可覆盖 manifest。

旧 V1 registry frame 不读取、不迁移、不回退。格式不匹配时明确失败。

## 2. Suite 与启用边界

一个 registry 只能保存与 manifest 相同 suite 的 key。混用 `INTL_V1` 与 `CN_SM_V1` 会在落盘前失败。

`CN_SM_V1` 当前仍未开放服务端 claim、receipt、batch、STH 和 anchor 生成；该生产启用由 #454 完成。#450 只允许密钥管理员和测试工具：

- 生成开发/互操作用 SM2 软件 descriptor；
- 解析生产 provider descriptor；
- 对 Registry V2 生命周期事件进行 SM2 签名和离线验签。

这条窄路径不能被 core evidence generation 调用。普通 `ResolveSigner` 继续要求 suite available；只有明确命名的 lifecycle resolver 接受 known/reserved suite。

## 3. 信任模型

Manifest 内嵌的 registry 公钥用于精确绑定文件，但不能自证可信。读取既有 registry 时，调用方必须从本地配置提供 registry verifier descriptor；manifest 的 suite、KeyID、算法、编码和公钥 bytes 必须与该外部 trust root 精确一致。

因此：

- `trustdb key list` 没有 `--registry-public-key` 时失败；
- server、commit 和 verify 使用 registry 时必须配置外部 registry public descriptor；
- 不能把 registry 文件自身携带的公钥当作信任根；
- signer descriptor 与 verifier descriptor 不精确匹配时失败。

## 4. 生命周期语义

### 4.1 注册

注册事件保存完整 `trustdb.key-descriptor.v1` bytes，而不是只保存裸公钥。相同 tenant/client/KeyID 的完全相同重试返回既有事件，不重复追加；suite、算法、公钥、provider reference、证书、有效期或其他 descriptor 内容冲突时 fail closed。

### 4.2 轮换

`KEY_ROTATED` 是单个耐久事件，同时：

1. 在 `rotated_at` 之前保留旧 KeyID 的历史有效性；
2. 从 `rotated_at` 开始将旧 KeyID 视为 revoked；
3. 从同一时点启用新 KeyID；
4. 不修改任何旧 claim、receipt、STH、proof 或 registry event。

新 KeyID 必须与旧 KeyID 不同，且此前未注册。轮换失败不会产生“旧 key 已退役但新 key 未注册”的中间状态。

### 4.3 撤销与失陷

撤销和失陷具有独立有效时间。历史查询使用待验证签名/receipt 的业务有效时点，而不是 registry 当前时间。失陷状态优先于撤销状态，便于安全审计识别事故语义。

### 4.4 证书有效期

Descriptor 中存在证书链时，registry validity 必须落在 leaf certificate 的 `[NotBefore, NotAfter)` 内。未指定 `valid_until` 时自动收口到 leaf `NotAfter`；不得让 registry key 生命周期越过证书有效期。

证书链只提供证书材料和绑定检查，不自带信任。CA roots、CRL/OCSP 或签名时状态材料仍由 verifier-local trust configuration 和 #455 负责。

## 5. 持久化与恢复

文件布局为 magic、manifest frame、零个或多个 event frame。每帧包含长度、canonical CBOR payload 和 CRC32C。CRC 只检测 torn write/随机损坏，密码完整性由 event signature、`prev_event_hash` 和 suite-specific `event_hash` 提供。

追加顺序：

1. 在锁内验证生命周期转换；
2. 固定 sequence 和 previous hash；
3. 使用 registry signer 签名，并立即用 manifest public key 反向验证 provider 输出；
4. 计算 event hash；
5. 写完整 frame 并 `fsync`；
6. 仅在 durable 后更新内存索引。

进程在第 5 步前崩溃时，重启忽略并在可写打开时截断最终不完整帧；完整帧 CRC、签名、hash、sequence 或生命周期异常时不得修复或跳过。并发创建通过原子 hard-link publish，已有 manifest 不会被后来的 initializer 覆盖。

## 6. CLI

```bash
trustdb key generate --suite CN_SM_V1 --out ./keys --prefix client
trustdb key import --registry ./keys.tdkeys --public-key ./keys/client.pub ...
trustdb key rotate --registry ./keys.tdkeys --previous-key-id old --descriptor ./keys/new.pub ...
trustdb key revoke --registry ./keys.tdkeys ...
trustdb key compromise --registry ./keys.tdkeys ...
trustdb key list --registry ./keys.tdkeys --registry-public-key ./keys/registry.pub
trustdb key inspect --key ./keys/client.pub
```

`key generate` 的 `plaintext-dev-v1` 只用于开发。生产私钥必须留在 HSM/SDF/KMS/PKCS#11 边界内，CLI 只导入 descriptor 和公开材料。

## 7. 验证 Gate

- INTL_V1 与 CN_SM_V1 注册、重载和按时点查询；
- suite/算法/公钥/KeyID 冲突拒绝；
- 轮换前后历史语义和单事件原子性；
- revoke/compromise 时间边界；
- provider reference 与证书链 round trip；
- leaf 证书有效期收口；
- final torn frame 恢复、CRC/签名/hash/sequence 篡改拒绝；
- 并发初始化不可替换 manifest；
- CLI SM2 generation、import、rotate、compromise、list golden flow；
- `go test ./...` 与 race gate。

## 8. 后续工作

- #451：SM4 software-key envelope；
- #452：PKCS#11 provider；
- #453：SDF provider；
- #454：Server Model V2 与 CN_SM_V1 证据生成；
- #455：`.sproof v2`、证书状态和离线信任材料。
