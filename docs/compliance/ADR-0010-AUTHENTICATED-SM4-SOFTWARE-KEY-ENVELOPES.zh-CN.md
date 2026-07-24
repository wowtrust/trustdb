# ADR-0010：认证 SM4 软件私钥信封与 KEK 轮换

- 状态：Accepted
- 日期：2026-07-24
- 关联：#443、#449、#451

## 1. 决策

TrustDB 为 `software.protection=sm4-envelope-v1` 实现版本化、canonical、fail-closed 的软件私钥信封。外层格式为 deterministic CBOR；私钥内容使用随机 128-bit DEK、随机 96-bit nonce 和固定 128-bit tag 的 SM4-GCM。DEK 再由 provider-neutral `KEKProvider` 包装，因此 HSM/KMS adapter 可以在不导出 KEK 的边界内完成 wrap/unwrap。

内置 `passphrase-dev-v1` 只用于开发、离线演示和互操作，使用 `PBKDF2-HMAC-SM3`：16-byte 随机 salt、默认 200000 次、固定允许 100000–2000000 次、16-byte KEK。passphrase 必须恰好从 `TRUSTDB_DEV_KEY_PASSPHRASE` 或 `TRUSTDB_DEV_KEY_PASSPHRASE_FILE` 指定的 owner-only 普通文件读取，不提供普通命令行明文 flag；secret file 必须位于 envelope 目录和同一备份卷之外。轮换的新 KEK 使用对应的 `_NEW` 直接值或文件来源，同样必须恰好选择一个。该能力不能表述为 HSM、SDF、KMS 托管，不能推出产品认证、密评结论或生产私钥已进入合规硬件边界。

## 2. 认证边界

调用方从已验证 descriptor 重建可信 metadata：suite、KeyID、签名算法和私钥编码。Open 在调用 KEK provider 前逐字段比较，随后两层 AAD 分别认证：

1. 内容层绑定 domain、object type、suite、KeyID、签名算法、私钥编码和 `SM4-GCM`；
2. DEK wrap 层再绑定 provider name、wrap algorithm 和完整 canonical provider parameters。

因此修改 descriptor/envelope metadata、nonce、ciphertext、tag、KDF salt/iterations、provider metadata、版本或算法都会在 signer 返回前失败。通用 parser 拒绝未知字段、重复 key、CBOR tag、indefinite value、trailing bytes、非 canonical bytes、超限 payload 和 future version；provider 是否注册则由 Open 阶段根据调用方 policy 拒绝。不存在 plaintext、旧格式或其他 provider fallback。

## 3. nonce 与轮换

每次新建信封生成新的 DEK 和 content nonce。passphrase provider 每次 wrap 生成新的 salt，因此派生新的 KEK，并同时生成新的 wrap nonce；同一轮换若复用上一组 provider parameters 会拒绝。随机源为 `crypto/rand`，实现不提供固定 nonce、外部计数器或调用方注入 nonce 的生产 API。

`key rewrap` 先认证旧 wrapped DEK 和私钥 ciphertext，再只替换 wrapped DEK。content nonce/ciphertext、私钥、公钥、KeyID、Registry V2 事件和历史验签引用不变。在受支持的 Unix 系统上，写入通过相邻 owner-only lock file 取得 OS 级锁，并在持锁期间完成 read、认证、rewrap、同目录 owner-only 临时文件、file fsync、atomic replace 和 directory fsync；并发或 stale writer 必须重新认证最新 envelope，不能覆盖胜出的轮换。进程退出由内核释放锁；callback、序列化或安装失败保持旧文件不变。不创建 plaintext 或 `.bak` 副本。

## 4. 密钥生成与兼容

`trustdb key generate` 的新默认值是 `sm4-envelope-v1`，缺少唯一有效的标准开发 passphrase 来源时 fail closed。原 `plaintext-dev-v1` 仅保留为显式 `--protection plaintext-dev-v1` 的开发兼容入口，不自动选择、不从 envelope 失败降级，也不得在生产部署使用。

Windows 软件 envelope 持久化当前明确返回 unsupported，直到项目能在支持的 Windows 版本和文件系统上持续运行时验证 owner-only DACL 的创建与检查。Windows 部署必须使用经批准的外部 signer；只有可丢弃的开发评估可以显式使用 `plaintext-dev-v1`。

这是 at-rest key custody 的版本化变更，不改变 TrustDB claim、receipt、Merkle、STH、anchor、ProofBundle、`.sproof` 或 Registry V2 的 canonical 签名/hash 输入。Registry 继续保存 descriptor 和公开材料，从不保存 envelope 私钥 bytes。

## 5. 备份、诊断与内存

逻辑备份继续排除 descriptor 引用的 material、passphrase、KEK、PIN、credential 和 remote handle。生产密钥备份/恢复必须使用经批准 provider 的受控流程，不能把软件 envelope 和 passphrase 一起复制后称为分离托管。

错误信息不输出 passphrase、私钥、material path 或 provider credential。DEK、派生 KEK、passphrase byte copy、解密私钥和临时 envelope buffer 在生命周期结束时 best-effort `clear`；Go runtime、环境变量和操作系统可能保留的副本无法保证物理擦除。

## 6. 验证 Gate

- 官方 SM4 与固定 SM4-GCM known-answer vector；
- canonical round trip 与 parser fuzz；
- wrong passphrase、tampered nonce/ciphertext/tag/provider params；
- KDF iteration downgrade/DoS 上界、schema/algorithm downgrade、truncation；
- descriptor metadata mismatch、unregistered provider、symlink 和 unsafe permissions；
- 新建 nonce/parameters 不重复、KEK rewrap 保持 content ciphertext/public identity；
- 跨进程 lock、并发/stale rewrap、持锁进程退出恢复、atomic no-replace/replace、失败保持旧文件、无 secret backup artifact；
- CLI generate/resolve/rewrap 和 INTL/SM2 lifecycle resolver；
- `go test`、race、Linux build、Windows fail-closed cross-build/test compile gate 与 secret-safe log/fixture review。
