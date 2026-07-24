# ADR-0011：受监督的外部签名插件

> 状态：Accepted
>
> 日期：2026-07-24
>
> 关联 Issue：[#552](https://github.com/wowtrust/trustdb/issues/552)
>
> 上位决策：[`ADR-0004`](ADR-0004-PROVIDER-NEUTRAL-CRYPTO-CONTRACTS.zh-CN.md)、[`ADR-0007`](ADR-0007-CANONICAL-SM2-SM3-SIGNATURES.zh-CN.md)、[`ADR-0008`](ADR-0008-VERSIONED-KEY-DESCRIPTORS.zh-CN.md)、[`ADR-0009`](ADR-0009-SUITE-AWARE-KEY-REGISTRY-V2.zh-CN.md)

## 1. 决策

TrustDB 允许通过版本化子进程协议接入 `remote`、`pkcs11` 和 `sdf` 私钥托管实现。插件只实现健康检查、公钥读取和对最终 message bytes 的签名；suite 注册、哈希、canonical 编码、domain separation、签名输入构造、Merkle、签名编码校验和公开验签继续由 TrustDB 内置实现唯一决定。

因此本扩展点是“私钥托管 provider 插件”，不是“任意密码算法插件”。不采用 Go `.so`、不加载插件提供的哈希或 verifier，也不允许插件改变证据格式语义。

完整英文协议见 [`formats/SIGNER_PLUGIN_V1.md`](../../formats/SIGNER_PLUGIN_V1.md)。

## 2. 进程与传输边界

- Host 启动独立 executable，并为每个进程生成随机 32-byte cookie；
- child 只监听随机 loopback TCP 端口，以单行、有上限、严格字段的 JSON 完成握手；
- RPC 使用 gRPC 与 canonical CBOR，拒绝未知字段、重复 map key、tag、indefinite length、非 canonical 编码和超限消息；
- 每个 RPC 都携带 cookie metadata，并受内部 deadline 与并发上限约束；
- child 默认不继承应用环境，只复制配置明确列出的变量；协议变量按大小写不敏感方式保留，Windows 由 Go 自动补充启动所需 `SYSTEMROOT`；
- command arguments 在配置诊断中脱敏，但可能被 OS process listing 看到，因此不得携带 credential。

插件 executable 以 TrustDB 的 OS 身份运行，属于部署 TCB。该协议隔离生命周期、依赖和崩溃，不提供 filesystem、network 或 syscall sandbox。

## 3. 精确绑定

启动信息和每个 key RPC 必须精确绑定。`GetPublicKey` 与 `Sign` request 的 `Key` 同时携带 binding 和 provider reference；response 只回显完全相同的 binding 以及公钥或签名输出，provider reference 由同一个 unary RPC request 关联，不在 response 中重复编码：

- protocol version、稳定 plugin ID、provider kind；
- crypto suite、signature algorithm；
- public-key encoding、signature encoding；
- KeyID、固定 SM2 user ID；
- request 中与 `trustdb.key-descriptor.v1` provider union 完全匹配的非秘密 key reference。

描述符先经过完整 canonical 校验，再由 Resolver 精确选择同名 provider。插件只能声明支持能力，不能选择或默认 suite。第一次接受进程后，后续 restart 必须重新校验 identity、capability、health 和所有已解析 key 的公钥；identity 或公钥漂移会永久关闭该 resolver 实例。

## 4. 签名接受规则

插件返回签名后，Host 必须依次完成：

1. response binding 与 request binding 完全相等；
2. suite-defined signature encoding 与长度合法；
3. signature metadata 只从描述符构造；
4. 使用描述符中的公钥和 TrustDB 内置 verifier 验证相同 message bytes。

只有本地验签成功的结果才允许进入 claim、receipt、key event、STH、WAL 派生结果或 proof。正确长度的随机 bytes、其他 key 的签名、重复哈希、不同 domain framing 和 response binding 漂移全部 fail closed。调用方 context 取消不等同于坏签名，不能把 provider 错误标记为 compromised。

AcceptedReceipt 还必须先通过 FIFO sequencer 预留唯一、精确的 WAL position，再在 WAL 全局锁之外并发签名，并按预留顺序发布。前序 reservation 失败或取消时，Host 原子取消并使后继 reservation 失效，后继返回可重试错误；不得自动换位重签，也不得写入未签名 claim 或制造 WAL position gap。若外部设备在取消到达前已经完成后继签名，其审计记录可能包含一个被 Host 丢弃、不会返回或持久化的签名；该情况仅发生在失败级联，不是正常并发路径。

## 5. 生命周期与失败语义

- 一个 provider supervisor 可服务同类 provider 的多个 immutable key adapter；
- 有效签名并发是 host cap 与 plugin advertised cap 的较小非零值；
- `Sign` 失败绝不自动 replay，避免随机签名或外部审计系统出现歧义重复操作；
- transport failure、RPC deadline 或 child exit 使当前 child 失效，后续调用在短 backoff 后可重启；
- request/provider permanent error 不触发 software、其他 plugin、其他算法或默认 suite fallback；
- response protocol violation、identity drift、public-key drift 或本地坏签名进入持久 fail-closed 状态，直到 resolver 被销毁并由 operator 重新启动或修复配置；
- CLI command 与 server 的 resolver 必须覆盖 signer 的完整使用期，并在成功、失败和 shutdown 路径关闭 connection 与 child；Host 先关闭 gRPC connection，在平台支持时发送 OS interrupt 并等待有上限的退出时间，signal 不受支持或超时则强制终止。v1 没有 shutdown RPC，Windows 当前不能通过 `os.Interrupt` 请求优雅退出，因此 adapter 必须能承受进程被直接终止，不能把 HSM/KMS session 一致性仅寄托于 shutdown hook。

## 6. Suite 可用性边界

普通 `ResolveSigner` 仍要求 suite 已获准用于生产证据生成。`ResolveLifecycleSigner` 仅沿用 #556 的已知 suite 例外，使尚未 server-enabled 的 `CN_SM_V1` 可以完成 registry key lifecycle；它不得用于 claim、receipt、STH 或 anchor。插件 provider 自身按 known suite 构造 binding，最终是否允许生产签名由 Resolver 的调用路径决定。

## 7. 兼容性

- 不新增 `provider=plugin`，继续复用 descriptor v1 的 `remote`、`pkcs11`、`sdf` union；
- `.tdclaim`、`.tdproof`、`.tdgproof`、`.tdanchor-result`、`.sproof`、WAL、proofstore、backup 和 API 格式不变；
- software signer 仍是默认 provider；未配置 external provider 时明确返回 unsupported；
- offline verification 从不启动 signer plugin，只依赖公开 trust material 和内置 suite verifier；
- `INTL_V1` 证据 bytes 与既有 golden vector 保持不变。

## 8. 验证 Gate

- canonical CBOR、unknown field、消息/握手大小、cookie 与 loopback negative tests；
- ambient environment 隔离、reserved/case-collision environment tests；
- exact binding、public-key mismatch、protocol violation、invalid signature 和 no-fallback tests；
- deadline、concurrency、child exit、restart identity/public-key rebind 和 shutdown tests；
- CLI runtime subprocess E2E，以及 register/revoke/compromise/rotate lifecycle resolver coverage；
- `go test ./...`、`go vet ./...`、race、integration/E2E 与 Linux/Windows CI gate。
