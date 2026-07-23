# ADR-0003：国密依赖、实现边界与一致性向量

> 状态：Accepted
>
> 日期：2026-07-23
>
> 关联 Issue：[#443](https://github.com/wowtrust/trustdb/issues/443)
>
> 依赖：[`ADR-0001`](ADR-0001-CRYPTOGRAPHIC-SUITES.zh-CN.md)、[`ADR-0002`](ADR-0002-CRYPTO-AGILITY-FORMATS.zh-CN.md)
>
> 机器可读向量：`test/vectors/cn-sm-v1-conformance.json`
>
> 自动验证：`internal/smconformance`

## 1. 决策摘要

TrustDB 选择 [`github.com/emmansun/gmsm`](https://github.com/emmansun/gmsm) `v0.44.0` 作为 `CN_SM_V1` 的纯 Go 软件实现与一致性参考实现。版本、模块校验和与上游 tag 对应提交全部固定；核心 Server、CLI、Go SDK 和离线验证器继续支持 `CGO_ENABLED=0`，不得为了国密算法把本地动态库隐式带入证据生成或验证进程。

该依赖获准用于开发、测试、软件公钥验签和后续 provider 实现，不等于 TrustDB 或该开源库已经成为经检测认证的商用密码产品。中国生产 Profile 的长期私钥、服务端签名密钥和备份 KEK 仍必须由适用且经批准的 HSM、SDF 设备或 KMS provider 持有；开源软件实现不能替代部署方应完成的产品选型、密钥仪式、密评或认证判断。

[`GmSSL`](https://github.com/guanzhi/GmSSL) 和 [`Tongsuo`](https://github.com/Tongsuo-Project/Tongsuo) 作为独立互操作与边界实现：GmSSL 用于命令行/实验室 oracle，Tongsuo 用于 TLCP gateway 和协议互操作评估。它们不得直接通过 CGO 链接进 TrustDB 核心进程。若未来需要原生库能力，应放入版本固定、最小权限、可替换的 sidecar 或 gateway，并以协议 contract 隔离崩溃、ABI、内存安全和升级风险。

`CN_SM_V1` 仍保持 `reserved`。本 ADR 只批准依赖、参数和向量，不启用生产套件，不改变当前证据字节，也不提供 v1 兼容代码。后续实现直接进入 [`ADR-0002`](ADR-0002-CRYPTO-AGILITY-FORMATS.zh-CN.md) 定义的破坏性 V2/V5 代际。

## 2. 候选依赖矩阵

以下版本是 2026-07-23 的批准基线。升级任何批准依赖都必须重新运行全部向量、负向测试、跨实现测试、性能测试和许可证检查，不能只让 Dependabot 合并版本号。

| 候选 | 固定版本 | 许可证 | 运行形态 | amd64 / arm64 | 决策 | 理由与边界 |
| --- | --- | --- | --- | --- | --- | --- |
| [`emmansun/gmsm`](https://github.com/emmansun/gmsm) | [`v0.44.0`](https://github.com/emmansun/gmsm/releases/tag/v0.44.0) | [MIT](https://github.com/emmansun/gmsm/blob/v0.44.0/LICENSE) | 纯 Go；核心进程内 | Go 支持的平台；发布 Gate 仍需逐平台 CI | **Approved** | SM2/SM3/SM4 API 完整、无需 CGO、适合确定性构建和 Go provider；用于软件/reference 路径，不作为认证声明或生产私钥边界 |
| [`GmSSL`](https://github.com/guanzhi/GmSSL) | [`v3.2.0`](https://github.com/guanzhi/GmSSL/releases/tag/v3.2.0) | Apache-2.0 | 独立 CLI、容器或实验室 oracle | 按独立制品矩阵验证 | **Approved external** | 提供独立实现交叉验证和生态互操作；原生 ABI、进程内内存安全、制品来源与 CGO 会扩大核心 TCB，因此不链接到核心 |
| [`Tongsuo`](https://github.com/Tongsuo-Project/Tongsuo) | [`8.4.0`](https://github.com/Tongsuo-Project/Tongsuo/releases/tag/8.4.0) | Apache-2.0 | 独立 TLS/TLCP gateway | 按 gateway 制品矩阵验证 | **Approved external** | 适合 TLCP、证书和网关互操作；不承担 TrustDB proof engine 的 canonical crypto 实现 |
| [`tjfoc/gmsm`](https://github.com/tjfoc/gmsm) | [`v1.4.1`](https://github.com/tjfoc/gmsm/releases/tag/v1.4.1) | Apache-2.0 | 纯 Go | 未进入本项目矩阵 | **Rejected for new code** | 最新 release 基线较旧，维护与 API 演进风险高于已选实现；不为“第二实现”把它引入生产依赖图 |
| 自研 SM2/SM3/SM4 | 不适用 | 不适用 | 核心进程内 | 不适用 | **Rejected** | 算法实现不是 TrustDB 的产品差异点；自研会增加侧信道、边界条件、互操作和审计风险 |
| 未固定版本的系统 OpenSSL/LibreSSL | 系统提供 | 依发行版 | 外部命令 | 按系统 | **Test oracle only** | 只用于 CI/开发交叉验证；不得参与生产证据生成，不得让系统升级改变 TrustDB 的密码语义 |

### 2.1 固定的 Go 模块身份

| 项目 | 固定值 |
| --- | --- |
| Module | `github.com/emmansun/gmsm` |
| Version | `v0.44.0` |
| Tag commit | `6a288945c6d670dc90c1d101d00c9bd97780866f` |
| Module sum | `h1:QAg/Xuha84+AUPFIe7T8Ly4S8z54+UPwpBnHS8Y8Ubc=` |
| `go.mod` sum | `h1:CHti5ihGbTOI0pCtdoC8HLjBxGFktH/ksbpsCgsCzkQ=` |
| TrustDB minimum build mode | 核心算法路径必须通过 `CGO_ENABLED=0` 构建和测试 |

不得使用未提交的 `replace`、分支名、浮动伪版本或关闭 checksum database 的方式替换该依赖。中国离线构建可以把已批准 module zip、`go.mod` 和校验和同步到境内受控镜像，但镜像内容必须与 `go.sum` 一致。

## 3. 密码与认证边界

### 3.1 可以在软件边界内完成的工作

- SM3 内容摘要、签名输入摘要、record ID 和 RFC6962-SM3 Merkle 运算；
- 使用本地受信任公钥进行 SM2 验签；
- 测试、开发和明确标为非生产 Profile 的临时软件密钥；
- 由离线验证器复算证据文件中的摘要、Merkle path、ZA 和签名；
- SM4-GCM envelope 的格式验证与解密，但生产 KEK/解包操作仍由 provider 控制。

### 3.2 必须保留在外部受控边界的工作

- 中国生产 Profile 的客户端、服务端、STH、Anchor 发布者长期私钥；
- 备份 DEK 的 KEK、KEK 轮换和高权限解包操作；
- 需要产品/模块检测认证结论的密码运算；
- 国密证书私钥、双证书、吊销状态与 TLCP 终止；
- 具体 HSM/SDF/KMS 厂商的密钥生成、导入、备份、销毁和审计。

TrustDB 后续通过 provider-neutral contract 调用这些能力。provider 必须返回可验证的公钥、KeyID、算法和签名，不允许把不可审计的“签名成功”布尔值当作证据。离线验证永远只依赖验证者本地 trust roots 和证据文件，不调用 HSM、KMS、CA、GmSSL、Tongsuo 或网络服务。

## 4. `CN_SM_V1` canonical vectors

机器可读文件 `test/vectors/cn-sm-v1-conformance.json` 是 Server、SDK、CLI、Desktop、离线 verifier、provider adapter 和外部互操作工具的共同基线。字段和值一经被 production V2 格式引用，只能通过新 suite 或新格式代际改变。

### 4.1 SM2

向量采用 GB/T 32918.5 标准示例，并与 OpenSSL 的 [`sm2_internal_test.c`](https://github.com/openssl/openssl/blob/master/test/sm2_internal_test.c) 交叉核对：

| 参数 | 固定值 |
| --- | --- |
| Curve | `sm2p256v1` |
| User ID | UTF-8/ASCII `1234567812345678`，16 bytes |
| ZA | `b2e14c5c79c6df5b85f4fe7ed8db7a262b9da7e07ccb0ea9f4747b8ccda8a4f3` |
| Message | UTF-8 `message digest` |
| `SM3(ZA || M)` | `f0b43e94ba45accaace692ed534382eb17e6ab5a19ce7b31f4486fdfc0d28640` |
| Signature encoding | 严格 ASN.1 DER `SEQUENCE(INTEGER r, INTEGER s)` |

验证测试同时确认：显式 canonical user ID 与空参数所表示的 canonical default 得到相同 ZA；修改 user ID、消息或签名后失败；raw `r || s`、尾随字节和非 DER 输入失败。业务代码不得允许 SDK 自定义默认 user ID；需要其他身份参数时必须定义新 suite。

### 4.2 SM3 与 Merkle domain

向量覆盖：

- 标准 `abc` 和 `abcd` 重复 16 次的已知答案；
- one-shot 与不规则分块 streaming 结果相同；
- 空树根 `SM3("")`；
- leaf `SM3(0x00 || payload)`；
- node `SM3(0x01 || left[32] || right[32])`。

`0x00` 和 `0x01` 是 Merkle domain prefix，不是可配置参数。任何去掉 prefix、把字符串十六进制文本当原始字节、调换左右节点或把 SHA-256 输出误当 SM3 的实现都必须被 golden vector 拒绝。

### 4.3 SM4-GCM envelope

标准单块向量固定 SM4 primitive，并包含一百万次连续加密结果。V2 envelope 固定：

| 参数 | 固定值 |
| --- | --- |
| Algorithm | `SM4-GCM` |
| Key | 128 bit DEK |
| Nonce | 96 bit；在同一 DEK 下绝不重复 |
| Authentication tag | 128 bit；禁止截短 |
| Sealed bytes | `ciphertext || tag` |
| AAD string encoding | UTF-8 |
| AAD framing | 每个字段使用 2-byte big-endian unsigned length，随后原始字段字节 |
| AAD fields | domain、suite、object type、tenant、KeyID、context，顺序固定 |

canonical domain 是 `trustdb.sm4-envelope.v2`。向量的完整 AAD、nonce、plaintext 与 sealed bytes 已固定在 JSON 中。实现必须在解密前从可信上下文重建并精确比较 AAD；不能相信 envelope 自带字段来降低调用方预期。AAD、ciphertext 或 tag 任一 bit 改变都必须认证失败。

禁止 ECB 保护业务数据，禁止未认证 CBC/CTR，禁止固定/计数器回绕 nonce，禁止在恢复或并发重试时重复 `(key, nonce)`。生产实现应使用密码学安全随机生成的 96-bit nonce，并持久记录已分配值、拒绝同一 key 下的重复值；若后续选择确定性 nonce，必须单独 ADR 证明其在并发、恢复、备份复制和 key rotation 下的唯一性。

## 5. 独立实现与互操作 Gate

当前自动测试执行以下两层验证：

1. 使用固定的 `emmansun/gmsm v0.44.0` 验证全部 SM2、SM3、SM4 和 SM4-GCM 向量。
2. 若系统存在 `openssl`，使用独立 OpenSSL/LibreSSL 命令重新计算 SM3 与 SM4 单块结果；CI 的 Ubuntu runner 必须实际通过而不是依赖生产代码生成 expected bytes。

SM2 标准签名取自标准参数并与 OpenSSL 上游测试源交叉核对。`CN_SM_V1` 从 `reserved` 变为 `available` 前，还必须增加至少一条可重复的 GmSSL 或 Tongsuo SM2/证书互操作 Gate，并覆盖：

- canonical user ID、ZA、DER 编码；
- 公钥/证书导入导出；
- 高位 INTEGER、非最短 DER、零/负数/越界 `r,s`；
- 错误 curve/OID、错误 user ID 和错误摘要；
- linux/amd64 与 linux/arm64；
- Go SDK、Server、CLI/Desktop 和完全断网 verifier 读取同一向量。

外部命令只产生对照结果，不能在测试失败或工具缺失时回退为 production verifier。正式 release Gate 应提供固定 GmSSL/Tongsuo 容器 digest，避免系统包升级导致 oracle 漂移。

## 6. 供应链与漏洞响应

### 6.1 每次依赖升级必须执行

1. 检查上游 release、tag/commit 身份、许可证和安全公告。
2. 更新精确 module version 和 `go.sum`，执行 `go mod verify` 与 `go mod tidy` 后确认无隐式依赖漂移。
3. 运行 `go vet ./...`、全部 Go/race/integration/E2E Gate、国密向量和外部 oracle。
4. 比较 SBOM，确认没有意外新增 CGO、动态库、网络下载、汇编平台缺口或许可证变化。
5. 重新验证 linux/amd64、linux/arm64 和 release 制品的 `CGO_ENABLED=0` 构建。
6. 由 Security & Cryptography owner 审查后再合并；密码依赖不得仅凭自动合并策略进入 release。

### 6.2 漏洞处理

- Dependabot、GitHub Advisory、Go vulnerability database、上游 advisory 和 release SBOM 是发现入口，不是风险结论本身。
- 命中项必须判断实际调用路径、私钥边界、验签/解析影响、可利用输入和受影响制品；不能仅以“未发现公开 CVE”批准依赖。
- 涉及签名伪造、私钥泄露、认证绕过、越界解析或远程代码执行时，按 `SECURITY.md` 使用 private vulnerability reporting，不在公开 Issue 暴露利用细节。
- 修复只进入最新稳定版和 `main`；如上游未修复，可以临时禁用受影响 provider、固定安全 commit 或替换实现，但所有偏离 release tag 的操作必须有期限明确的风险记录和可复现 patch。

本项目不虚构固定响应 SLA；确认、修复和披露时限按漏洞严重性、可复现性和 release 复杂度执行，并在安全通告中给出受影响版本与可操作缓解措施。

## 7. 后续实现约束

- #445 的 hash abstraction 必须显式选择 suite，不能用全局默认 hash。
- #446 的持久 marker 和 #447 的 V2 model 必须在任何密码运算前绑定 `CN_SM_V1`。
- SM2 signer/provider、SM3 Merkle、SM4 envelope、证书/TLCP 和 BCOS adapter 必须复用本向量，不得各自复制一套默认参数。
- `CN_SM_V1` 启用 PR 必须删除对应的 `reserved` gate，并同时证明 V2/V5 全链路、离线验证、备份恢复和跨架构互操作完整；不能通过配置开关提前启用半套算法。
- 切换前格式不是同一个统一版本号：model、evidence、`.sproof`、WAL、HTTP/gRPC 和 SDK 当前主要使用 v1，proofstore keyspace 与逻辑备份当前使用 v4。国产 V2/V5 路线不为这些旧格式保留双读、自动迁移或回退代码；正式切换时停止旧服务、清空或移走旧数据目录，并以新 `LogID` 和新 namespace 初始化。逻辑备份能力不会删除，而是由只读写新格式的 backup v5 直接替换 backup v4。

## 8. 决策后果

正向结果：

- 核心保持纯 Go、跨平台和可复现，不把 native ABI 扩散到整个 TCB；
- 所有组件共享同一机器可读向量，避免 SM2 user ID、DER、Merkle prefix 和 SM4 AAD 漂移；
- 开源算法实现、硬件密钥边界、TLCP 网关和认证结论彼此分离，部署方可以明确采购与测评责任；
- V2 破坏性切换不需要维护旧算法/格式兼容分支。

代价与限制：

- 生产签名必须额外实现和验证 HSM/SDF/KMS provider；
- GmSSL/Tongsuo 的制品 pin、跨架构 CI 和证书互操作仍是启用 Gate；
- 依赖升级比普通业务库更严格，需要重新确认字节级输出与供应链边界。
