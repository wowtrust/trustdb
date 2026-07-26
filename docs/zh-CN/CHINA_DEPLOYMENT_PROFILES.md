# 国产化生产、离线隔离与测评部署 Profile

TrustDB 除开发、基准和普通单节点生产模式外，新增三个真正改变启动行为的严格
Profile：

| Profile | 模板 | 适用边界 |
| --- | --- | --- |
| `china_production` | `configs/china-production.yaml` | `CN_SM_V1`、不可导出私钥、mTLS/TLCP、显式出站、不可变审计、国密 FISCO BCOS 锚定的在线生产。 |
| `offline_isolated` | `configs/offline-isolated.yaml` | TrustDB 进程完全不发起出站连接的无互联网运行环境，本地继续生成 L4 和离线证据。 |
| `assessment` | `configs/assessment.yaml` | 与国产生产相同的门禁；测评期确需临时例外时，必须审批、限时并写入签名审计。 |

严格 Profile 不是提示标签。TrustDB 会先校验合并后的 YAML，再读取真实服务端/
审计密钥 descriptor 和 canonical FISCO BCOS TrustConfig；全部通过后才打开 WAL、
proofstore 和监听端口。

## 启动时强制检查什么

严格门禁逐项检查：

1. HTTP/gRPC 使用带 client CA 指纹钉扎的 mTLS；或只监听 loopback，并由已验证
   TLCP gateway profile 与 active identity manifest 建立外部国密边界；
2. 不可变安全审计已启用、强制、成功打开，并取得满足时效/漂移要求的可信时间；
3. 服务端与审计签名 descriptor 都是 `CN_SM_V1`，且 provider 不是 `software`；
4. 备份 KEK 不能使用开发用 `passphrase-dev-v1`；
5. 国产生产与测评必须使用 `fisco-bcos` anchor；
6. TrustConfig 必须是 `crypto_mode=guomi`，BCOS 账户不能使用软件私钥，并同时
   提供本地 CA 哈希与 peer 证书指纹钉扎；
7. NATS、TiKV、BCOS、remote signer、BCOS remote account signer 的每个真实端点
   必须与 `deployment_policy.allowed_endpoints` 精确匹配；
8. 使用域名时必须同时列入 `dns_allowlist`；
9. telemetry 与 update check 保持关闭。

任何一项错误都会在接收流量之前停止启动。系统不会静默换回软件密钥、改变
密码套件、使用公共 OTS 池或连接未声明地址。

## 出站与 DNS 如何配置

允许清单必须写成完整的 `scheme://host:port` origin。不接受账号密码、path、
query、通配符、省略端口或域名后缀匹配。remote signer descriptor 可以包含 HTTPS
API path；TrustDB 使用其规范化 HTTPS origin（默认 443）匹配清单，path 不会扩大
网络目的地：

```yaml
deployment_policy:
  egress_mode: "allowlist"
  allowed_endpoints:
    - "gm-tls://10.0.0.20:20200"
    - "gm-tls://10.0.0.21:20200"
    - "https://kms.security.example.cn:443"
  dns_allowlist:
    - "kms.security.example.cn"
  telemetry_enabled: false
  update_checks_enabled: false
  exceptions: []
```

TiKV PD 使用显式的 `tikv://10.0.1.10:2379` 形式。NATS 必须使用 `tls://`、开启
证书校验并配置 CA 文件；严格 Profile 拒绝 `nats://`。
国密 FISCO BCOS TrustConfig 端点使用 `gm-tls://`；`tls://` 属于 standard
模式，会被国产 Profile 的 mode binding 拒绝。

这个清单是应用启动门禁，不替代宿主机防火墙、Kubernetes NetworkPolicy/CNI、
安全组、DNS 策略和出站网关。生产中应把同一目的地址集合下发到这些控制面，并
对 YAML 与网络策略漂移告警。

## 离线隔离模式

`offline_isolated` 强制 `egress_mode: deny_all`、关闭 NATS，只允许 `off`、
`file`、`noop` anchor。它仍强制 `CN_SM_V1`、非软件服务/审计密钥、mTLS 或
受验证 TLCP 边界、安全审计、可信时间和非开发备份 KEK。

这表示运行中的 TrustDB 不发起网络连接。进入隔离区前需要镜像并核验：

- 二进制/容器镜像、checksum、签名、SBOM 与 provenance；
- 操作系统包、基础镜像、Go module 与工具链；
- SDF/PKCS#11 adapter、厂商库、固件、许可证与 recovery bundle；
- CA/CRL、descriptor、registry、可信时间输入和运维手册。

隔离环境仍可生成 L4、导出 `.sproof v2` 并完全断网验证。`off/file/noop`
没有独立外部时间来源，不能宣传成等价于 FISCO BCOS 的 L5。

## 临时例外怎么用

不能通过删除配置项绕过失败。测评例外必须给出受支持的单一 control、原因、
审批人、工单和最长 30 天的 RFC 3339 到期时间：

```yaml
deployment_policy:
  exceptions:
    - id: "CAB-2026-0042"
      control: "server_key_custody"
      reason: "仅用于无生产数据的临时测评 HSM 夹具"
      approved_by: "security-owner@example.cn"
      ticket: "SEC-42"
      expires_at: "2026-08-09T00:00:00Z"
```

control 只能是 `server_crypto_suite`、`audit_crypto_suite`、
`bcos_crypto_mode`、`server_key_custody`、`audit_key_custody`、
`bcos_key_custody`、`server_transport_pins`、`bcos_transport_pins`、
`egress`、`anchor`、`backup_key`。每个 control 只放宽一个相邻边界，避免一次
审批同时绕过多项门禁。字段缺失、ID 重复、未知 control、已经过期或超过
30 天都会失败。TrustDB 在开启监听前，把每个获准例外以
`deployment.policy.exception` 写进签名审计；审计不可用时例外也不可用。

例外只放宽一个技术门禁，不代表通过等保或商用密码应用安全性评估。到期前必须
完成整改、删除例外、重新跑严格配置，并保留审批、审计事件、整改和负向测试。

Admin Web 通用配置接口不能修改 `run_profile` 或 `deployment_policy`（与
`admin`、`audit` 一样受保护）。例外必须通过部署/变更控制流程审查文件并重启，
普通系统配置会话不能关闭严格 Profile 或给自己增加例外。

## 上线步骤

1. 复制最接近的模板，替换所有示例 IP、pin、路径、descriptor、KeyID 和
   TrustConfig。
2. 准备 `CN_SM_V1` 公开 descriptor；服务、审计、备份和 BCOS 账户私钥使用
   SDF、PKCS#11、HSM/KMS 或批准的 remote provider。
3. 创建国密 canonical TrustConfig：至少双 endpoint/read quorum、本地 CA 哈希、
   peer pin、validator、合约 binding 和可信 checkpoint。
4. 使允许端点与所有已启用 provider/服务逐项完全一致；域名另列 DNS 清单。
5. 校验合并配置并查看去敏结果：

   ```bash
   trustdb --config /etc/trustdb/trustdb.yaml config validate
   trustdb --config /etc/trustdb/trustdb.yaml config show
   trustdb --config /etc/trustdb/trustdb.yaml doctor
   ```

6. 先在隔离预生产启动；故意制造策略错误时，进程必须退出且没有监听端口。
7. 提交 canary，达到目标 L4/L5；导出 `.sproof v2`，在断网验证机用独立信任根
   验证。
8. 导出并验证安全审计链/checkpoint；如有例外，核对审计事件与审批单一致。
9. 恢复备份到全新 namespace 并验收后，才允许生产流量进入。

## 必须执行的负向测试

上线审批前，分别修改并确认启动失败：

- 服务或审计 descriptor 从 `CN_SM_V1` 改成 `INTL_V1`；
- 服务、审计或 BCOS 账户 provider 改成 `software`；
- 清空 mTLS client CA pin 或 BCOS peer pin；
- 把任一端点改成未列出的 IP、域名、端口或 scheme；
- 使用未列入 DNS 清单的域名；
- BCOS 从 `guomi` 改成 `standard`；
- 备份 provider 改成 `passphrase-dev-v1`；
- 例外到期时间改成当前或过去；
- 在离线 Profile 开启 NATS、TiKV、FISCO BCOS、OTS 或 remote signer。

把命令、去敏配置 digest、预期错误、执行时间、复核人和发布版本作为测评证据保留。
