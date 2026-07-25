# 不可变安全审计与可信时间证据

TrustDB 为高权限控制面操作维护独立的安全审计链。它不属于普通应用日志、
Prometheus 指标、业务 record、WAL 或 `.sproof`，用途是变更追责、事件调查、
分权复核和跨主机连续性检查。

生产模式下，只要审计签名器、受保护存储、审计链或强制同步时间不可用，
TrustDB 就拒绝继续执行高权限操作。只要审计存储仍可写，时间不同步造成的
拒绝会先写入一条 `result=blocked` 的签名事件，再向调用方返回错误。

本功能不声称本机系统时间、NTP 样本或 FISCO BCOS 区块时间等同于具有法律
效力的可信时间戳。TrustDB 只固化进程当时观察到的时间来源、偏移、不确定度、
同步状态和置信等级；需要法定时间戳时仍应接入独立、受治理的外部服务。

## 1. 它能保证什么

每条事件都采用 canonical CBOR 编码、签名，并引用上一条事件哈希：

- `INTL_V1` 使用 Ed25519 + SHA-256；
- `CN_SM_V1` 使用 SM2 + SM3；
- 序号断裂、事件篡改、重排、错误签名、截断，以及相对最新签名 checkpoint
  的回滚都会被拒绝；
- context key 中包含 `password`、`secret`、`token`、`private`、
  `credential`、`cookie`、`authorization`、`payload` 或 `content` 时，
  值会在签名前强制改成 `<redacted>`；
- break-glass 原因只记录 SHA-256 摘要，审计链和普通结构化日志都不保存原文；
- Unix 文件必须归当前进程用户所有且 mode 为 owner-only，父目录不得允许
  group/other 写入；Windows 使用受保护 DACL，只给进程 owner 一个完全访问 ACE；
- 单进程稳定追加使用签名 checkpoint 的 O(1) 快路径；导出先固定已签名的
  字节长度快照，再释放跨进程写锁，因此慢速导出不会长时间阻塞在线写入。

事件字段包括 actor、roles、action、object、result、request ID、source、
policy version、本地时间、可信时间状态、保留截止时间和有界脱敏 context。
审计签名器可使用 software、remote、PKCS#11 或 SDF descriptor；指定 provider
不可用时直接失败，不会回退到其他密钥。

## 2. 哪些操作会被审计

CLI 在操作执行前写入授权意图，完成后写入结果。主要 action 包括：

| action | 覆盖内容 |
| --- | --- |
| `security.policy.*` | RBAC bootstrap、读取、更新、离线恢复 |
| `key.lifecycle` | 生成、注册、轮换、撤销、compromise、rewrap |
| `backup.*` | 创建、验证、恢复 `.tdbackup` |
| `anchor.configuration` | Anchor 配置和管理 |
| `trust.configuration` | FISCO BCOS TrustConfig 创建、validator checkpoint 推进 |
| `system.configuration` | 系统配置变更 |
| `system.operation` | 服务启停和高权限维护 |
| `audit.*` | 状态检查、完整导出、checkpoint 导出 |

Admin HTTP 会记录登录成功/失败、认证与授权拒绝、授权意图、请求结果、退出、
策略替换和配置替换。强制审计写入失败时，会在签发 session 或进入已授权 handler
之前返回 HTTP 503。通用配置接口禁止修改 `admin` 和 `audit` 配置块。

服务启停和监听证书 reload 失败也会入链。请求来源只保存摘要，不保存原始 IP。

## 3. 准备审计签名密钥

在开启 required audit 前先创建独立审计身份。审计密钥不能复用 client/server
业务证明签名密钥。下面是本地 `CN_SM_V1` 开发或离线测试方式。

### Linux / macOS

```bash
mkdir -p .trustdb-audit-key
read -r -s -p 'Audit key passphrase: ' TRUSTDB_DEV_KEY_PASSPHRASE
printf '\n'
export TRUSTDB_DEV_KEY_PASSPHRASE
./bin/trustdb key generate \
  --suite CN_SM_V1 \
  --out .trustdb-audit-key \
  --prefix audit
unset TRUSTDB_DEV_KEY_PASSPHRASE
```

### Windows PowerShell

```powershell
# 仅用于可丢弃测试；Windows 生产使用 SDF/PKCS#11/remote descriptor。
New-Item -ItemType Directory -Force .trustdb-audit-key | Out-Null
.\bin\trustdb.exe key generate `
  --suite CN_SM_V1 `
  --out .trustdb-audit-key `
  --prefix audit `
  --protection plaintext-dev-v1
```

`--out` 是本地输出目录。结果包括 `audit.key`（signer descriptor）、
`audit.pub`（public verifier descriptor）和 `audit.material`（私钥材料）。
PowerShell 示例使用 `plaintext-dev-v1`，只是因为 Windows 软件 envelope 持久化
当前会 fail closed；它只能用于可丢弃测试。生产环境应改用经过准入的 SDF、
PKCS#11、HSM/KMS 或 remote descriptor。

把 `audit.pub` 通过独立渠道交给审计验证方并纳入其本地 trust store。导出文件
虽然会携带匹配公钥，但文件自带公钥永远不能自行成为信任根。

## 4. 提供时间参考文件

`require_synchronized_time: true` 时，本机 time-monitor agent 必须在
`time_max_sample_age` 到期前原子刷新受保护 JSON。agent 必须从组织批准的时间源
计算字段，不能把 `synchronized: true` 写成固定值。

```json
{
  "schema_version": "trustdb.time-reference.v1",
  "source": "chrony-ntp-auth",
  "sampled_at_unix_nano": 1785037200000000000,
  "offset_nanos": 12000000,
  "uncertainty_nanos": 8000000,
  "synchronized": true,
  "confidence": "authenticated"
}
```

`confidence` 支持 `authenticated`、`network`、`hardware`、`local`。
`local` 永远按 `unverified` 处理，不能满足生产强制同步。最终状态可能是：
`synchronized`、`stale`、`drift-exceeded`、`unsynchronized`、
`unavailable`、`invalid` 或 `unverified`。

未来时间、`abs(offset)+uncertainty` 超限、JSON 非法、权限不安全、文件缺失都会
在强制模式下 fail closed。更新时必须在同目录创建新的 owner-only 文件、fsync，
再原子替换目标，不能直接原地改写。time monitor 与 TrustDB 的运行用户/ACL 模型
必须满足安全文件检查。

## 5. YAML 配置

`configs/production.yaml` 已提供生产基线：

```yaml
audit:
  enabled: true
  required: true
  path: "/var/lib/trustdb/audit/security.audit"
  checkpoint_path: "/var/lib/trustdb/audit/security.checkpoint"
  signing_key: "/etc/trustdb/keys/audit.tdkey"
  max_bytes: 4294967296
  retention: "4380h"
  time_reference_path: "/run/trustdb/time-reference.json"
  time_max_sample_age: "2m"
  time_max_drift: "5s"
  require_synchronized_time: true
```

`single_node_production` 强制要求 `enabled`、`required` 和
`require_synchronized_time` 全部开启。log 与 checkpoint 路径不能相同；
`max_bytes` 至少 1 MiB，`retention` 至少 24 小时。

每条事件都会签入 retention deadline。TrustDB 不会静默删除或自动轮转审计历史。
达到 `max_bytes` 后所有需要审计的操作都会被阻止。必须提前扩容或在审批后提高
`max_bytes`，不能删除当前 log/checkpoint 来“恢复服务”。

## 6. 日常检查、导出和完全离线验证

检查在线审计链：

```bash
./bin/trustdb --config /etc/trustdb/trustdb.yaml audit status
```

导出完整 JSONL：

```bash
./bin/trustdb --config /etc/trustdb/trustdb.yaml audit export \
  --out /secure-export/trustdb-audit-2026-07-26.jsonl
```

验证时不访问 TrustDB、provider 或网络：

```bash
./bin/trustdb audit verify \
  --file /secure-export/trustdb-audit-2026-07-26.jsonl \
  --public-key /verifier-trust/audit.pub
```

导出并验证轻量签名 checkpoint：

```bash
./bin/trustdb --config /etc/trustdb/trustdb.yaml audit checkpoint export \
  --out /secure-export/trustdb-audit-checkpoint-2026-07-26.json

./bin/trustdb audit checkpoint verify \
  --file /secure-export/trustdb-audit-checkpoint-2026-07-26.json \
  --public-key /verifier-trust/audit.pub
```

建议把周期 checkpoint 放入独立 WORM/Object Lock 存储，或者把其精确字节/摘要
交给组织批准的外部时间戳或 anchor 流程，并把外部 receipt 一并留存。TrustDB
不会自动把这类 receipt 宣称成法定可信时间戳。

一次 export 固定快照时已经包含允许本次导出的授权意图；export 命令最终结果在
快照完成后入链，因此会出现在下一次导出中。

## 7. 容量、备份和恢复

按峰值而不是平均值估算：

```text
所需字节 = 峰值事件数/天 × 实测事件字节数 × 保留天数 × 安全系数
```

默认 4 GiB、`4380h`（182.5 天）约等于每天 23.5 MiB。若平均每条编码后 2 KiB，
未计安全余量时约为每天 12,000 条。登录攻击同样会产生审计事件，因此必须把失败
请求纳入估算，并同时监控磁盘剩余空间、审计文件增长和 `max_bytes` 余量。

`.tdbackup v5` 不能替代安全审计备份。业务 proofstore 使用 `trustdb backup`；
审计侧另外保留 JSONL、签名 checkpoint、可信 `audit.pub`、time-monitor 配置和
外部 anchor receipt。执行 restore 会产生审计事件，但不会覆盖目标环境自己的
安全审计历史。

## 8. 故障处置

| 报错/现象 | 处理方式 |
| --- | --- |
| `audit rollback or truncation detected` | 立即停止高权限操作，逐字节保全 log/checkpoint/lock，与独立保管的最新 checkpoint 比对并调查。禁止 truncate、删除或重建。 |
| `unsafe storage` | 修复 owner、mode/DACL、父目录可写权限、symlink 或文件类型；不要通过替换证据来掩盖问题。 |
| `configured audit capacity exhausted` | 保留完整链，扩磁盘并审批提高 `max_bytes` 后重启；禁止删除 checkpoint 或尾部。 |
| `trusted time requirement is not satisfied` | 修复 time monitor/时间源，原子刷新 reference，检查 age、offset、uncertainty、confidence、权限和 schema。存储可用时，被阻止的尝试已经入链。 |
| 签名或公钥不匹配 | 只使用独立分发的 `audit.pub`，精确匹配 suite、KeyID、算法、编码和公钥 bytes；异常换钥按安全事件处理。 |

如果攻击者能够同时回滚审计 log、本地 checkpoint、全部备份以及所有独立保管的
checkpoint，纯本地验证器无法证明被删除的历史曾经存在。因此，跨主机独立保管
checkpoint 是突破单机信任边界后检测回滚的必要条件。
