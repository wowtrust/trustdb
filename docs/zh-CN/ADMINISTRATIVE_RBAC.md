# 管理 RBAC、三员分立与紧急恢复

TrustDB 使用版本化的 `trustdb.admin-policy.v1` 管理所有高权限身份。它替代旧的
Admin Web 单用户名/单密码模型，同时保护 Admin Web 和可选的本地 CLI。策略文件
仅允许属主访问，每次更新都会保存不可变的上一版本历史。

这套控制只约束运维权限，不改变记录、Merkle 树、STH、锚定、备份和离线证明语义。

## 1. 角色与权限

| 角色 | 职责 | 权限范围 |
| --- | --- | --- |
| `system-admin` | 系统管理员 | 系统读取、配置和运行维护 |
| `security-admin` | 安全管理员 | RBAC/信任策略、会话管理，兼具系统只读 |
| `audit-admin` | 审计管理员 | 审计读取/导出、策略只读、系统只读 |
| `key-operator` | 密钥操作员 | 密钥读取和生命周期操作 |
| `backup-operator` | 备份恢复操作员 | 备份读取、创建和恢复 |
| `anchor-governor` | 锚定治理员 | 锚定读取/发布、信任材料只读 |
| `support-readonly` | 支持人员 | 系统、密钥、备份、锚定和信任只读 |
| `emergency-admin` | 封存的紧急账号 | 仅在有限时间内拥有全部权限 |

普通账号不能同时拥有系统、安全、审计三类管理员中的多个角色；合法策略必须始终
各有一个处于有效状态的非紧急账号。因此安全管理员能修改高风险策略，但不能删除
或批准独立审计材料；系统本身也不提供删除策略历史的接口。

## 2. 首次引导

Linux/macOS：

```bash
export TRUSTDB_ADMIN_BOOTSTRAP_SYSTEM_PASSWORD='替换为系统管理员密码'
export TRUSTDB_ADMIN_BOOTSTRAP_SECURITY_PASSWORD='替换为安全管理员密码'
export TRUSTDB_ADMIN_BOOTSTRAP_AUDIT_PASSWORD='替换为审计管理员密码'

trustdb --config /etc/trustdb/production.yaml admin policy bootstrap \
  --out /etc/trustdb/admin-policy.json
```

Windows PowerShell：

```powershell
$env:TRUSTDB_ADMIN_BOOTSTRAP_SYSTEM_PASSWORD = '替换为系统管理员密码'
$env:TRUSTDB_ADMIN_BOOTSTRAP_SECURITY_PASSWORD = '替换为安全管理员密码'
$env:TRUSTDB_ADMIN_BOOTSTRAP_AUDIT_PASSWORD = '替换为审计管理员密码'

.\trustdb.exe --config C:\TrustDB\production.yaml admin policy bootstrap `
  --out C:\TrustDB\admin-policy.json
```

生产环境优先使用对应的 `*_PASSWORD_FILE`，三个口令应分开保管。命令只创建
version 1，目标已存在时拒绝覆盖，并在结构化输出和日志中记录执行引导的操作系统
身份。随后执行：

```bash
export TRUSTDB_ADMIN_ACTOR=security-admin
export TRUSTDB_ADMIN_PASSWORD="$TRUSTDB_ADMIN_BOOTSTRAP_SECURITY_PASSWORD"
trustdb admin policy validate --file /etc/trustdb/admin-policy.json
trustdb admin policy inspect --file /etc/trustdb/admin-policy.json
```

`inspect` 只显示 `<configured>`，不会打印 bcrypt 校验值。

## 3. 配置与启停

```yaml
admin:
  enabled: true
  base_path: "/admin"
  policy_path: "/etc/trustdb/admin-policy.json"
  session_secret: "替换为至少32字节随机值"
  web_dir: "/opt/trustdb/admin"
  cookie_secure: true
  session_ttl: "8h"
  login_max_failures: 5
  login_lockout: "15m"
  cli_enforce: true
  oidc_gateway_spki_sha256: []
```

- `enabled` 只控制 Admin Web；设为 `false` 并重启即可关闭网页，不影响核心 API。
- `cli_enforce` 独立控制高权限 CLI。生产模板默认开启，策略缺失、权限不安全或格式
  错误都会拒绝命令。
- 通用 YAML 编辑接口禁止修改整个 `admin` 区块，防止系统管理员绕过安全管理员。
- session v2 绑定账号 ID、角色、session epoch、策略版本和 digest；任意策略更新都会
  使旧会话失效。
- Cookie 使用 HttpOnly、SameSite=Strict；HTTPS 下必须开启 `cookie_secure`。

## 4. Admin Web 与身份接入

服务端按接口检查权限，而不是“登录后全放行”：系统查看需要 `system.read`，保存
YAML 需要 `system.configure`，策略查看/更新分别需要
`security.policy.read/write`。前端会显示当前角色并禁用无权按钮，但最终边界始终在
服务端。

当前公开 gRPC 只包含提交、证据查询和健康检查，没有管理变更接口；后续若增加管理
gRPC，必须先复用同一权限常量和传递 actor 的拦截器，未接入鉴权前不得注册。

本地密码登录预留 MFA 验证器接口；账号设置 `mfa_required=true` 后，验证器缺失或
失败都会 fail closed。标准二进制只接受来自 mTLS 身份网关的 OIDC 头，网关证书
SPKI 必须列在 `oidc_gateway_spki_sha256`，并由网关先验证 JWT 签名、issuer、
audience、时效、nonce 和 MFA 声明。未 pin 客户端和裸身份头都会拒绝。直接 mTLS
账号则绑定自身证书 SPKI 的 SHA-256。

## 5. CLI 授权

Linux/macOS：

```bash
export TRUSTDB_ADMIN_ACTOR=backup-operator
export TRUSTDB_ADMIN_PASSWORD_FILE=/run/secrets/trustdb-backup-operator
trustdb --config /etc/trustdb/production.yaml backup create ...
```

PowerShell：

```powershell
$env:TRUSTDB_ADMIN_ACTOR = 'backup-operator'
$env:TRUSTDB_ADMIN_PASSWORD_FILE = 'C:\TrustDB\secrets\backup-operator.txt'
.\trustdb.exe --config C:\TrustDB\production.yaml backup create ...
```

`TRUSTDB_ADMIN_PASSWORD` 与 `TRUSTDB_ADMIN_PASSWORD_FILE` 只能二选一。服务启动、
配置、密钥、备份恢复、WAL 修复/导出、存储迁移、锚定、Global Log 压缩和 FISCO
BCOS TrustConfig 变更都在命令执行前统一鉴权，并记录 actor、permission、command
和 emergency 状态。要求 MFA 的账号不能使用内置本地密码 CLI 钩子，应通过已认证
的管理服务完成操作。

## 6. 在线修改策略

1. 安全管理员登录后 GET `/admin/api/security/policy`，保存响应的 `ETag`。
2. 将 `version` 严格加一；账号按 `id` 排序，角色和身份绑定也要有序且不重复。
3. PUT 完整 JSON，并发送 `If-Match: "<digest>"`。

在线修改者不能修改自己的账号、系统/审计管理员托管关系或紧急账号；普通操作员和
只读支持身份仍可在线增删改。这样安全策略修改者不能悄悄接管系统或审计权限。自身
账号由另一位安全管理员处理，系统/审计及紧急托管变更必须进入离线恢复。旧版本会保存到：

```text
<policy_path>.history/v00000000000000000001-<sha256>.json
```

当前策略使用原子替换；digest 过期时返回冲突，不会覆盖并发修改。

## 7. 紧急账号与离线恢复

紧急账号只能拥有 `emergency-admin`，必须设置 `emergency=true`，并提供 UTC 的
`not_before/not_after`，有效窗口不得超过 24 小时。Web、mTLS、OIDC 紧急访问必须
给出 12–512 字符理由；CLI 还要求 `TRUSTDB_ADMIN_EMERGENCY_REASON`。

紧急账号只能通过受控离线恢复创建或轮换：

```bash
export TRUSTDB_ADMIN_EMERGENCY_REASON='已批准事故单 INC-2026-0042 的恢复操作'
trustdb admin policy recover \
  --file /etc/trustdb/admin-policy.json \
  --replacement /secure/reviewed-policy-vNEXT.json \
  --expect-current-digest <当前digest> \
  --offline-recovery
```

Windows PowerShell：

```powershell
$env:TRUSTDB_ADMIN_EMERGENCY_REASON = '已批准事故单 INC-2026-0042 的恢复操作'
.\trustdb.exe admin policy recover `
  --file C:\TrustDB\admin-policy.json `
  --replacement C:\TrustDB\reviewed-policy-vNEXT.json `
  --expect-current-digest <当前digest> `
  --offline-recovery
```

替换文件必须是合法的下一版本，历史仍会保留。应停止管理入口，在受控终端双人复核，
并把命令输出、前后策略和事故单一并归档。命令会记录操作系统 actor 和必填恢复理由。

## 8. 锁定、会话与恢复演练

- 连续失败达到 `login_max_failures` 后，用户名被锁定 `login_lockout`；到期后正确
  登录自动恢复，不能通过删除服务状态解锁。
- 禁用账号、变更角色、递增 `session_epoch` 或安装任意新策略都会使旧会话失效。
- 全部在线管理员失效时，关闭 Admin Web，离线确认当前 digest，使用 `policy recover`
  安装下一版本，再启动并验证旧会话已失效。
- 禁止原地编辑当前文件、删除 `.history`、降低版本号，或把证据签名私钥放进管理策略。

上线前必须覆盖：横向/纵向越权、会话到期、角色变更、锁定和解锁、mTLS SPKI、
OIDC/MFA 失败、过期 If-Match、自修改拒绝、紧急理由和到期、离线恢复、历史保留。
