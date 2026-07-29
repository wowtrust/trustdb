# 在线客户端密钥生命周期

TrustDB v2.0.1 可以在不重启单节点 `trustdb serve` 进程的情况下，让审批系统准入新的客户端签名公钥。接口直接修改当前 claim admission 使用的同一份签名追加式 Key Registry V2，不建立第二份缓存，也不接受由 ingest 请求自行携带的“可信密钥”。

## 安全边界

接口挂载在 `admin.base_path` 下，沿用现有 Admin 鉴权方式：

- 带签名的本地密码会话 cookie；
- 直接绑定到管理账号的 mTLS 身份；
- 由固定 mTLS 网关声明的 OIDC 身份。

注册和撤销要求 `key.manage`，查询要求 `key.read`。内置 `key-operator` 角色同时拥有两项权限；`security-admin` 只管理策略，不隐式获得密钥托管权限。

认证、授权、请求路径、方法和结果都会进入不可变安全审计。部署要求审计时，审计写入失败会使操作 fail closed。Admin 子树不是公开 ingest 端点；除明确的本机开发 profile 外，必须使用 TLS 或 mTLS。

## 配置

只有当前客户端信任根为 V2 Key Registry，并且配置了注册表签名 descriptor 时，才能在线修改：

```yaml
paths:
  key_registry: /var/lib/trustdb/keys/clients.tdkeys

registry:
  key_id: registry-key

keys:
  client_public: ""
  registry_private: /run/secrets/registry.key
  registry_public: /etc/trustdb/keys/registry.pub

admin:
  enabled: true
  base_path: /admin
  policy_path: /etc/trustdb/admin-policy.json
  session_secret: ${TRUSTDB_ADMIN_SESSION_SECRET}
```

`registry_private` 与 `registry_public` 必须描述同一 crypto suite、key ID、算法、编码和公钥字节；不一致会阻止启动。省略 `keys.registry_private` 时，claim admission 和历史查询仍然可用，但修改请求返回 `503`。

静态 `keys.client_public` 部署保持原有行为，不会暴露可写注册表。

## 鉴权

本地密码自动化应创建专用 `key-operator` 账号，并建立 cookie jar：

```bash
curl --fail-with-body \
  --cookie-jar trustdb-admin.cookies \
  --header 'Content-Type: application/json' \
  --data '{"username":"proof-mesh-key-operator","password":"..."}' \
  https://trustdb.example/admin/api/session
```

生产集成优先使用直接绑定的 mTLS 账号，或受 pin 约束的 OIDC 网关。密码、会话 cookie 和注册表 signer 必须来自 secret manager，不能写入配置、命令历史或日志。

## 注册密钥

`POST /admin/api/keys`

```json
{
  "tenant_id": "tenant-a",
  "client_id": "chrome-extension:proof-mesh",
  "descriptor": {
    "schema_version": "trustdb.key-descriptor.v1",
    "kind": "verifier",
    "provider": "public",
    "crypto_suite": "CN_SM_V1",
    "key_id": "browser-key-2026-07",
    "algorithm": "sm2-sm3",
    "sm2_user_id": "1234567812345678",
    "public_key": {
      "encoding": "sec1-uncompressed-65-byte-sm2p256v1",
      "bytes": "<base64>"
    }
  },
  "valid_from": "2026-07-29T08:00:00Z"
}
```

接口只接受公开 verifier descriptor，拒绝私钥材料、remote signer credential 和 provider handle。`valid_until` 可选，时间使用 RFC 3339。

完全相同的重试会返回原 sequence 和 event hash，不追加事件。相同 tenant/client/key identity 下如果 descriptor 材料或有效期不同，会返回 `409`；轮换必须使用新的 `key_id`。

## 查询密钥

`GET /admin/api/keys/{tenant_id}/{client_id}/{key_id}?at=<RFC3339>`

省略 `at` 时使用服务器当前时间。撤销之后仍可查询撤销前的历史时点；查询等于或晚于撤销时点时返回 `409`，表示该密钥在目标 admission 时刻无效。

## 撤销密钥

`POST /admin/api/keys/{tenant_id}/{client_id}/{key_id}/revoke`

```json
{
  "revoked_at": "2026-07-29T09:00:00Z",
  "reason": "tenant administrator revoked browser key"
}
```

生效时间进入签名注册表事件。完全相同的撤销即使很久以后重试，也会幂等返回原事件。

新的在线撤销可以在服务器当前时间或未来生效；超过五秒的过去时间会被拒绝，防止集成系统回溯撤销 TrustDB 已经接受的 claim，并导致重启时的确定性 WAL replay 失败。生效时点及之后收到的新 claim 会被拒绝；之前接受的 record 仍可按历史注册表状态验证。

## 验收清单

- 使用专用 `key-operator` 完成鉴权，并确认无权限账号返回 `403`。
- 注册真实客户端公钥，提交由对应私钥签名的 claim，确认达到 L2。
- 重放完全相同的注册，确认 sequence 与 event hash 不变。
- 设置未来撤销时间，确认生效前 claim 可接受、生效后返回 `FAILED_PRECONDITION` / `HTTP 412`。
- 重放完全相同的撤销，确认不追加事件。
- 重启 TrustDB，确认注册、撤销和历史 accepted record 的结果保持不变。
- 导出安全审计，核对 actor、权限、路径、方法、对象和结果。

## 多副本约束

在线 API 立即更新处理该请求的进程，因此单二进制或单 TrustDB Compose 服务可直接使用。

NATS + TiKV 多副本部署不能把密钥管理请求随机发送到任意节点。每个接收 claim 的副本必须先观察并验证同一条有序、受鉴权、可重放的注册表事件流，达到同一 sequence 后才能通过 readiness 并接收流量。落后或无法验证事件的副本必须摘流。

在部署具备这条控制面之前，使用运维人员受控的注册表发布流程，并通过全副本重启与 readiness 屏障完成一致性切换。
