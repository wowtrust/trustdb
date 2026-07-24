# 存证状态订阅与刷新通知

TrustDB 为指定 `record_id` 提供轻量实时状态投影，并通过 SSE、预配置
Webhook 或 NATS 发送“需要刷新”的合并通知。通知不携带完整状态历史；上游收到
通知后批量拉取当前状态，因此重复通知、合并通知和短暂丢失都不会改变最终结果。
主动刷新覆盖 `accepted`、`processing`、`retry_pending`、`failed`、`committed`
以及证明等级从 L3 到 L4/L5 的提升。

## 状态查询

单条查询：

```http
GET /v1/records/{record_id}/status
```

批量查询（最多 1000 条）：

```http
POST /v1/records/status:batchGet
Content-Type: application/json

{"record_ids":["tr1...","tr1..."]}
```

状态查询只读取内存中的 L2/处理中投影或 proofstore 的 `RecordIndex` 点键，不加载
完整 `ProofBundle`。

## 预配置上游路由

Webhook URL、NATS subject 和 queue group 只能由管理员在注册或轮换上游密钥时
配置。订阅请求不能提供或覆盖这些值。同一 `tenant_id/client_id` 只有一套路由；
轮换后的所有密钥继续使用相同 subject 和 queue group。

```bash
trustdb key key-register \
  --tenant tenant-a \
  --client upstream-a \
  --key-id upstream-a-key \
  --public-key upstream-a.pub \
  --registry-private-key registry.key \
  --status-webhook-url https://upstream.example/trustdb/status-refresh \
  --status-nats-subject trustdb.status.upstream-a \
  --status-nats-queue-group trustdb-status-upstream-a
```

路由写入 `<key-registry>.status-routes.json` 管理员侧文件（权限 `0600`），不改变
严格的 Key Registry V2 签名证据格式。重复配置相同路由是幂等的，尝试在密钥
轮换时改成另一目标会被拒绝；需要变更路由时应走独立的受控迁移流程。配置完成后
重启 TrustDB 使服务加载新路由。Webhook 通知由 TrustDB server key 签名；NATS
使用同一个签名 CBOR 消息。

## 创建选择性订阅

```http
POST /v1/status-subscriptions
Content-Type: application/json

{
  "tenant_id": "tenant-a",
  "client_id": "upstream-a",
  "key_id": "upstream-a-key",
  "record_ids": ["tr1...", "tr1..."],
  "channels": {"webhook": true, "nats": true},
  "ttl_seconds": 86400,
  "signed_at_unix_nano": 1784870000000000000,
  "nonce": "base64url-random-nonce",
  "signature": {}
}
```

TrustDB 会校验所有 `record_id` 属于该 tenant/client。每个订阅最多 1000 条，TTL
最长 7 天。创建请求必须由对应 client key 签名，时间窗口为 5 分钟；同一签名请求
可安全重试并返回同一个订阅 ID。订阅关系持久化到 proof 目录，服务重启后会主动
补发一次刷新提示。

SSE：

```http
GET /v1/status-subscriptions/{subscription_id}/events
Accept: text/event-stream
```

拉取订阅内全部当前状态：

```http
GET /v1/status-subscriptions/{subscription_id}/statuses
```

删除：

```http
DELETE /v1/status-subscriptions/{subscription_id}
```

## 合并和背压语义

状态变化只把匹配订阅标记为 dirty。默认约 50ms 后发送一次
`trustdb.status-refresh.v1`：

```json
{
  "schema_version": "trustdb.status-refresh.v1",
  "subscription_id": "tss1...",
  "tenant_id": "tenant-a",
  "client_id": "upstream-a",
  "version": 1784870000000000000,
  "refresh_required": true,
  "emitted_at_unix_nano": 1784870000000000000,
  "server_signature": {}
}
```

同一窗口内一条或一百万条状态变化都只形成一个待刷新标记。Webhook/NATS 使用
独立有界 worker；失败采用指数退避并重新标记 dirty，不进入存证提交主链路。
SSE 慢消费者最多保留一个未读提示。

NATS 通知是可合并的唤醒提示，使用既有 TrustDB NATS 连接发布到管理员预配置的
具体 subject。同一后端服务的多个实例加入该上游固定的同一个 queue group，一条提示
只交给其中一个实例处理；不同 queue group 会各收到一份。消费者重连后应立即调用
状态拉取接口，不应把 Core NATS 提示当作持久化事件日志。

当前订阅索引和 SSE 连接属于节点本地状态。单节点部署可直接使用；多节点部署应
对订阅创建、状态拉取和 SSE 使用会话亲和，并确保产生状态变化的节点能把 dirty
提示送到订阅所属节点。后续若接入共享内部事件总线，可去掉这一节点亲和约束。

## Go SDK

```go
sub, err := client.CreateStatusSubscription(ctx, sdk.CreateStatusSubscriptionOptions{
    Identity: sdk.Identity{
        TenantID:   "tenant-a",
        ClientID:   "upstream-a",
        KeyID:      "upstream-a-key",
        PrivateKey: clientPrivateKey,
    },
    RecordIDs: recordIDs,
    Channels: sdk.StatusSubscriptionChannels{
        Webhook: true,
        NATS:    true,
    },
    TTL: 24 * time.Hour,
})

events, streamErrors, err := client.SubscribeStatusRefresh(ctx, sub.ID)
for event := range events {
    if err := sdk.VerifyStatusRefresh(event, serverPublicKey); err != nil {
        continue
    }
    current, err := client.GetStatusSubscriptionStatuses(ctx, sub.ID)
    // 使用 current.Statuses 更新上游数据库。
}
```

Webhook 接收端使用 `sdk.DecodeAndVerifyStatusRefreshJSON` 校验 server signature；
NATS 使用预配置参数加入消费组：

```go
natsEvents, natsErrors, err := sdk.SubscribeNATSStatusRefresh(
    ctx,
    natsConn,
    "trustdb.status.upstream-a",
    "trustdb-status-upstream-a",
    serverPublicKey,
)
```

收到提示后调用同一个批量拉取接口。
