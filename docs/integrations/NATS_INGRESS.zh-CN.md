# 可选 NATS / JetStream 存证入口

[English](NATS_INGRESS.md)

当生产者需要在 TrustDB 前增加耐久缓冲、多对一汇聚或由消息系统控制的
流量分发时，可以选择通过 NATS JetStream 提交 signed claim。该入口默认
关闭；无论是否启用 NATS，HTTP 和 gRPC 都保持可用。

NATS 只改变 signed claim 到达 TrustDB 的方式，不改变 claim、WAL、batch、
proof、Global Log、anchor 或离线验证语义。

## 两种确认不能混淆

整个链路有两个不同的耐久边界：

1. JetStream publish acknowledgement 只说明请求已写入 NATS ingress stream，
   不代表 TrustDB 已接受存证。
2. accepted result 才表示 TrustDB 完成签名与密钥状态校验，并跨过正常 WAL
   acceptance 边界。它报告 L2，并携带与 HTTP/gRPC 相同的 server record 和
   accepted receipt。

服务端必须先持久化结果，再确认原 ingress delivery。因此只要结果仍在
配置的 retention 窗口内，调用方即使遇到超时、断连或进程重启，也能恢复
同一个不可变结果。

```text
生产者
   |
   | 发布 SignedClaim request
   v
TRUSTDB_INGRESS（work-queue stream）
   |
   | durable pull consumer，受 MaxAckPending 限制
   v
TrustDB 共用 submission service -> 签名/密钥校验 -> WAL acceptance
   |                                      |
   | accepted 或终态失败                  | 非法 broker delivery
   v                                      v
TRUSTDB_INGRESS_RESULTS                 TRUSTDB_INGRESS_DLQ
   |
   | 先持久化不可变结果
   v
ACK / 终止原 ingress delivery
```

## 适用场景

下列情况适合启用 NATS ingress：

- 多个生产者需要通过共享耐久缓冲汇聚到一个 TrustDB 服务；
- 生产者无法在整个 acceptance 等待期间持续连接 TrustDB；
- 需要由 broker 吸收有界突发流量，同时让 TrustDB 对下游施加背压；
- broker account、subject 和 stream limit 是部署隔离与路由模型的一部分。

如果单个应用可以直接调用 HTTP 或 gRPC，则不必启用 NATS。公开的
`NATSIngressClient` 只负责写入；record 查询、proof 导出、Global Log
证据和 anchor 读取仍使用 HTTP/gRPC 的普通 `sdk.Client`。

## 默认关闭边界

生成的配置包含完整 `nats` 段，默认值为：

```yaml
nats:
  enabled: false
```

当 `enabled` 为 `false` 时，`trustdb serve` 不连接 NATS、不创建或检查
JetStream 资源、不启动 NATS worker，也不改变 HTTP/gRPC 行为。只有显式
开启后，其余 NATS 字段才产生运行时效果。

## 本地验证

下面的 broker 适合一次性本地演练，不是加固后的 broker 配置：

```bash
docker volume create trustdb-nats-data
docker run --rm --name trustdb-nats \
  -p 127.0.0.1:4222:4222 \
  -v trustdb-nats-data:/data \
  nats:2 -js -sd /data
```

如果部署还没有配置文件，先生成当前完整配置：

```bash
./bin/trustdb config init --out ./trustdb.yaml
```

保留原本可运行的 server、key、WAL 和 proofstore 设置，至少修改生成的
NATS 段为：

```yaml
nats:
  enabled: true
  urls: ["nats://127.0.0.1:4222"]
  provision: true
```

启动前验证最终合并配置：

```bash
./bin/trustdb --config ./trustdb.yaml config validate
./bin/trustdb --config ./trustdb.yaml serve
```

启动成功时，TrustDB 会记录 ingress stream、durable consumer、result
stream、dead-letter stream、最终 worker 数量和每 worker fetch batch。
broker 不可达或已有资源语义不匹配时，启动会失败关闭。

## 拓扑与 provision

默认拓扑包含三个相互独立的 stream 和一个 durable consumer：

| 资源 | 默认值 | 必须满足的语义 |
| --- | --- | --- |
| Ingress stream | `TRUSTDB_INGRESS` | 对具体 `trustdb.ingress.v1.claims` subject 使用 work-queue retention、`DiscardNew`、有界字节/消息大小和配置的 duplicate window。 |
| Durable consumer | `trustdb-ingress` | 显式 ACK、instant replay、精确 subject filter，以及配置的 `AckWait`、`MaxDeliver`、`MaxAckPending`、request batch 和 expiry。 |
| Result stream | `TRUSTDB_INGRESS_RESULTS` | 对 `trustdb.ingress.v1.results.*` 使用 limits retention；每个结果 subject 只能保存一条不可变消息，并启用 `DiscardNewPerSubject`。 |
| Dead-letter stream | `TRUSTDB_INGRESS_DLQ` | 对 `trustdb.ingress.v1.dlq.*` 使用 limits retention；每个 rejection subject 只能保存一条不可变消息，并启用 `DiscardNewPerSubject`。 |

`nats.provision: true` 时，TrustDB 会创建缺失资源，但不会静默改写已有
stream 或 consumer；所有关键字段都会被校验，不兼容拓扑会阻止启动。

`nats.provision: false` 时，四个资源必须预先存在，并与配置精确一致。
该模式适合由独立运维或基础设施流程管理 broker 拓扑的环境。

Go SDK 从不创建、更新或删除 broker 资源，只会打开并校验配置的 ingress
和 result stream。

## 配置说明

使用 `trustdb config init` 生成当前版本的完整 schema。以下按运维用途说明
各字段。

### 连接、认证与 TLS

| 字段 | 含义 |
| --- | --- |
| `enabled` | 开启可选传输，默认 `false`。 |
| `urls` | 一个或多个 `nats://`、`tls://`、`ws://` 或 `wss://` endpoint。禁止在 URL 中携带认证信息或 query secret。 |
| `connect_timeout` | 首次连接建立上限。 |
| `reconnect_wait` | 重连间隔。 |
| `max_reconnects` | 最大重连次数；`-1` 表示不限制。 |
| `drain_timeout` | 关闭时 drain 的时间上限。 |
| `credentials_file` | NATS credentials 文件；与用户名/密码、token 互斥。 |
| `username`、`password` | 必须同时设置，并与其他认证模式互斥。 |
| `token` | Token 认证，与其他认证模式互斥。 |
| `tls.enabled` | 强制配置 TLS；设置任意 TLS 文件或 server name 也会启用 TLS 配置。 |
| `tls.ca_file` | 额外 PEM CA bundle。 |
| `tls.cert_file`、`tls.key_file` | mTLS 客户端证书与私钥，必须成对配置。 |
| `tls.server_name` | 期望的服务端证书名称。 |
| `tls.insecure_skip_verify` | 显式关闭证书校验；除隔离测试外应保持 `false`。 |

部署 secret 优先使用 `TRUSTDB_NATS_CREDENTIALS_FILE`、
`TRUSTDB_NATS_USERNAME`、`TRUSTDB_NATS_PASSWORD` 或
`TRUSTDB_NATS_TOKEN` 等环境变量。认证模式互斥，不要把凭据写入
`nats.urls` 或提交到仓库配置文件。

### Stream 容量与保留

| 字段 | 含义 |
| --- | --- |
| `stream`、`subject`、`durable` | ingress stream、精确 publish subject 和 durable consumer identity。 |
| `provision` | `true` 时创建缺失拓扑；`false` 时只校验。 |
| `stream_storage` | `file` 表示 broker 重启后保留；`memory` 表示有意使用易失存储。 |
| `stream_replicas` | JetStream 副本数，范围 1 到 5；broker 集群必须支持所选数量。 |
| `stream_max_bytes`、`stream_max_age` | ingress backlog 边界。`0s` 只表示不按时间过期，字节上限仍生效。 |
| `result_stream`、`result_subject` | 每请求不可变结果 stream，以及以 `.*` 结尾的 subject pattern。 |
| `result_max_bytes`、`result_max_age` | 结果恢复窗口。默认 age 为 `24h`；结果过期后 `WaitResult` 无法恢复。 |
| `dlq_stream`、`dlq_subject` | 非法 delivery 的不可变 stream，以及以 `.*` 结尾的 subject pattern。 |
| `dlq_max_bytes`、`dlq_max_age` | Dead-letter 保留边界。 |
| `duplicate_window` | JetStream publish 去重窗口。TrustDB 还会核对已存不可变 outcome，因此即使丢失 outcome publish ACK，超过该窗口后重试仍不会覆盖既有结果。 |

三个 stream 都使用 `DiscardNew`。Ingress stream 达到边界时，生产者的
publish 会失败，必须把它当作背压。Result 或 DLQ stream 达到边界时，
TrustDB 无法耐久保存 outcome，因此不会 ACK 原 ingress delivery，并持续
重试 outcome write。任何路径都不会静默删除旧不可变结果，也不会绕过配置
上限让内存或磁盘无界增长。

### Worker、流控与重试

| 字段 | 含义 |
| --- | --- |
| `workers` | Pull loop 数量。`0` 会根据 `GOMAXPROCS`、`fetch_batch` 和 `max_ack_pending` 自动取有界值；显式值也受 `max_ack_pending` 限制。 |
| `fetch_batch` | 配置的最大 pull request batch。必要时每 worker 会取得更小份额，确保总客户端 buffer 有界。 |
| `fetch_wait` | Pull expiry 与最大空闲等待，至少 `1s`。 |
| `ack_wait` | Broker ACK deadline。处理期间 TrustDB 会持续发送 progress heartbeat。 |
| `max_ack_pending` | Durable consumer 同时未确认 delivery 的上限。 |
| `nak_delay` | 可重试 submission 失败后的 redelivery 延迟。 |
| `max_deliver` | 达到该 delivery 次数后，合法请求会得到不可变终态失败结果。 |
| `outcome_retry_wait` | result 或 dead letter 持久化失败后的重试间隔；持久化成功前不会 ACK 原 ingress delivery。 |

Worker 不会再增加第二个进程内消息队列。JetStream durable consumer 与
`MaxAckPending` 限制分发量，共用 TrustDB submission service 则继续使用与
HTTP/gRPC 相同的阻塞式队列背压。

## Go SDK 接入

固定到包含 `NATSIngressClient` 的 release 或 commit。评估当前尚未发版的
代码树时可使用：

```bash
go get github.com/wowtrust/trustdb@main
```

应用通常先通过现有签名链路生成 `sdk.SignedClaim`，再选择同步或可恢复
两种方式。

### 同步发布并等待

```go
cfg := sdk.DefaultNATSIngressConfig()
cfg.URLs = []string{"tls://nats.internal.example:4222"}
cfg.ConnectionOptions = []nats.Option{
    nats.UserCredentials("/run/secrets/trustdb-nats.creds"),
    nats.RootCAs("/etc/trust/nats-ca.pem"),
}

client, err := sdk.NewNATSIngressClient(ctx, cfg)
if err != nil {
    return err
}
defer client.Close()

result, err := client.SubmitSignedClaim(ctx, signed)
if err != nil {
    return err
}
fmt.Printf("record=%s level=%s\n", result.RecordID, result.ProofLevel)
```

### 先发布，稍后恢复结果

```go
submission, err := client.PublishSignedClaim(ctx, signed)
if err != nil {
    return err
}

// 返回上层调用方前，把 submission.MessageID 与 submission.SignedClaim
// 一起写入应用自己的耐久状态。

result, err := client.WaitResult(ctx, submission)
```

`WaitResult` 会重新校验 handle 是否仍指向原始 signed claim。它先订阅精确
结果 subject，再读取耐久 snapshot，因此无需轮询即可同时覆盖“结果早已
存在”和“结果恰好在查询期间提交”两种情况。SDK 会拒绝 subject、header、
schema、message ID、body 不匹配，以及可变 result stream 配置。

`NATSSubmission` 是 Go value，不是新的 TrustDB 证据格式。若需要跨进程
恢复，应用必须耐久保存两个字段并防止被修改；不能仅凭不可信 message ID
重新拼装 handle。

服务端拒绝以 `*sdk.Error` 返回，可用 `errors.As` 检查。连接、publish、
lookup 和 wait 都遵守 context cancellation/deadline。`Close` 可重复调用，
并执行有上限的 NATS drain。

经过编译检查的公开 API 示例位于
[`sdk/example_test.go`](../../sdk/example_test.go)，完整 embedded JetStream
生命周期测试位于 [`sdk/nats_ingress_test.go`](../../sdk/nats_ingress_test.go)。

## 重试、重复与失败语义

- 完全相同的 signed claim 会得到同一个确定性 request ID。JetStream 可能
  把再次发布标记为 duplicate，但调用方仍可恢复同一不可变结果。
- subject、header、schema、message ID 或 CBOR body 非法时，TrustDB 先把
  原始 delivery 完整写入不可变 DLQ，再终止原 delivery。
- 合法请求遇到可重试 TrustDB 失败时，会按 `nak_delay` NAK；达到
  `max_deliver` 后保存终态 error result。
- Invalid argument、与 TrustDB 状态冲突的 duplicate、data-loss 分类不会
  无限重试。
- 成功或终态失败都必须先持久化精确 result，之后才能 ACK。Result store
  失败会持续重试，并让原 ingress delivery 保持未确认。
- 关闭期间未完成的 delivery 保持未确认，重启后由同一 durable consumer
  继续处理。

## Broker 权限

TrustDB server 和 SDK producer 应使用不同 broker identity。

TrustDB server 需要检查配置拓扑、消费并 ACK durable ingress consumer、
发布不可变 result 和 dead-letter subject 的权限。`provision=true` 时还
需要创建三个 stream 和 durable consumer 的权限。

SDK producer 需要检查 ingress/result stream、只发布具体 ingress subject、
订阅自己请求对应的精确 result subject、通过 JetStream API 读取该 subject
最后一条消息，以及使用 NATS inbox 接收 request/reply ACK。它不需要
consumer 管理、stream 更新/删除或 DLQ 权限。

具体 NATS ACL 语法取决于 broker account 与部署方式。放量前必须同时做
一次 publish-and-wait 和一次 stored-result recovery 测试，验证最终账号。

## 运维与排障

需要同时观察 TrustDB 与 JetStream：

- TrustDB 启动日志应包含 `optional NATS ingress started`，并显示预期的
  stream、consumer、result stream、DLQ stream 和 worker sizing。
- Broker stream state 用于观察 ingress 积压和 result/DLQ retention 压力。
- Durable consumer state 用于观察 pending、redelivery 和 unacknowledged
  delivery。
- 重复出现 `NATS ingress worker delivery error` 必须调查，可能来自
  submission 失败、broker 中断或 outcome store 压力。
- Worker 异常退出会让 `trustdb serve` 失败；应先确认 broker 或拓扑原因，
  再重启服务。

TrustDB 通过现有 `/metrics` endpoint 暴露进程内 NATS ingress 指标。所有
label 都是固定枚举，不包含 message ID、subject、客户端身份或错误文本。

| 指标 | 含义 |
| --- | --- |
| `trustdb_nats_ingress_in_flight` | 当前正在执行 worker 状态机的 delivery，不包含 broker backlog。 |
| `trustdb_nats_ingress_deliveries_total{action}` | 成功完成的 broker 动作：`ack`、`nak`、`term_result` 或 `term_rejection`。 |
| `trustdb_nats_ingress_outcome_store_retries_total{kind}` | 在确认原 delivery 前，耐久 result 或 rejection 写入失败并准备重试的次数。 |
| `trustdb_nats_ingress_errors_total{stage}` | `consume`、`process` 或 `ack_progress` 阶段的 worker error。 |

`nak` 速率持续上升通常表示下游暂时性压力；broker 健康但 outcome store
retry 上升时，应检查 result/DLQ 容量和存储可用性。Error counter 非零时，
需要结合日志和 JetStream state 确认精确原因。

常见问题：

| 现象 | 处理方式 |
| --- | --- |
| Broker connection refused | 检查 endpoint、监听地址、网络策略、凭据和 TLS server name。NATS 已开启时会失败关闭。 |
| `provision=false` 且 stream/consumer 缺失 | 通过 broker 管理流程创建精确拓扑，或在获得权限的 bootstrap 阶段临时开启 provision。 |
| Existing resource incompatible | 按错误逐项比较。TrustDB 不会自动修改已有资源。 |
| 能 publish 但不能 wait | 补齐 result stream info/read、精确 result subject subscribe 和必要 inbox reply 权限。 |
| 延迟调用方返回前结果已消失 | 提高 `result_max_age` 和/或 `result_max_bytes`，并在计划变更中创建兼容拓扑；不匹配旧资源会被拒绝。 |
| Ingress publish 因容量失败 | 将其视为背压，降低生产速率或提高经过评估的有界 stream 容量，不要改为无界保留。 |

## 证据与备份边界

JetStream ingress message、NATS result 和 dead letter 属于传输状态，不是
`.sproof` 证据，也不包含在 TrustDB 逻辑 `.tdbackup` 中。Claim 被接受后，
L2-L5 处理和 proof 导出全部使用正常 TrustDB store。Broker 数据应根据
所选 JetStream storage 与 replication 策略单独保全和备份。
