# L5 外部锚定插件协议 v1

TrustDB 支持把自定义 L5 provider 作为独立 Go 子进程运行。TrustDB 负责
持久化 Pending/InFlight 调度、固定窗口合并、重试、不可变结果存储和 STH
绑定检查；插件只负责发布外部锚点及验证 provider-specific proof。

## 为什么使用子进程

- 插件可以独立构建、发布和升级，不需要重新链接 TrustDB。
- 插件 panic、退出或返回畸形数据不会直接破坏 TrustDB 进程。
- 外部调用失败继续使用现有 durable anchor retry 语义。
- 插件只依赖公共包 `github.com/wowtrust/trustdb/sdk/anchorplugin`，不导入
  `internal/model`。

当前 v1 SDK 使用 loopback gRPC 和确定性 CBOR 消息。启动时 TrustDB 生成
一次性 magic cookie，插件监听随机 loopback 端口，并把一行握手 JSON 写到
stdout；后续每个 RPC 也必须携带该 cookie。stdout 只用于握手；插件日志必须
写 stderr。

## 配置

先构建仓库内的演示插件：

```bash
go build -o ./bin/trustdb-example-anchor-plugin ./examples/anchor-plugin
```

然后在配置中启用：

```yaml
anchor:
  scope: "global"
  max_delay: "5m"
  poll_interval: "2s"
  sink: "plugin"
  plugin:
    command: "./bin/trustdb-example-anchor-plugin"
    args: []
    start_timeout: "10s"
    rpc_timeout: "30s"
```

也可以使用命令行：

```bash
trustdb serve \
  --anchor-sink=plugin \
  --anchor-plugin-command=./bin/trustdb-example-anchor-plugin \
  --anchor-plugin-start-timeout=10s \
  --anchor-plugin-rpc-timeout=30s
```

每个参数使用一个 `--anchor-plugin-arg`。插件继承 TrustDB 进程环境，因此
provider 凭据应通过环境变量、受限权限的配置文件、KMS 或 workload identity
传递，不要放进会被进程列表和日志看到的命令行参数。

## 实现插件

插件实现三个方法：

```go
type Plugin interface {
    Info(context.Context) (anchorplugin.Info, error)
    Publish(context.Context, anchorplugin.SignedTreeHead) (anchorplugin.AnchorResult, error)
    Verify(context.Context, anchorplugin.SignedTreeHead, anchorplugin.AnchorResult) error
}
```

插件还可以选择实现 `anchorplugin.Explorer`，向 TrustDB SDK/Desktop 暴露
只读系统状态以及节点、区块、交易、账户或合约资源。`Info.System` 声明稳定
`system_id`、锚系统种类、可信属性和 capabilities；旧插件不提供该字段时继续
按只有存取证能力的 provider 运行。完整语义和 API 见
[Anchor System Provider v1](ANCHOR_SYSTEM_PROVIDER_V1.md)。

入口调用：

```go
func main() {
    if err := anchorplugin.Serve(context.Background(), myPlugin{}); err != nil {
        log.Fatal(err) // log 默认写 stderr
    }
}
```

`Info` 返回稳定的 `sink_name`。名称必须匹配
`[a-z0-9][a-z0-9._-]*`、长度不超过 64，并且不能冒充 `file`、`noop` 或
`ots`。发布过结果后不要修改名称，否则重启后的插件会被 TrustDB 拒绝。

`Publish` 返回的 provider 字段只有：

- `anchor_id`：外部系统中稳定、可审计的标识；
- `proof`：自描述的 provider-specific 证明字节；
- `published_at_unix_nano`：可选的外部发布时间。

TrustDB 不信任插件返回 STH binding。`node_id`、`log_id`、`tree_size`、
`root_hash` 和完整 signed STH 都由当前 immutable InFlight target 重新填充并
校验后才会落库。

临时网络错误直接返回普通 error；schema 不支持、凭据策略拒绝等重试无效的
错误使用：

```go
return anchorplugin.AnchorResult{}, anchorplugin.Permanent(err)
```

普通错误会使当前子进程失效；durable worker 下次重试时启动一个新进程。
permanent error 会映射到 TrustDB 的 terminal anchor failure。

## 验证

自定义 proof 必须由同名插件的 `Verify` 方法验证。TrustDB 在调用插件前总会
先检查 anchor result 与 GlobalLogProof 中 STH 的 schema、tree size、node、
log 和 root hash 是否精确一致。

本地或远程验证自定义 L5 时传入相同插件：

```bash
trustdb verify \
  --file document.pdf \
  --sproof document.sproof \
  --server-public-key server.pub \
  --client-public-key client.pub \
  --anchor-plugin-command ./bin/my-anchor-plugin
```

`.sproof` 的结构和 immutable binding 可以在没有插件时读取，但自定义 proof
不会因此被认定为 L5。插件缺失、名称不匹配、进程退出或 Verify 拒绝时，验证
均 fail closed。

Go SDK 调用方可以自行启动进程并把它传给验证选项：

```go
process, err := anchorplugin.StartProcess(ctx, anchorplugin.ProcessConfig{
    Command: "./bin/my-anchor-plugin",
})
if err != nil { /* handle */ }
defer process.Close()

result, err := sdk.VerifySingleProof(raw, proof, keys, sdk.VerifyOptions{
    AnchorVerifier: process,
})
```

TrustDB Desktop 在“设置 → L5 锚定插件”中提供相同的 executable、逐行参数、
启动超时和 RPC 超时配置。本地 `.sproof`、拆分证明文件和远程 record 查询在
遇到自定义 sink 时都会使用该插件；内置 `file`、`noop`、`ots` 不启动子进程。

## 安全边界

- 插件 executable 和其依赖属于受信任的部署代码，应使用哈希、签名或软件
  物料清单固定版本。
- gRPC 仅监听 loopback；TrustDB 会拒绝插件声明非 loopback 地址。
- magic cookie 用于确认握手来自本次启动的子进程，不是远程认证机制。
- TrustDB 限制握手和 gRPC 消息大小，但插件仍应限制外部 provider 响应大小。
- 演示插件只生成本地确定性 proof，不增加独立时间语义，不能作为生产 L5
  trust anchor。
