# Anchor System Provider v1

## 1. 目标

TrustDB 把下游 L5 provider 包裹为统一的锚系统语义，同时严格区分两类数据：

- `STHAnchorResult` 是不可变 L5 证据，必须与同一个 SignedTreeHead 精确绑定并执行 sink-specific 验证；
- `AnchorSystemStatus` 和 `AnchorSystemResource` 是实时发现与浏览数据，不参与证明等级判定。

因此，节点在线、同步完成或区块高度增长都不能把一份未验证的证明提升到 L5；反过来，provider 暂时离线也不会降低已经形成的不可变 L5 证据。

## 2. 锚系统种类

| Kind | 语义 | 典型能力 |
| --- | --- | --- |
| `timestamp_evidence` | 仅存证或时间证据系统，例如 OpenTimestamps | 发布、取证、验证 |
| `evidence_blockchain` | 无真实账户与合约的存证区块链 | 节点、区块、交易、同步、出块 |
| `full_blockchain` | 完整区块链 | 节点、区块、交易、账户、合约 |

`kind` 只提供粗粒度分类。调用方必须按 `capabilities` 判断具体功能，不能假定所有完整区块链都允许 TrustDB 持有账户私钥或部署合约。

## 3. 稳定描述

`AnchorSystem` 使用 `trustdb.anchor-system.v1`：

- `system_id`：一个配置实例的稳定 ID；未来同一链可以注册多个实例；
- `sink_name`：与 `STHAnchorResult.sink_name` 的精确关联；
- `kind`、`network`、`provider`：系统分类和网络身份；
- `capabilities`：版本化能力字符串；
- `assurance`：独立时间、公开可验证性、去中心化、终局性和托管边界；
- `metadata`：有界的 provider-specific 描述字段。

`assurance` 是展示和策略输入，不替代证明验证。

## 4. 能力

### 4.1 证据能力

- `anchor.publish`
- `anchor.verify`
- `evidence.read`

### 4.2 只读控制面

- `system.status.read`
- `node.read`
- `block.read`
- `transaction.read`
- `account.read`
- `contract.read`

### 4.3 特权操作能力

以下能力已保留在公共模型中，但 v1 公共 HTTP/gRPC API 不执行这些操作：

- `data.sync`
- `block.produce`
- `transaction.send`
- `contract.call`
- `contract.deploy`

在开放这些能力前，服务端必须具备明确的 RBAC、凭据隔离、请求审批/限速和不可变审计事件。只声明 capability 不构成执行授权。

## 5. 实时状态与资源

`AnchorSystemStatus` 使用 `trustdb.anchor-system-status.v1`，包含：

- `state`：`healthy`、`degraded`、`unavailable` 或 `unknown`；
- `observed_at_unix_nano`：provider 产生快照的时间；
- `message` 和 `details`：同步高度、节点数量、延迟等有界摘要。

`AnchorSystemResource` 使用 `trustdb.anchor-system-resource.v1`，支持：

- `node`
- `block`
- `transaction`
- `account`
- `contract`

公共字段包括 ID、parent、hash、状态、高度、时间和摘要；`attributes` 保存 provider-specific 字符串字段。列表调用必须分页，单页最多 1000 项。

服务端在转发结果前校验：

1. system ID 与所请求 provider 一致；
2. resource kind 与请求一致；
3. resource ID 非空；
4. provider 已声明对应 `*.read` capability；
5. 返回页大小不超过请求 limit。

## 6. 公共 API

HTTP：

```text
GET /v1/anchor-systems
GET /v1/anchor-systems/{system_id}
GET /v1/anchor-systems/{system_id}/status
GET /v1/anchor-systems/{system_id}/resources?kind=&limit=&cursor=
GET /v1/anchor-systems/{system_id}/resources/{kind}/{resource_id}
```

gRPC 提供等价的：

```text
ListAnchorSystems
GetAnchorSystem
GetAnchorSystemStatus
ListAnchorSystemResources
GetAnchorSystemResource
```

Go SDK 在 HTTP、gRPC 和多 endpoint transport 上暴露一致方法。

## 7. 插件兼容性

Anchor Plugin 协议版本仍为 `trustdb.anchor-plugin.v1`：

- 旧插件继续只实现 `Info`、`Publish`、`Verify`；
- `Info.System` 是可选字段；缺失时 TrustDB 将插件描述为只有证据能力的 `timestamp_evidence`；
- 新插件可选实现 `anchorplugin.Explorer`；
- `GetStatus`、`ListResources`、`GetResource` 是同一 loopback gRPC 服务上的新增可选 RPC；
- 不支持 Explorer 的插件对这些 RPC 返回 `Unimplemented`，不会影响发布与验证。

TrustDB 在插件重启后要求 `sink_name` 和 `system_id` 保持稳定。

## 8. 当前实现边界

v1 首个实现按当前单 sink 配置暴露一个 provider，但服务层和 API 使用 system ID 注册表，允许后续扩展为多 provider。内置 `noop`、`file`、`ots` 使用静态描述；外部插件可以提供动态状态和资源。

仓库中的 `examples/anchor-plugin` 演示 `evidence_blockchain`，将已发布 STH 映射为内存区块和交易。它没有独立时间或生产级持久性，不能作为生产信任锚。
