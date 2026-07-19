# TrustDB

![CI](https://github.com/ryan-wong-coder/trustdb/actions/workflows/ci.yml/badge.svg)

[官方网站](https://ryan-wong-coder.github.io/trustdb-website/) | [English README](README.md) | [贡献指南](CONTRIBUTING.md) | [`.sproof` 格式](formats/SPROOF_V1.md)

TrustDB 是一个面向文件存证和证明交换的可验证证据数据库。它把本地文件哈希转换为客户端签名声明、服务端持久化收据、批次 Merkle 证明、Global Transparency Log 证明，以及可选的外部 Signed Tree Head（STH）锚定结果。

文档、快速开始、版本发布和反馈渠道统一维护在 [TrustDB 官方网站](https://ryan-wong-coder.github.io/trustdb-website/)。

![TrustDB 系统架构](assets/readme/system-architecture.png)

当前 Go module：

```text
github.com/ryan-wong-coder/trustdb
```

许可证：AGPL-3.0-only，见 [LICENSE](LICENSE)。

## v1.0.0-beta

首个公开测试版通过 [GitHub Releases](https://github.com/ryan-wong-coder/trustdb/releases/tag/v1.0.0-beta) 发布，其中包括 Linux、macOS、Windows 两种架构的服务器与 CLI 归档，Apple Silicon、Intel Mac、Windows ARM64、Windows x86-64 四种桌面客户端，以及统一的 `SHA256SUMS`。

Go SDK 使用同一个 module tag：

```bash
go get github.com/ryan-wong-coder/trustdb@v1.0.0-beta
```

Docker Hub 同步发布 amd64 与 arm64 镜像；测试版不会占用 `latest`：

```bash
docker pull wsy19990317/trustdb:1.0.0-beta
docker run --name trustdb -p 8080:8080 -v trustdb-data:/var/lib/trustdb wsy19990317/trustdb:1.0.0-beta
```

桌面包使用本次发版临时生成的自签名证书，并附带公开 `.cer` 文件。自签名可以校验安装包是否被改动，但不会取得 Apple 或 Microsoft 的系统信任；Gatekeeper 或 SmartScreen 仍可能提示未知开发者。安装前请先核对 `SHA256SUMS`。

## 能力概览

- 使用确定性 CBOR 表达 claim、receipt、proof bundle、global-log proof、STH、anchor result、backup 和 `.sproof` 文件。
- 支持客户端、服务端和 key registry 的 Ed25519 签名。
- WAL-backed ingest：有界队列、可配置 fsync、replay、checkpoint 和优雅关闭。
- Batch Merkle proof、持久化 record index、分页 record/root API。
- Global Transparency Log：持久化 STH、inclusion proof、consistency proof 和 history tile。
- L5 STH/global-root 锚定：支持 `off`、`noop`、本地文件和 OpenTimestamps sink。
- Proofstore 支持 file、Pebble 和 TiKV；TiKV 可用于多计算节点共享持久证明数据，实现存算分离。
- `.tdbackup` 便携备份：创建、校验、带 checkpoint 的可恢复 restore。
- Go SDK：claim 签名、HTTP/gRPC 调用、证明导出、本地验证。
- Wails + Vue 桌面客户端：本地身份、文件存证、记录管理、proof refresh、`.sproof` 导出和离线验证。
- 可选 Vue Admin Web：由 `trustdb serve` 挂载，用于 metrics、只读浏览和受控 YAML 配置维护。
- React + Vite 官网源码：位于 `website`，与主仓库一起构建和校验，并使用 GSAP 实现动态证明信号与滚动叙事。

## 证明等级

![TrustDB 证明等级](assets/readme/proof-levels.png)

| 等级 | 含义 | 主要产物 |
| --- | --- | --- |
| L1 | 客户端对包含内容哈希和元数据的 claim 签名。 | `SignedClaim` / `.tdclaim` |
| L2 | 服务端校验 claim，并在 WAL 持久化边界内接受。 | `AcceptedReceipt` |
| L3 | accepted claim 被提交进 batch Merkle tree。 | `ProofBundle` / `.tdproof` |
| L4 | batch root 已进入 Global Transparency Log，并能证明包含于目标 STH。 | `GlobalLogProof` / `.tdgproof` |
| L5 | 对应 STH/global root 已被外部 anchor sink 锚定。 | `STHAnchorResult` / `.tdanchor-result` |

桌面客户端和交换场景推荐使用 `.sproof` 单文件证明。它可以包含 L3 `ProofBundle`、可选 L4 `GlobalLogProof` 和可选 L5 `STHAnchorResult`。稳定 v1 格式见 [formats/SPROOF_V1.md](formats/SPROOF_V1.md)。

## 架构

TrustDB 默认可按单节点服务运行。启用 TiKV proofstore 后，多个 TrustDB 计算节点可以共享同一份持久证明数据，并通过 `node_id` 和 `log_id` 保留来源身份。

核心路径：

- Client path：CLI、SDK 或桌面客户端计算文件哈希，签名 claim，并提交到本地或服务端。
- Ingest path：服务端校验签名和 key 状态，写入 WAL durable boundary，返回 accepted receipt。
- Batch path：accepted records 被聚合成 Merkle batch，存储 proof bundle 和索引。
- Global log path：committed batch roots 被追加到 global transparency log，生成持久化 STH 和 global proof。
- Anchor path：STH/global roots 入队后由 anchor worker 按配置发布。
- Storage path：proof 数据可落到 file、Pebble 或 TiKV proofstore。
- Backup path：proofstore 数据可导出为 `.tdbackup`，支持 verify 与带 checkpoint 的 restore。
- Observability path：`/metrics` 暴露 ingest、batch、global log、anchor、WAL、backup、storage 等指标。

## 快速开始

生成客户端和服务端密钥：

```powershell
go run ./cmd/trustdb keygen --out .trustdb-dev --prefix client
go run ./cmd/trustdb keygen --out .trustdb-dev --prefix server
```

启动本地开发服务：

```powershell
go run ./cmd/trustdb serve `
  --config configs/development.yaml `
  --server-private-key .trustdb-dev/server.key `
  --client-public-key .trustdb-dev/client.pub `
  --listen 127.0.0.1:8080
```

创建并签名文件 claim：

```powershell
go run ./cmd/trustdb claim-file `
  --file .\example.txt `
  --private-key .trustdb-dev/client.key `
  --tenant default `
  --client local-client `
  --key-id client-key `
  --out .trustdb-dev/example.tdclaim
```

把 claim 本地提交为 proof bundle：

```powershell
go run ./cmd/trustdb commit `
  --claim .trustdb-dev/example.tdclaim `
  --server-private-key .trustdb-dev/server.key `
  --client-public-key .trustdb-dev/client.pub `
  --out .trustdb-dev/example.tdproof
```

验证本地文件和 proof：

```powershell
go run ./cmd/trustdb verify `
  --file .\example.txt `
  --proof .trustdb-dev/example.tdproof `
  --server-public-key .trustdb-dev/server.pub `
  --client-public-key .trustdb-dev/client.pub
```

验证推荐的 `.sproof` 单文件证明：

```powershell
go run ./cmd/trustdb verify `
  --file .\example.txt `
  --sproof .trustdb-dev/example.sproof `
  --server-public-key .trustdb-dev/server.pub `
  --client-public-key .trustdb-dev/client.pub
```

创建并校验便携备份：

```powershell
go run ./cmd/trustdb backup create `
  --metastore file `
  --metastore-path .trustdb-dev/proofs `
  --out .trustdb-dev/trustdb.tdbackup

go run ./cmd/trustdb backup verify --file .trustdb-dev/trustdb.tdbackup
```

## HTTP 和 gRPC

已实现 HTTP endpoints：

| Endpoint | 用途 |
| --- | --- |
| `GET /healthz` | 健康检查。 |
| `POST /v1/claims` | 提交 signed claim。 |
| `POST /v1/claims/batch` | 提交 CBOR signed claim 批量。 |
| `GET /v1/records` | 分页 record 列表和搜索。 |
| `GET /v1/records/{record_id}` | 读取 record index 详情。 |
| `GET /v1/proofs/{record_id}` | 获取 L3 proof bundle。 |
| `GET /v1/roots` | 列出 batch roots。 |
| `GET /v1/roots/latest` | 获取最新 batch root。 |
| `GET /v1/sth/latest` | 获取最新 SignedTreeHead。 |
| `GET /v1/sth/{tree_size}` | 获取指定 tree size 的 STH。 |
| `GET /v1/global-log/inclusion/{batch_id}` | 获取 batch 的 global-log inclusion proof。 |
| `GET /v1/global-log/consistency?from=&to=` | 获取 global-log consistency proof。 |
| `GET /v1/anchors/sth/{tree_size}` | 获取 STH anchor 状态或结果。 |
| `GET /metrics` | Prometheus metrics。 |

可选 gRPC listener 通过 `--grpc-listen` 或 `server.grpc_listen` 开启。gRPC 复用 TrustDB 确定性 CBOR payload model，因此 HTTP 和 gRPC transport 不改变证明语义。

## 配置

配置示例在 [configs](configs)：

| 文件 | 用途 |
| --- | --- |
| `configs/development.yaml` | 本地开发和演示；file proofstore、`noop` anchor。 |
| `configs/production.yaml` | 单节点生产基线；Pebble proofstore、directory WAL、group fsync、global log、OTS anchor。 |
| `configs/benchmark-extreme.yaml` | 极限 L2 accepted receipt 吞吐；on-demand proof，不适合生产。 |
| `configs/benchmark-burst.yaml` | 瞬时流量吸收；大批次和大队列，后台完成 L3。 |
| `configs/benchmark-l3-throughput.yaml` | 持续高写的 L2/L3 平衡。 |
| `configs/benchmark-proof-ready.yaml` | 优先降低 L3 backlog。 |
| `configs/benchmark-balanced.yaml` | group fsync、低索引写放大和 L4 的综合档位。 |
| `configs/benchmark-production-safe.yaml` | full index、group fsync、L4/L5 的生产安全基线。 |
| `configs/benchmark-production-guaranteed.yaml` | strict fsync、full index、L4/L5 的生产保证基线。 |
| `configs/benchmark-large-payload.yaml` | 16 KiB 和 64 KiB payload 压测。 |
| `configs/benchmark.yaml` | 吞吐压测配置；不代表生产审计语义。 |

`run_profile` 语义和启动提示见 [configs/README.md](configs/README.md)。

## Admin Web 和桌面客户端

可选 Admin Web（`clients/web`）由 `trustdb serve` 挂载到 `/admin`，用于 metrics、只读 API 浏览和 YAML 配置维护。写回配置需要服务端使用 `--config` 启动。

桌面客户端（`clients/desktop`）是 Wails + Vue 应用，覆盖本地身份、文件存证、服务端设置、本地 record index、proof refresh、proof 导出和离线验证。

![TrustDB 桌面客户端概览](assets/readme/desktop-overview.png)

## 项目文档

- [CONTRIBUTING.md](CONTRIBUTING.md)：Issue、PR、Commit、验证和 Review 标准。
- [formats/SPROOF_V1.md](formats/SPROOF_V1.md)：稳定 `.sproof` v1 交换格式。
- [formats/DISTRIBUTED_ARCHITECTURE.md](formats/DISTRIBUTED_ARCHITECTURE.md)：分布式/存算分离说明。
- [docs/performance/trustdb-performance-report-2026-07-16.zh-CN.md](docs/performance/trustdb-performance-report-2026-07-16.zh-CN.md)：最新全链路双机性能报告。
- [docs/performance/trustdb-performance-optimization-2026-07.zh-CN.md](docs/performance/trustdb-performance-optimization-2026-07.zh-CN.md)：性能优化实现说明。
- [docs/performance/trustdb-performance-report-2026-04-30.zh-CN.md](docs/performance/trustdb-performance-report-2026-04-30.zh-CN.md)：旧版性能优先基线。

## 开发检查

迭代时按范围选择最小检查，合并前跑更完整的检查：

```powershell
go test ./...
go test -race ./...
go test -tags=integration ./...
go test -tags=e2e ./...
```

前端和桌面检查：

```powershell
cd clients/web
npm ci
npm run build

cd ../desktop
go test ./...
```

标准 Issue、PR 和提交格式见 [CONTRIBUTING.md](CONTRIBUTING.md)。
