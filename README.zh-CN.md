# TrustDB

![CI](https://github.com/wowtrust/trustdb/actions/workflows/ci.yml/badge.svg)

[官方网站](https://www.trustdb.ryan-wong.cn/) | [English README](README.md) | [贡献指南](CONTRIBUTING.md) | [`.sproof` 格式](formats/SPROOF_V1.md)

TrustDB 是一个面向文件存证和证明交换的可验证证据数据库。它把本地文件哈希转换为客户端签名声明、服务端接受收据、批次 Merkle 证明、Global Transparency Log 证明，以及可选的外部 Signed Tree Head（STH）锚定结果。

文档、快速开始、版本发布和反馈渠道统一维护在 [TrustDB 官方网站](https://www.trustdb.ryan-wong.cn/)。

![TrustDB 系统架构](assets/readme/system-architecture.png)

当前 Go module：

```text
github.com/wowtrust/trustdb
```

许可证：AGPL-3.0-only，见 [LICENSE](LICENSE)。

## v1.0.0-beta.1

第二个公开测试版通过 [GitHub Releases](https://github.com/wowtrust/trustdb/releases/tag/v1.0.0-beta.1) 发布。除 Linux、macOS、Windows 两种架构的服务器与 CLI、四种桌面客户端和统一的 `SHA256SUMS` 外，本版还为官网、桌面客户端和 Admin Web 增加中、英、俄、日、法、韩六种语言，并让官网按当前语言展示真实客户端画面。

仓库 `main` 分支现在声明 `github.com/wowtrust/trustdb`。历史标签 `v1.0.0-beta.1` 发布于本次迁移之前，仍保留旧 module identity，因此不能通过新的 module 路径请求该标签。下一个新路径版本标签发布前，请使用首次合并新路径后的 canonical pseudo-version。固定这个精确版本可避开分支查询缓存，并保证构建可复现：

```bash
go get github.com/wowtrust/trustdb@v1.0.0-beta.1.0.20260722051404-c91313f7f40e
```

Docker Hub 同步发布 amd64 与 arm64 镜像；测试版不会占用 `latest`：

```bash
docker pull wsy19990317/trustdb:1.0.0-beta.1
docker run --name trustdb -p 8080:8080 -v trustdb-data:/var/lib/trustdb wsy19990317/trustdb:1.0.0-beta.1
```

桌面包使用本次发版临时生成的自签名证书，并附带公开 `.cer` 文件，可供用户核对本次发布所用的签名证书。它不会取得 Apple 或 Microsoft 的系统信任；Gatekeeper 或 SmartScreen 仍可能提示未知开发者。安装前请用 `SHA256SUMS` 核对下载文件。

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
| L2 | 服务端校验并将 claim 接受到 WAL；崩溃耐久性取决于配置的 fsync 策略。 | `AcceptedReceipt` |
| L3 | accepted claim 被提交进 batch Merkle tree。 | `ProofBundle` / `.tdproof` |
| L4 | batch root 已进入 Global Transparency Log，并能证明包含于目标 STH。 | `GlobalLogProof` / `.tdgproof` |
| L5 | 对应 STH/global root 已被外部 anchor sink 锚定。 | `STHAnchorResult` / `.tdanchor-result` |

桌面客户端和交换场景推荐使用 `.sproof` 单文件证明。它可以包含 L3 `ProofBundle`、可选 L4 `GlobalLogProof` 和可选 L5 `STHAnchorResult`。稳定 v1 格式见 [formats/SPROOF_V1.md](formats/SPROOF_V1.md)。

## 架构

TrustDB 默认可按单节点服务运行。启用 TiKV proofstore 后，多个 TrustDB 计算节点可以共享同一份持久证明数据，并通过 `node_id` 和 `log_id` 保留来源身份。

核心路径：

- Client path：CLI、SDK 或桌面客户端计算文件哈希，签名 claim，并提交到本地或服务端。
- Ingest path：服务端校验签名和 key 状态，将接受记录追加到 WAL，并返回 accepted receipt。
- Batch path：accepted records 被聚合成 Merkle batch，存储 proof bundle 和索引。
- Global log path：committed batch roots 被追加到 global transparency log，生成持久化 STH 和 global proof。
- Anchor path：STH/global roots 入队后由 anchor worker 按配置发布。
- Storage path：proof 数据可落到 file、Pebble 或 TiKV proofstore。
- Backup path：proofstore 数据可导出为 `.tdbackup`，支持 verify 与可断点续传的 restore 状态；便携备份不包含节点本地 WAL checkpoint。
- Observability path：`/metrics` 暴露 ingest、batch、global log、anchor、WAL、backup、storage 等指标。

`wal.fsync_mode=strict` 会在每条 accepted record 的 WAL 文件完成 fsync 后才返回。`group` 通过 `wal.group_commit_interval` 限制异步未刷盘窗口；`batch` 会把 accepted record 数据的 fsync 延后到 segment 轮转或关闭。Writer 启动，以及 WAL 目录创建、文件发布、轮转与裁剪所需的命名空间屏障，不受该追加策略影响。在 Windows 上，如果底层文件系统拒绝当前可用的最强目录刷新操作，TrustDB 会直接失败而不会静默降级。回执契约要求逐条 fsync 时应选择 `strict`；端到端崩溃耐久性仍取决于文件系统与存储设备保证。

只有当 proofstore 能在 checkpoint 之前持久化排序 committed artifacts 与重启幂等决策，并把 checkpoint 限定到同一份节点本地 WAL 时，TrustDB 才会自动跳过 checkpoint 覆盖的记录并裁剪 WAL segment。Pebble 会把带幂等键的重启幂等决策与 committed manifest 原子发布，并仅在该投影就绪时启用 checkpoint 跳过与裁剪。开发用 file 后端和共享 TiKV 后端仍会保留并重放 WAL：file 缺少完整的崩溃耐久屏障，TiKV checkpoint 则尚未按节点划分。

升级时，旧版 v1 checkpoint 只能基于从 sequence 1 开始的完整保留 WAL 重建。如果旧部署已经裁掉该前缀，启动会以 `DataLoss` 失败关闭；应从可信备份恢复完整 WAL，而不是删除 checkpoint 标记，因为删除标记无法证明缺失记录已经提交。

## 快速开始

从 [v1.0.0-beta.1 发布页](https://github.com/wowtrust/trustdb/releases/tag/v1.0.0-beta.1)下载与你的系统和处理器相符的服务器 / CLI 压缩包，解压后在发布目录运行下列命令，不需要安装 Go 工具链。示例使用 `./bin/trustdb`；Windows 请改为 `.\bin\trustdb.exe`。

运行前请用 [`SHA256SUMS`](https://github.com/wowtrust/trustdb/releases/download/v1.0.0-beta.1/SHA256SUMS)核对下载文件。源码编译步骤见单独的[从源码构建](https://www.trustdb.ryan-wong.cn/docs/source-build)章节。

生成客户端和服务端密钥：

```powershell
./bin/trustdb keygen --out .trustdb-dev --prefix client
./bin/trustdb keygen --out .trustdb-dev --prefix server
```

启动本地开发服务：

```powershell
./bin/trustdb serve `
  --config config/production.yaml `
  --server-private-key .trustdb-dev/server.key `
  --client-public-key .trustdb-dev/client.pub `
  --listen 127.0.0.1:8080
```

创建并签名文件 claim：

```powershell
./bin/trustdb claim-file `
  --file .\example.txt `
  --private-key .trustdb-dev/client.key `
  --tenant default `
  --client local-client `
  --key-id client-key `
  --out .trustdb-dev/example.tdclaim
```

把 claim 本地提交为 proof bundle：

```powershell
./bin/trustdb commit `
  --claim .trustdb-dev/example.tdclaim `
  --server-private-key .trustdb-dev/server.key `
  --client-public-key .trustdb-dev/client.pub `
  --out .trustdb-dev/example.tdproof
```

验证本地文件和 proof：

```powershell
./bin/trustdb verify `
  --file .\example.txt `
  --proof .trustdb-dev/example.tdproof `
  --server-public-key .trustdb-dev/server.pub `
  --client-public-key .trustdb-dev/client.pub
```

验证推荐的 `.sproof` 单文件证明：

```powershell
./bin/trustdb verify `
  --file .\example.txt `
  --sproof .trustdb-dev/example.sproof `
  --server-public-key .trustdb-dev/server.pub `
  --client-public-key .trustdb-dev/client.pub
```

创建并校验便携备份：

```powershell
./bin/trustdb backup create `
  --metastore file `
  --metastore-path .trustdb-dev/proofs `
  --out .trustdb-dev/trustdb.tdbackup

./bin/trustdb backup verify --file .trustdb-dev/trustdb.tdbackup
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

## 社区致谢

TrustDB 感谢 [LINUX DO 社区](https://linux.do/) 对开放技术交流与开源协作的推动。

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
