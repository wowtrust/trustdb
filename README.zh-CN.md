# TrustDB

![CI](https://github.com/wowtrust/trustdb/actions/workflows/ci.yml/badge.svg)
![GitHub release](https://img.shields.io/github/v/release/wowtrust/trustdb)
![License](https://img.shields.io/github/license/wowtrust/trustdb)
![Go version](https://img.shields.io/github/go-mod/go-version/wowtrust/trustdb)

[官方网站](https://www.trustdb.ryan-wong.cn/) | [快速开始](#快速开始) | [English README](README.md) | [社区](COMMUNITY.md) | [路线图](ROADMAP.md) | [贡献指南](CONTRIBUTING.md)

**TrustDB 是一个面向文件、审计事件和数据交接的可自托管防篡改证据数据库。** 它把本地内容哈希转换为可移植证明，让接收方不必取得原始数据、不必信任源系统管理员，也能离线独立验证。

当业务以后必须回答“提交了什么、谁签过、服务端是否接受、当前材料是否仍与当时一致”时，可以把 TrustDB 作为业务数据库之外的独立证据层：

- 原始业务数据继续留在原系统；TrustDB 保存哈希、签名、收据和证明。
- 导出单个 `.sproof` 证据文件，交给另一方离线验证。
- 从签名声明、Merkle 批次逐步形成全局透明日志证据。
- 可通过 CLI、Go SDK、Docker、桌面客户端自托管，并可选使用 TiKV proofstore。

典型场景包括发布产物核验、数据和报告交付、高危操作凭证、数据集/模型来源追踪以及跨组织数据交接。TrustDB 不作笼统的法律效力承诺，也不会自动把密码学密钥绑定到现实身份。

## 一条命令体验篡改检测

安装 Go 并克隆仓库后运行：

```sh
./scripts/demo.sh
```

脚本会在临时目录构建 CLI，为样例文件生成证明，验证原文件，然后修改一份副本并确认验证失败。它不会启动服务，也不会保留生成的密钥。

预编译包、Docker、Windows 指引、L4/L5 证明和生产部署请查看[官方快速开始](https://www.trustdb.ryan-wong.cn/docs/quick-start)。

![TrustDB 系统架构](assets/readme/system-architecture.png)

当前 Go module：

```text
github.com/wowtrust/trustdb
```

许可证：AGPL-3.0-only，见 [LICENSE](LICENSE)。

## v1.0.0

首个正式版通过 [GitHub Releases](https://github.com/wowtrust/trustdb/releases/tag/v1.0.0) 发布，包含 Linux、macOS、Windows 的服务器与 CLI、四种自签名桌面客户端、多架构 Docker 镜像和统一的 `SHA256SUMS`。

本版正式确立 `github.com/wowtrust/trustdb` module 路径，并包含持久化 STH 合并锚定、covering anchor 离线证据导出、可恢复 L5 coverage 投影、存储 schema v4 和当前逻辑备份格式。Go SDK 可直接固定正式标签：

```bash
go get github.com/wowtrust/trustdb@v1.0.0
```

Docker Hub 同步发布 amd64 与 arm64 镜像，并提供不可变版本标签与稳定通道标签：

```bash
docker pull wsy19990317/trustdb:1.0.0
docker run -d --name trustdb -p 127.0.0.1:8080:8080 -v trustdb-data:/var/lib/trustdb wsy19990317/trustdb:1.0.0
docker logs trustdb
curl --fail http://127.0.0.1:8080/healthz
```

桌面包使用本次发版临时生成的自签名证书，并附带公开 `.cer` 文件，可供用户核对本次发布所用的签名证书。它不会取得 Apple 或 Microsoft 的系统信任；Gatekeeper 或 SmartScreen 仍可能提示未知开发者。安装前请用 `SHA256SUMS` 核对下载文件。

## 能力概览

- 使用确定性 CBOR 表达 claim、receipt、proof bundle、global-log proof、STH、anchor result、backup 和 `.sproof` 文件。
- 支持客户端、服务端和 key registry 的 Ed25519 签名。
- WAL-backed ingest：有界队列、可配置 fsync、replay、checkpoint 和优雅关闭。
- Batch Merkle proof、持久化 record index、分页 record/root API。
- Global Transparency Log：持久化 STH、inclusion proof、consistency proof 和 history tile。
- L5 STH/global-root 锚定：支持 `off`、`noop`、本地文件和 OpenTimestamps sink。
- Proofstore 支持 file、Pebble 和 TiKV；TiKV 可实现存算分离，但每个 namespace 只属于一个逻辑 `(node_id, log_id)` 流，不支持同 namespace active-active writer。
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
| L5 | 受支持的 anchor sink 已为对应 STH/global root 产生匹配结果；只有真实外部 sink 才增加独立时间语义。 | `STHAnchorResult` / `.tdanchor-result` |

桌面客户端和交换场景推荐使用 `.sproof` 单文件证明。它可以包含 L3 `ProofBundle`、可选 L4 `GlobalLogProof` 和可选 L5 `STHAnchorResult`。稳定 v1 格式见 [formats/SPROOF_V1.md](formats/SPROOF_V1.md)。

## 架构

TrustDB 默认按单节点服务运行。多个计算节点可以共享同一个 TiKV 集群，但一个 proofstore namespace 只能属于一个逻辑 `(node_id, log_id)` Global Log 流。只有保持相同逻辑身份的 active-passive 替换实例才能复用该 namespace；独立日志必须使用不同 namespace。目前不支持同 namespace 的 active-active writer。

核心路径：

- Client path：CLI、SDK 或桌面客户端计算文件哈希，签名 claim，并提交到本地或服务端。
- Ingest path：服务端校验签名和 key 状态，将接受记录追加到 WAL，并返回 accepted receipt。
- Batch path：accepted records 被聚合成 Merkle batch，存储 proof bundle 和索引。
- Global log path：committed batch roots 被追加到 global transparency log，生成持久化 STH 和 global proof。
- Anchor path：STH/global roots 按 `(node_id, log_id, sink)` 合并进常数空间的 Pending/InFlight 调度状态，再由 anchor worker 按固定窗口发布。
- Storage path：proof 数据可落到 file、Pebble 或 TiKV proofstore。
- Backup path：proofstore 数据可导出为 `.tdbackup`，支持 verify 与可断点续传的 restore 状态；便携备份不包含节点本地 WAL checkpoint。
- Observability path：`/metrics` 暴露 ingest、batch、global log、anchor、WAL、backup、storage 等指标。

`wal.fsync_mode=strict` 会在每条 accepted record 的 WAL 文件完成 fsync 后才返回。`group` 通过 `wal.group_commit_interval` 限制异步未刷盘窗口；`batch` 会把 accepted record 数据的 fsync 延后到 segment 轮转或关闭。Writer 启动，以及 WAL 目录创建、文件发布、轮转与裁剪所需的命名空间屏障，不受该追加策略影响。在 Windows 上，如果底层文件系统拒绝当前可用的最强目录刷新操作，TrustDB 会直接失败而不会静默降级。回执契约要求逐条 fsync 时应选择 `strict`；端到端崩溃耐久性仍取决于文件系统与存储设备保证。

只有当 proofstore 能在 checkpoint 之前持久化排序 committed artifacts 与重启幂等决策，并把 checkpoint 限定到同一份节点本地 WAL 时，TrustDB 才会自动跳过 checkpoint 覆盖的记录并裁剪 WAL segment。Pebble 会把带幂等键的重启幂等决策与 committed manifest 原子发布，并仅在该投影就绪时启用 checkpoint 跳过与裁剪。TiKV 只有在显式绑定当前计算节点和本地 WAL 的绝对路径身份后才启用同一能力。开发用 file 后端缺少完整的幂等投影耐久屏障，因此仍保留并重放 WAL。

升级时，旧版 v1 checkpoint 只能基于从 sequence 1 开始的完整保留 WAL 重建。如果旧部署已经裁掉该前缀，启动会以 `DataLoss` 失败关闭；应从可信备份恢复完整 WAL，而不是删除 checkpoint 标记，因为删除标记无法证明缺失记录已经提交。

## 快速开始

从 [v1.0.0 发布页](https://github.com/wowtrust/trustdb/releases/tag/v1.0.0)下载与你的系统和处理器相符的服务器 / CLI 压缩包。解压前先用 [`SHA256SUMS`](https://github.com/wowtrust/trustdb/releases/download/v1.0.0/SHA256SUMS)核对归档，再从解压后的发布目录执行下列命令。这个本地 L3 流程无需启动服务，也不需要 Go 工具链；Windows 用户请直接跟随官网的[平台化快速开始](https://www.trustdb.ryan-wong.cn/docs/quick-start)。

先创建明确的输入和一次性练习目录：

```bash
printf 'hello TrustDB\n' > example.txt
mkdir -p .trustdb-dev
```

生成一次性客户端和服务端密钥。`keygen` 会替换同名密钥文件；已经签发过证据的身份不能重复执行：

```bash
./bin/trustdb keygen --out .trustdb-dev --prefix client
./bin/trustdb keygen --out .trustdb-dev --prefix server
```

在本地创建并签名文件 claim：

```bash
./bin/trustdb claim-file \
  --file ./example.txt \
  --private-key .trustdb-dev/client.key \
  --tenant default \
  --client local-client \
  --key-id client-key \
  --out .trustdb-dev/example.tdclaim
```

把 claim 本地提交为 L3 ProofBundle，并把 WAL 也放在练习目录：

```bash
./bin/trustdb commit \
  --claim .trustdb-dev/example.tdclaim \
  --server-private-key .trustdb-dev/server.key \
  --client-public-key .trustdb-dev/client.pub \
  --wal .trustdb-dev/local-wal \
  --out .trustdb-dev/example.tdproof

./bin/trustdb proof inspect --proof .trustdb-dev/example.tdproof
```

重新计算原文件摘要、签名、收据和 Merkle 路径：

```bash
./bin/trustdb verify \
  --file ./example.txt \
  --proof .trustdb-dev/example.tdproof \
  --server-public-key .trustdb-dev/server.pub \
  --client-public-key .trustdb-dev/client.pub
```

成功输出包含 `"valid":true` 与 `"proof_level":"L3"`。这里的本地 `commit` 不会把 claim 发给正在运行的服务。服务端提交、异步 L4、`.sproof` 导出和离线验证请继续查看经过编译检查的 [Go SDK 示例](examples/sdk-onboarding)；生产部署与停服逻辑备份见官网[运维指南](https://www.trustdb.ryan-wong.cn/docs/server)。

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
| `GET /v1/global-log/evidence/{batch_id}` | 获取覆盖该 batch 的 Global Log 组合证据，并在可用时返回精确匹配的已发布 anchor result。 |
| `GET /v1/global-log/consistency?from=&to=` | 获取 global-log consistency proof。 |
| `GET /v1/anchors/sth/{tree_size}` | 获取已发布的 immutable STH anchor result。 |
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

- [ARCHITECTURE.zh-CN.md](ARCHITECTURE.zh-CN.md)：TrustDB 服务端、持久化、Global Log、Anchor、SDK、备份和离线验证的详细架构设计。
- [COMMUNITY.md](COMMUNITY.md)：使用支持、讨论和首次贡献入口。
- [ROADMAP.md](ROADMAP.md)：公开产品方向以及影响路线图的方式。
- [SECURITY.md](SECURITY.md)：漏洞私密报告和支持版本策略。
- [LICENSE-FAQ.md](LICENSE-FAQ.md)：AGPL 采用常见问题和项目边界。
- [ADOPTERS.md](ADOPTERS.md)：公开评估、试点和生产采用者。
- [CONTRIBUTING.md](CONTRIBUTING.md)：Issue、PR、Commit、验证和 Review 标准。
- [formats/SPROOF_V1.md](formats/SPROOF_V1.md)：稳定 `.sproof` v1 交换格式。
- [formats/DISTRIBUTED_ARCHITECTURE.md](formats/DISTRIBUTED_ARCHITECTURE.md)：分布式/存算分离说明。
- [docs/performance/trustdb-performance-report-2026-07-16.zh-CN.md](docs/performance/trustdb-performance-report-2026-07-16.zh-CN.md)：最新全链路双机性能报告。
- [docs/performance/trustdb-performance-optimization-2026-07.zh-CN.md](docs/performance/trustdb-performance-optimization-2026-07.zh-CN.md)：性能优化实现说明。
- [docs/performance/trustdb-performance-report-2026-04-30.zh-CN.md](docs/performance/trustdb-performance-report-2026-04-30.zh-CN.md)：旧版性能优先基线。

## 社区致谢

TrustDB 感谢 [LINUX DO 社区](https://linux.do/) 对开放技术交流与开源协作的推动。

使用问题和集成想法请进入 [GitHub Discussions](https://github.com/wowtrust/trustdb/discussions)，确认的缺陷和已接受的工程任务请进入 [GitHub Issues](https://github.com/wowtrust/trustdb/issues)。更多入口见[社区指南](COMMUNITY.md)、[路线图](ROADMAP.md)、[安全策略](SECURITY.md)、[许可证 FAQ](LICENSE-FAQ.md)和[采用者列表](ADOPTERS.md)。

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
