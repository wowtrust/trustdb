# TrustDB

<p align="center">
  <img src="clients/desktop/build/appicon.png" alt="TrustDB 对号标志" width="120">
</p>

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

## TrustDB 是否适合你的场景？

| TrustDB 适合 | TrustDB 不替代 |
| --- | --- |
| 文件和数据交接的可移植证据 | 原始业务内容存储 |
| 高风险操作的防篡改记录 | 日志搜索、链路追踪或 SIEM 平台 |
| 独立、离线的证明验证 | 现实身份认定和密钥管理制度 |
| 透明日志和外部锚定证据 | 部署层 TLS、认证和授权 |
| 数据集、模型、报告和发布产物来源追踪 | 法律意见或自动获得的证据效力 |

## 一条命令体验篡改检测

安装 Go 并克隆仓库后运行：

```sh
./scripts/demo.sh
```

脚本会在临时目录构建 CLI，为样例文件生成证明，验证原文件，然后修改一份副本并确认验证失败。它不会启动服务，也不会保留生成的密钥。

预编译包、Docker、Windows 指引、L4/L5 证明和生产部署请查看[官方快速开始](https://www.trustdb.ryan-wong.cn/docs/quick-start)。

## 加入社区

- 在 [GitHub Discussions](https://github.com/wowtrust/trustdb/discussions) 提问或分享部署经验。
- 通过[集成讨论](https://github.com/wowtrust/trustdb/discussions/categories/ideas)提出生态连接方案。
- 领取适合首次参与的 [`good first issue`](https://github.com/wowtrust/trustdb/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)。
- 把评估、试点或生产部署加入 [ADOPTERS.md](ADOPTERS.md)。
- 在[更新日志](CHANGELOG.md)查看面向用户的版本变化。

![TrustDB 系统架构](assets/readme/system-architecture.png)

当前 Go module：

```text
github.com/wowtrust/trustdb/v2
```

许可证：AGPL-3.0-only，见 [LICENSE](LICENSE)。

## v2.0.0-rc.2

修正后的 V2 发布候选版通过 [GitHub Releases](https://github.com/wowtrust/trustdb/releases/tag/v2.0.0-rc.2) 发布，包含 Linux、macOS、Windows 的服务器与 CLI、四种自签名桌面客户端、同步发布到 GHCR 与 Docker Hub 的多架构镜像，以及带 SHA-256、SM3、SBOM、漏洞报告、生产输入、容器摘要和 Sigstore 来源证明的签名发布清单。RC.2 同时保证 macOS、Linux 与 Windows 使用确定且一致的发布清单校验规则。

这个版本完成明确的 V2/V5 破坏性切换：proofstore schema v5、全链路 suite 绑定对象、`.sproof v2`、加密 `.tdbackup v5`，以及 `INTL_V1` / `CN_SM_V1` 端到端证据生成。Go module 遵循语义化主版本路径：

```bash
go get github.com/wowtrust/trustdb/v2@v2.0.0-rc.2
```

V2 不读取或迁移 v1 存储、备份、API 对象和证据文件。升级前保留旧环境用于审计，再使用新 namespace、新 LogID 和空数据目录部署 RC。Docker Hub 同步发布 amd64 与 arm64 镜像；发布候选版更新不可变版本标签和 `beta` 通道，不移动 `latest`：

```bash
docker pull wsy19990317/trustdb:2.0.0-rc.2
printf '开发密钥口令：'
IFS= read -r -s TRUSTDB_DEV_KEY_PASSPHRASE
printf '\n'
export TRUSTDB_DEV_KEY_PASSPHRASE
docker run -d --name trustdb \
  -e TRUSTDB_DEV_KEY_PASSPHRASE \
  -p 127.0.0.1:8080:8080 \
  -v trustdb-data:/var/lib/trustdb \
  wsy19990317/trustdb:2.0.0-rc.2
unset TRUSTDB_DEV_KEY_PASSPHRASE
docker logs trustdb
curl --fail http://127.0.0.1:8080/healthz
```

这里仅把当前 shell 中的值转交给容器，口令不会出现在 `docker run` 参数中。长期运行的服务应优先使用 `TRUSTDB_DEV_KEY_PASSPHRASE_FILE`，令其指向 `/var/lib/trustdb` 之外、由 secret manager 注入且仅 owner 可读的文件；两个口令来源必须恰好配置一个，KEK 不得与 envelope 放在同一目录或备份卷。

桌面包使用本次发版临时生成的自签名证书，并附带公开 `.cer` 文件，可供用户核对本次发布所用的签名证书。它不会取得 Apple 或 Microsoft 的系统信任；Gatekeeper 或 SmartScreen 仍可能提示未知开发者。安装前请用 `SHA256SUMS` 核对下载文件。

通用发布包支持 FISCO BCOS 证据的离线验证。向真实 FISCO BCOS 网络发布锚点时，必须按固定 C SDK v3.6.0、Go SDK v3.0.2 和 `fiscobcos_sdk` build tag 从源码构建；通用二进制会明确失败，不会静默替换为其他 sink。

历史 [v1.0.0 版本](https://github.com/wowtrust/trustdb/releases/tag/v1.0.0)仍可用于既有 v1 证据环境。它的 module 路径是 `github.com/wowtrust/trustdb`，存储 schema 是 v4，证明容器是 `.sproof v1`；这些产物与 V2 不兼容。

## 发布供应链证据

v2.0.0-rc.2 包含已签名的
`TRUSTDB_RELEASE_MANIFEST.json`、`SHA256SUMS`、`SM3SUMS`、SPDX SBOM、
漏洞扫描留存结果、精确的原生库/合约/许可证/架构矩阵、不可变容器 digest
与可下载 Sigstore bundle。Release Actions 和基础镜像分别固定到 commit 或
OCI digest；未进入 manifest 的文件、内容漂移的生产输入都会阻断发版。

RC.2 根据确定的产物文件名推导 manifest media type，不再依赖宿主 MIME
数据库，因此 macOS、Linux 与 Windows 随包 verifier 会执行完全一致的发布
清单校验。RC.1 保持不可变并继续用于历史审计。

断网运维人员先用独立下发的 trusted root 验证 manifest，再执行
`trustdb release verify --dir <release目录>` 检查精确文件集合与双摘要。
国产 Go/npm/OCI 镜像只改变获取路线，lockfile integrity 与不可变 digest
始终是最终约束。完整步骤见[发布供应链与隔离区运维手册](docs/zh-CN/SUPPLY_CHAIN_RELEASES.md)。

## 能力概览

- 使用确定性 CBOR 表达 claim、receipt、proof bundle、global-log proof、STH、anchor result、backup 和 `.sproof` 文件。
- 当前客户端/服务端证据使用 Ed25519；suite-bound Registry V2 已支持 Ed25519 与 SM2 生命周期事件、历史时点查询、轮换、撤销和失陷标记。
- WAL-backed ingest：有界队列、可配置 fsync、replay、checkpoint 和优雅关闭。
- 可选 NATS JetStream ingress：耐久汇聚、有界 broker 背压、不可变 acceptance result 与重启后结果恢复。
- Batch Merkle proof、持久化 record index、分页 record/root API。
- Global Transparency Log：持久化 STH、inclusion proof、consistency proof 和 history tile。
- L5 STH/global-root 锚定：支持 `off`、`noop`、本地文件、OpenTimestamps 和受监管的外部 gRPC 子进程插件。
- Proofstore 支持 file、Pebble 和 TiKV；TiKV 可实现存算分离，但每个 namespace 只属于一个逻辑 `(node_id, log_id)` 流，不支持同 namespace active-active writer。
- `.tdbackup` 便携备份：创建、校验、带 checkpoint 的可恢复 restore。
- Go SDK：claim 签名、HTTP/gRPC 调用、证明导出、本地验证。
- Wails + Vue 桌面客户端：本地身份、文件存证、记录管理、proof refresh、`.sproof` 导出和离线验证。
- 可选 Vue Admin Web：由 `trustdb serve` 挂载，用于 metrics、只读浏览和受控 YAML 配置维护。
- 独立的签名/哈希链安全审计：覆盖认证、授权、配置、密钥、备份、Anchor、trust root 和服务生命周期，支持 SM2/SM3、可信时间 fail-closed、JSONL 完全离线验证与独立保管的签名 checkpoint。
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

桌面客户端和交换场景推荐使用 `.sproof` 单文件证明。它可以包含 L3 `ProofBundle`、可选 L4 `GlobalLogProof`、可选 L5 `STHAnchorResult`，以及有界的公开身份/状态证据。当前版本只接受 [formats/SPROOF_V2.md](formats/SPROOF_V2.md) 定义的 suite-bound v2；v1 已退役，不读取、不迁移，也不会失败后回退尝试。

## 架构

TrustDB 默认按单节点服务运行。多个计算节点可以共享同一个 TiKV 集群，但一个 proofstore namespace 只能属于一个逻辑 `(node_id, log_id)` Global Log 流。只有保持相同逻辑身份的 active-passive 替换实例才能复用该 namespace；独立日志必须使用不同 namespace。目前不支持同 namespace 的 active-active writer。

核心路径：

- Client path：CLI、SDK 或桌面客户端计算文件哈希，签名 claim，并提交到本地或服务端。
- Ingest path：服务端校验签名和 key 状态，将接受记录追加到 WAL，并返回 accepted receipt。
- 可选 NATS path：JetStream 耐久缓冲 signed claim，共用 submission service 在确认 broker delivery 前先保存不可变结果。
- Batch path：accepted records 被聚合成 Merkle batch，存储 proof bundle 和索引。
- Global log path：committed batch roots 被追加到 global transparency log，生成持久化 STH 和 global proof。
- Anchor path：STH/global roots 按 `(node_id, log_id, sink)` 合并进常数空间的 Pending/InFlight 调度状态，再由 anchor worker 按固定窗口发布。
- Storage path：proof 数据可落到 file、Pebble 或 TiKV proofstore。
- Backup path：proofstore 数据可导出为 `.tdbackup`，支持 verify 与可断点续传的 restore 状态；便携备份不包含节点本地 WAL checkpoint。
- 加密逻辑备份：`.tdbackup v5` 已支持 `INTL_V1` 与 `CN_SM_V1`，使用 provider-wrapped 随机 DEK、SM4-GCM 分帧认证加密、suite 选择的 SHA-256/SM3 entry digest，以及 source/target namespace-bound 可恢复 checkpoint；v4/plain tar 不读取、不迁移、不回退。
- Observability path：`/metrics` 暴露 ingest、batch、global log、anchor、WAL、backup、storage 等指标。
- 安全审计 path：高权限控制面的授权意图和结果写入独立签名链；[配置、可信时间、导出、离线验证、容量与事件处置](docs/zh-CN/IMMUTABLE_SECURITY_AUDIT.md)不依赖普通日志或 `.sproof`。

file、Pebble 和每个 TiKV namespace 使用 proofstore storage schema v5。旧版或无版本标记的非空存储会明确失败；当前版本不扫描、不迁移、也不双读旧键布局。部署 V5 时应使用空 namespace 和新的 LogID。

`wal.fsync_mode=strict` 会在每条 accepted record 的 WAL 文件完成 fsync 后才返回。`group` 通过 `wal.group_commit_interval` 限制异步未刷盘窗口；`batch` 会把 accepted record 数据的 fsync 延后到 segment 轮转或关闭。Writer 启动，以及 WAL 目录创建、文件发布、轮转与裁剪所需的命名空间屏障，不受该追加策略影响。在 Windows 上，如果底层文件系统拒绝当前可用的最强目录刷新操作，TrustDB 会直接失败而不会静默降级。回执契约要求逐条 fsync 时应选择 `strict`；端到端崩溃耐久性仍取决于文件系统与存储设备保证。

只有当 proofstore 能在 checkpoint 之前持久化排序 committed artifacts 与重启幂等决策，并把 checkpoint 限定到同一份节点本地 WAL 时，TrustDB 才会自动跳过 checkpoint 覆盖的记录并裁剪 WAL segment。Pebble 会把带幂等键的重启幂等决策与 committed manifest 原子发布，并仅在该投影就绪时启用 checkpoint 跳过与裁剪。TiKV 只有在显式绑定当前计算节点和本地 WAL 的绝对路径身份后才启用同一能力。开发用 file 后端缺少完整的幂等投影耐久屏障，因此仍保留并重放 WAL。

恢复只接受绑定到当前 crypto suite、NodeID、LogID 与 storage namespace 的 V2 WAL/checkpoint 代际。旧版或未绑定的恢复数据会失败关闭；当前版本不迁移，也不会回退读取更早的 WAL/checkpoint 格式。

## 快速开始

当前 README 与官网教程固定到 `v2.0.0-rc.2`。请下载适合当前平台的已发布
Server/CLI 压缩包，使用发布的校验和文件验真后再解压；无需安装 Go 工具链，
也无需启动服务。Windows 用户可直接复制官网[平台化快速开始](https://www.trustdb.ryan-wong.cn/docs/quick-start)
中的 PowerShell 命令。

```bash
VERSION=2.0.0-rc.2
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) PLATFORM=darwin-arm64 ;;
  Darwin-x86_64) PLATFORM=darwin-amd64 ;;
  Linux-aarch64|Linux-arm64) PLATFORM=linux-arm64 ;;
  Linux-x86_64) PLATFORM=linux-amd64 ;;
  *) printf '不支持的系统或架构\n' >&2; exit 1 ;;
esac
ARCHIVE="trustdb-$VERSION-$PLATFORM.tar.gz"
BASE_URL="https://github.com/wowtrust/trustdb/releases/download/v$VERSION"
mkdir trustdb-quickstart && cd trustdb-quickstart
curl --fail --location --remote-name "$BASE_URL/SHA256SUMS"
curl --fail --location --remote-name "$BASE_URL/$ARCHIVE"
if command -v sha256sum >/dev/null 2>&1; then
  grep "  $ARCHIVE$" SHA256SUMS | sha256sum --check
else
  grep "  $ARCHIVE$" SHA256SUMS | shasum -a 256 --check
fi
tar -xzf "$ARCHIVE"
cd "trustdb-$VERSION-$PLATFORM"
./bin/trustdb version
```

先创建明确的输入和一次性练习目录：

```bash
printf 'hello TrustDB\n' > example.txt
mkdir -p .trustdb-dev
```

生成一次性客户端和服务端身份。每条命令会写入 signer descriptor（`.key`）、公开 verifier descriptor（`.pub`）和独立的软件私钥材料（`.material`）。两个 descriptor 都是 canonical CBOR，不是裸私钥；默认 material 是经过认证的 SM4-GCM envelope。开发 passphrase 只通过标准环境变量传入，不能作为普通 argv flag。加密生成拒绝覆盖已有 material；已经签发过证据的身份必须显式轮换，不能重新生成：

```bash
printf '开发密钥口令：'
IFS= read -r -s TRUSTDB_DEV_KEY_PASSPHRASE
printf '\n'
export TRUSTDB_DEV_KEY_PASSPHRASE
./bin/trustdb key generate --out .trustdb-dev --prefix client
./bin/trustdb key generate --out .trustdb-dev --prefix server
```

这里的 `--out .trustdb-dev` 是“把生成文件写入 `.trustdb-dev` 目录”，不是上传地址，也不是证明文件名；`--prefix client` 决定生成 `client.key`、`client.pub` 和 `client.material`。

无人值守的开发服务可以改设 `TRUSTDB_DEV_KEY_PASSPHRASE_FILE`。该变量必须指向仅 owner 可读的普通文件，同时必须取消 `TRUSTDB_DEV_KEY_PASSPHRASE`；secret file 应位于密钥目录及其备份范围之外。

开发/互操作环境可显式生成 SM2 身份。使用 `CN_SM_V1` 服务端 descriptor 启动服务后，claim、receipt、Merkle proof、STH、anchor 与 `.sproof v2` 都按 SM2/SM3 suite 生成；受信客户端 descriptor 与恢复后的 proofstore namespace 必须使用同一 suite：

```bash
./bin/trustdb key generate \
  --suite CN_SM_V1 \
  --out .trustdb-dev/sm2 \
  --prefix client
```

默认 `sm4-envelope-v1` 使用随机 DEK/nonce，并由仅限开发的 `passphrase-dev-v1` provider 包装 DEK。只依靠 owner-only 权限的旧路径必须显式指定 `--protection plaintext-dev-v1`，仍然只能用于开发。生产环境应配置版本化 PKCS#11、SDF、HSM/KMS 或 remote provider descriptor；软件 SM4 envelope 不等于生产 HSM 托管。TrustDB 不读取或回退到旧 raw-base64 key file。完整格式见 [`formats/SM4_KEY_ENVELOPE_V1.md`](formats/SM4_KEY_ENVELOPE_V1.md)。

在 TrustDB 能持续运行时验证 owner-only DACL 之前，Windows 上的软件 envelope 持久化会 fail closed。Windows 部署应使用经批准的外部 signer；显式 `plaintext-dev-v1` 只能用于可丢弃的评估环境。

只轮换开发 KEK、保持签名私钥和公开身份不变：

```bash
printf '新开发密钥口令：'
IFS= read -r -s TRUSTDB_DEV_KEY_PASSPHRASE_NEW
printf '\n'
export TRUSTDB_DEV_KEY_PASSPHRASE_NEW
./bin/trustdb key rewrap --descriptor .trustdb-dev/client.key
export TRUSTDB_DEV_KEY_PASSPHRASE="$TRUSTDB_DEV_KEY_PASSPHRASE_NEW"
unset TRUSTDB_DEV_KEY_PASSPHRASE_NEW
```

文件型轮换分别使用 `TRUSTDB_DEV_KEY_PASSPHRASE_FILE` 和 `TRUSTDB_DEV_KEY_PASSPHRASE_FILE_NEW` 指定旧、新 KEK；每一侧的直接值与文件来源都必须恰好选择一个。

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

成功输出包含 `"valid":true` 与 `"proof_level":"L3"`。这里的本地 `commit` 不会把 claim 发给正在运行的服务。服务端提交、异步 L4、`.sproof` 导出和离线验证请继续查看经过编译检查的 [Go SDK 示例](examples/sdk-onboarding)；需要耐久汇聚和 broker 分流时，查看[可选 NATS / JetStream ingress 指南](docs/integrations/NATS_INGRESS.zh-CN.md)；生产部署与停服逻辑备份见官网[运维指南](https://www.trustdb.ryan-wong.cn/docs/server)。

## HTTP 和 gRPC

已实现 HTTP endpoints：

| Endpoint | 用途 |
| --- | --- |
| `GET /healthz` | 健康检查。 |
| `POST /v2/claims` | 提交 signed claim。 |
| `POST /v2/claims/batch` | 提交 CBOR signed claim 批量。 |
| `GET /v2/records` | 分页 record 列表和搜索。 |
| `GET /v2/records/{record_id}` | 读取 record index 详情。 |
| `GET /v2/proofs/{record_id}` | 获取 L3 proof bundle。 |
| `GET /v2/roots` | 列出 batch roots。 |
| `GET /v2/roots/latest` | 获取最新 batch root。 |
| `GET /v2/sth/latest` | 获取最新 SignedTreeHead。 |
| `GET /v2/sth/{tree_size}` | 获取指定 tree size 的 STH。 |
| `GET /v2/global-log/inclusion/{batch_id}` | 获取 batch 的 global-log inclusion proof。 |
| `GET /v2/global-log/evidence/{batch_id}` | 获取覆盖该 batch 的 Global Log 组合证据，并在可用时返回精确匹配的已发布 anchor result。 |
| `GET /v2/global-log/consistency?from=&to=` | 获取 global-log consistency proof。 |
| `GET /v2/anchors/sth/{tree_size}` | 获取已发布的 immutable STH anchor result。 |
| `GET /v2/anchor-systems` | 列出配置的下游锚系统、种类、可信属性和 capabilities。 |
| `GET /v2/anchor-systems/{system_id}` | 获取一个锚系统的稳定语义描述。 |
| `GET /v2/anchor-systems/{system_id}/status` | 获取 provider 实时状态快照。 |
| `GET /v2/anchor-systems/{system_id}/resources` | 按 capability 分页查看节点、区块、交易、账户或合约。 |
| `GET /v2/anchor-systems/{system_id}/resources/{kind}/{resource_id}` | 获取一项 provider 资源详情。 |
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
自定义 provider 的开发、部署和验证方式见 [L5 外部锚定插件](formats/ANCHOR_PLUGIN_V1.md)。
锚系统种类、可信属性、能力发现与只读 Explorer API 见 [Anchor System Provider v1](formats/ANCHOR_SYSTEM_PROVIDER_V1.md)。

## Admin Web 和桌面客户端

可选 Admin Web（`clients/web`）由 `trustdb serve` 挂载到 `/admin`，用于 metrics、只读 API 浏览和 YAML 配置维护。写回配置需要服务端使用 `--config` 启动。

桌面客户端（`clients/desktop`）是 Wails + Vue 应用，覆盖本地身份、文件存证、服务端设置、本地 record index、proof refresh、proof 导出、离线验证和下游锚系统能力/状态/资源浏览。

![TrustDB 桌面客户端概览](assets/readme/desktop-overview.png)

## 项目文档

- [ARCHITECTURE.zh-CN.md](ARCHITECTURE.zh-CN.md)：TrustDB 服务端、持久化、Global Log、Anchor、SDK、备份和离线验证的详细架构设计。
- [docs/zh-CN/CHINA_DEPLOYMENT_PROFILES.md](docs/zh-CN/CHINA_DEPLOYMENT_PROFILES.md)：国产生产、离线隔离和测评 Profile 的真实启动门禁、出站/DNS、国密密钥与 BCOS、限时审计例外和负向测试。
- [docs/integrations/NATS_INGRESS.zh-CN.md](docs/integrations/NATS_INGRESS.zh-CN.md)：可选 JetStream ingress 的拓扑、配置、安全、背压、结果恢复与 Go SDK 接入指南。
- [docs/integrations/PKCS11_SIGNER.md](docs/integrations/PKCS11_SIGNER.md)：隔离的原生 PKCS#11 签名 sidecar、PIN 文件、机制检查、轮换、SoftHSM 互操作与生产设备验收要求。
- [docs/compliance/NATIONAL_CRYPTOGRAPHY_THREAT_MODEL_AND_EVIDENCE_MAP.zh-CN.md](docs/compliance/NATIONAL_CRYPTOGRAPHY_THREAT_MODEL_AND_EVIDENCE_MAP.zh-CN.md)：国产密码威胁模型、禁止的信任捷径、tabletop 场景、残余风险与合规证据映射。
- [docs/compliance/ADR-0004-PROVIDER-NEUTRAL-CRYPTO-CONTRACTS.zh-CN.md](docs/compliance/ADR-0004-PROVIDER-NEUTRAL-CRYPTO-CONTRACTS.zh-CN.md)：suite-aware hash、不可导出 KeyHandle、Signer/Verifier 与 provider fail-closed 契约。
- [docs/compliance/ADR-0008-VERSIONED-KEY-DESCRIPTORS.zh-CN.md](docs/compliance/ADR-0008-VERSIONED-KEY-DESCRIPTORS.zh-CN.md)：canonical software、PKCS#11、SDF、remote 与证书描述符、脱敏、解析和破坏性迁移规则。
- [docs/compliance/ADR-0009-SUITE-AWARE-KEY-REGISTRY-V2.zh-CN.md](docs/compliance/ADR-0009-SUITE-AWARE-KEY-REGISTRY-V2.zh-CN.md)：suite-bound Registry V2、SM2/INTL 生命周期、原子轮换、崩溃恢复和外部 trust root 规则。
- [docs/compliance/ADR-0010-AUTHENTICATED-SM4-SOFTWARE-KEY-ENVELOPES.zh-CN.md](docs/compliance/ADR-0010-AUTHENTICATED-SM4-SOFTWARE-KEY-ENVELOPES.zh-CN.md)：认证 SM4-GCM 软件私钥 envelope、KEK provider 边界、原子 rewrap 和生产托管限制。
- [COMMUNITY.md](COMMUNITY.md)：使用支持、讨论和首次贡献入口。
- [ROADMAP.md](ROADMAP.md)：公开产品方向以及影响路线图的方式。
- [SECURITY.md](SECURITY.md)：漏洞私密报告和支持版本策略。
- [LICENSE-FAQ.md](LICENSE-FAQ.md)：AGPL 采用常见问题和项目边界。
- [ADOPTERS.md](ADOPTERS.md)：公开评估、试点和生产采用者。
- [CHANGELOG.md](CHANGELOG.md)：面向用户整理的版本变化和已知限制。
- [CONTRIBUTING.md](CONTRIBUTING.md)：Issue、PR、Commit、验证和 Review 标准。
- [formats/SPROOF_V2.md](formats/SPROOF_V2.md)：当前 `.sproof` v2 交换格式与离线信任边界。
- [docs/zh-CN/README.md](docs/zh-CN/README.md)：按功能分类的中文用户与运维文档入口。
- [formats/KEY_DESCRIPTOR_V1.md](formats/KEY_DESCRIPTOR_V1.md)：canonical key descriptor schema、provider union、解析、脱敏与迁移契约。
- [formats/SDF_RECOVERY_BUNDLE_V1.md](formats/SDF_RECOVERY_BUNDLE_V1.md)：canonical SDF 签名引用与 wrapped-SM4 provider 恢复 artifact。
- [docs/integrations/SDF_SIGNER.md](docs/integrations/SDF_SIGNER.md)：隔离 SDF 签名 sidecar、稳定厂商适配 ABI、SM2/SM4 托管边界、配置与真机资格测试。
- [formats/SM4_KEY_ENVELOPE_V1.md](formats/SM4_KEY_ENVELOPE_V1.md)：canonical 认证软件私钥 envelope、passphrase KDF profile 和原子持久化契约。
- [formats/KEY_REGISTRY_V2.md](formats/KEY_REGISTRY_V2.md)：Registry V2 字节布局、manifest、事件链、生命周期、恢复和兼容性契约。
- [formats/DISTRIBUTED_ARCHITECTURE.md](formats/DISTRIBUTED_ARCHITECTURE.md)：分布式/存算分离说明。
- [docs/performance/trustdb-sustained-stream-persistence-assessment-2026-07-23.zh-CN.md](docs/performance/trustdb-sustained-stream-persistence-assessment-2026-07-23.zh-CN.md)：唯一双机性能口径，覆盖 L2-L5、HTTP/gRPC、背压、持久化与多种配置语义。
- [docs/performance/trustdb-performance-optimization-2026-07.zh-CN.md](docs/performance/trustdb-performance-optimization-2026-07.zh-CN.md)：性能优化实现说明。

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
