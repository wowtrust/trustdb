# TrustDB

![CI](https://github.com/ryan-wong-coder/trustdb/actions/workflows/ci.yml/badge.svg)

[Official Website](https://ryan-wong-coder.github.io/trustdb-website/) | [中文说明](README.zh-CN.md) | [Contributing](CONTRIBUTING.md) | [`.sproof` format](formats/SPROOF_V1.md)

TrustDB is a verifiable evidence database for file claims and proof exchange. It turns a local file hash into a signed claim, a durable server receipt, a batch Merkle proof, a global transparency-log proof, and optionally an externally anchored Signed Tree Head (STH).

Documentation, quick start guides, releases, and feedback channels are available on the [TrustDB official website](https://ryan-wong-coder.github.io/trustdb-website/).

![TrustDB system architecture](assets/readme/system-architecture.png)

Module:

```text
github.com/ryan-wong-coder/trustdb
```

License: AGPL-3.0-only. See [LICENSE](LICENSE).

## What It Provides

- Deterministic CBOR models for claims, receipts, proof bundles, global-log proofs, STHs, anchor results, backups, and `.sproof` files.
- Ed25519 signing for client, server, and key-registry workflows.
- WAL-backed ingest with bounded queues, configurable fsync policy, replay, checkpoints, and graceful shutdown.
- Batch Merkle proofs, persisted record indexes, and paginated record/root APIs.
- Global Transparency Log with persisted STHs, inclusion proofs, consistency proofs, and history tiles.
- L5 STH/global-root anchoring through `off`, `noop`, file, and OpenTimestamps sinks.
- File, Pebble, and TiKV proofstore backends. TiKV enables storage-compute separation for multiple TrustDB compute nodes sharing durable proof data.
- Portable `.tdbackup` create, verify, and resumable restore.
- Go SDK for claim signing, HTTP/gRPC calls, proof export, and local verification.
- Wails + Vue desktop client for local identity, file attestation, record management, proof refresh, `.sproof` export, and offline verification.
- Optional Vue Admin Web mounted by `trustdb serve` for metrics, read-only browsing, and controlled YAML config maintenance.

## Proof Levels

![TrustDB proof levels](assets/readme/proof-levels.png)

| Level | Meaning | Primary artifact |
| --- | --- | --- |
| L1 | Client signs a claim containing the content hash and metadata. | `SignedClaim` / `.tdclaim` |
| L2 | Server validates and accepts the claim into the durable WAL boundary. | `AcceptedReceipt` |
| L3 | The accepted claim is committed into a batch Merkle tree. | `ProofBundle` / `.tdproof` |
| L4 | The batch root is included in the Global Transparency Log and a target STH. | `GlobalLogProof` / `.tdgproof` |
| L5 | The corresponding STH/global root is externally anchored. | `STHAnchorResult` / `.tdanchor-result` |

For exchange and desktop verification, `.sproof` is the recommended single-file proof container. It can include the L3 `ProofBundle`, optional L4 `GlobalLogProof`, and optional L5 `STHAnchorResult`. The stable v1 format is documented in [formats/SPROOF_V1.md](formats/SPROOF_V1.md).

## Architecture

TrustDB runs as a single-node service by default. With the TiKV proofstore backend, multiple compute nodes can share the same durable proofstore while preserving `node_id` and `log_id` metadata for source identity.

Core paths:

- Client path: CLI, SDK, or desktop computes a file hash, signs a claim, and submits it locally or to the server.
- Ingest path: the server validates signatures and key state, appends durable acceptance to WAL, and returns an accepted receipt.
- Batch path: accepted records are grouped into Merkle batches and stored as proof bundles plus indexes.
- Global log path: committed batch roots are appended into the global transparency log, producing persisted STHs and global proofs.
- Anchor path: STH/global roots are queued and published by the configured anchor worker.
- Storage path: proof data is stored in file, Pebble, or TiKV proofstores.
- Backup path: proofstore data can be exported to `.tdbackup`, verified, and restored with resume checkpoints.
- Observability path: `/metrics` exposes ingest, batch, global log, anchor, WAL, backup, and storage metrics.

## Quick Start

Generate client and server keys:

```powershell
go run ./cmd/trustdb keygen --out .trustdb-dev --prefix client
go run ./cmd/trustdb keygen --out .trustdb-dev --prefix server
```

Start a local development server:

```powershell
go run ./cmd/trustdb serve `
  --config configs/development.yaml `
  --server-private-key .trustdb-dev/server.key `
  --client-public-key .trustdb-dev/client.pub `
  --listen 127.0.0.1:8080
```

Create and sign a file claim:

```powershell
go run ./cmd/trustdb claim-file `
  --file .\example.txt `
  --private-key .trustdb-dev/client.key `
  --tenant default `
  --client local-client `
  --key-id client-key `
  --out .trustdb-dev/example.tdclaim
```

Commit a claim locally into a proof bundle:

```powershell
go run ./cmd/trustdb commit `
  --claim .trustdb-dev/example.tdclaim `
  --server-private-key .trustdb-dev/server.key `
  --client-public-key .trustdb-dev/client.pub `
  --out .trustdb-dev/example.tdproof
```

Verify a local file with a proof:

```powershell
go run ./cmd/trustdb verify `
  --file .\example.txt `
  --proof .trustdb-dev/example.tdproof `
  --server-public-key .trustdb-dev/server.pub `
  --client-public-key .trustdb-dev/client.pub
```

Verify the recommended single-file `.sproof` artifact:

```powershell
go run ./cmd/trustdb verify `
  --file .\example.txt `
  --sproof .trustdb-dev/example.sproof `
  --server-public-key .trustdb-dev/server.pub `
  --client-public-key .trustdb-dev/client.pub
```

Create and verify a portable backup:

```powershell
go run ./cmd/trustdb backup create `
  --metastore file `
  --metastore-path .trustdb-dev/proofs `
  --out .trustdb-dev/trustdb.tdbackup

go run ./cmd/trustdb backup verify --file .trustdb-dev/trustdb.tdbackup
```

## HTTP And gRPC

Implemented HTTP endpoints:

| Endpoint | Purpose |
| --- | --- |
| `GET /healthz` | Health check. |
| `POST /v1/claims` | Submit a signed claim. |
| `POST /v1/claims/batch` | Submit a CBOR batch of signed claims. |
| `GET /v1/records` | Paginated record list and search. |
| `GET /v1/records/{record_id}` | Read record index details. |
| `GET /v1/proofs/{record_id}` | Fetch L3 proof bundle. |
| `GET /v1/roots` | List batch roots. |
| `GET /v1/roots/latest` | Fetch latest batch root. |
| `GET /v1/sth/latest` | Fetch latest SignedTreeHead. |
| `GET /v1/sth/{tree_size}` | Fetch a specific STH. |
| `GET /v1/global-log/inclusion/{batch_id}` | Fetch global-log inclusion proof for a batch. |
| `GET /v1/global-log/consistency?from=&to=` | Fetch global-log consistency proof. |
| `GET /v1/anchors/sth/{tree_size}` | Fetch STH anchor status or result. |
| `GET /metrics` | Prometheus metrics. |

The optional gRPC listener is enabled with `--grpc-listen` or `server.grpc_listen`. It uses TrustDB's deterministic CBOR payload model so HTTP and gRPC transports share proof semantics.

## Configuration

Configuration examples live in [configs](configs):

| File | Intended use |
| --- | --- |
| `configs/development.yaml` | Local development and demos. Uses file proofstore and `noop` anchoring. |
| `configs/production.yaml` | Single-node production baseline with Pebble proofstore, directory WAL, group fsync, global log, and OTS anchoring. |
| `configs/benchmark-extreme.yaml` | Maximum L2 accepted-receipt throughput with on-demand proofs; not for production. |
| `configs/benchmark-burst.yaml` | Short burst absorption with large batches and queues. |
| `configs/benchmark-l3-throughput.yaml` | High-write asynchronous L3 throughput and drain tests. |
| `configs/benchmark-proof-ready.yaml` | Prioritizes L3 materialization and lower proof backlog. |
| `configs/benchmark-balanced.yaml` | Group fsync, reduced index amplification, and L4 proofs. |
| `configs/benchmark-production-safe.yaml` | Durable L4/L5 end-to-end performance tests. |
| `configs/benchmark-production-guaranteed.yaml` | Strict fsync, full indexes, and L4/L5 performance floor. |
| `configs/benchmark-large-payload.yaml` | 16 KiB and 64 KiB payload pressure tests. |
| `configs/benchmark.yaml` | Benchmark profile with throughput-oriented settings. Not a production audit profile. |

See [configs/README.md](configs/README.md) for `run_profile` semantics and startup notes.

## Admin Web And Desktop

The optional Admin Web (`clients/web`) is served under `/admin` by `trustdb serve` when enabled. It provides metrics, read-only API browsing, and YAML config maintenance when the server is started with `--config`.

The desktop client (`clients/desktop`) is a Wails + Vue application for local identity setup, file attestation, server settings, local record indexes, proof refresh, proof export, and offline verification.

![TrustDB desktop overview](assets/readme/desktop-overview.png)

## Project Documents

- [CONTRIBUTING.md](CONTRIBUTING.md): issue, PR, commit, validation, and review standards.
- [formats/SPROOF_V1.md](formats/SPROOF_V1.md): stable `.sproof` v1 exchange format.
- [formats/DISTRIBUTED_ARCHITECTURE.md](formats/DISTRIBUTED_ARCHITECTURE.md): distributed/storage-compute separation notes.
- [docs/performance/trustdb-performance-report-2026-07-16.zh-CN.md](docs/performance/trustdb-performance-report-2026-07-16.zh-CN.md): latest comprehensive dual-host performance report (Chinese).
- [docs/performance/trustdb-performance-optimization-2026-07.zh-CN.md](docs/performance/trustdb-performance-optimization-2026-07.zh-CN.md): performance implementation notes (Chinese).
- [docs/performance/trustdb-performance-report-2026-04-30.en.md](docs/performance/trustdb-performance-report-2026-04-30.en.md): previous performance-first baseline.

## Development Checks

Use the smallest relevant set while iterating, then run broader checks before merge:

```powershell
go test ./...
go test -race ./...
go test -tags=integration ./...
go test -tags=e2e ./...
```

Frontend and desktop checks:

```powershell
cd clients/web
npm ci
npm run build

cd ../desktop
go test ./...
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the standard issue, PR, and commit formats.
