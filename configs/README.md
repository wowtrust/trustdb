# TrustDB configuration templates

Shipped YAML files are **starting points** only: adjust paths, keys, `server.listen`, anchor calendars, and TiKV endpoints for your environment.

Every `keys.*` path points to a canonical
`trustdb.key-descriptor.v1` file, not raw Base64 key bytes. A software signer
descriptor references separate private material relative to the descriptor;
PKCS#11, SDF, and remote descriptors reference non-exportable provider keys.
Legacy raw-key files are rejected. See
[`formats/KEY_DESCRIPTOR_V1.md`](../formats/KEY_DESCRIPTOR_V1.md).

`anchor.poll_interval` controls the O(1) durable scheduler recovery lookup. Triggered work normally starts immediately; polling resumes pending or in-flight work after missed triggers and restarts. Benchmark profiles use `250ms`, while the default remains `2s` to limit idle store reads.

| File | `run_profile` | Purpose |
| --- | --- | --- |
| `development.yaml` | `development` | Local demos: file proofstore, `noop` anchor, debug-friendly logging. |
| `production.yaml` | `single_node_production` | Single-node baseline: Pebble (or TiKV) proofstore, OTS anchor, JSON logs. |
| `benchmark.yaml` | `benchmark` | Throughput experiments: Pebble, `wal.fsync_mode: batch`, async batch proofs, `noop` anchor. |
| `benchmark-extreme.yaml` | `benchmark` | Absolute L2 ceiling with on-demand proofs and intentionally unsafe durability. |
| `benchmark-burst.yaml` | `benchmark` | Maximum short-lived L2 burst absorption; 32 ingest workers, large queue, L4/L5 disabled. |
| `benchmark-l3-throughput.yaml` | `benchmark` | Sustained high-write L2/L3 balance; 16 ingest workers and four materializers. |
| `benchmark-proof-ready.yaml` | `benchmark` | Gives more CPU and queue slots to L3 materialization at the expense of peak Submit TPS. |
| `benchmark-balanced.yaml` | `benchmark` | Group-fsync WAL, reduced secondary indexes, batched artifacts, and L4 enabled. |
| `benchmark-production-safe.yaml` | `benchmark` | Full indexes, chunk-sync artifacts, group-fsync WAL, L4 and OTS-ready L5. |
| `benchmark-production-guaranteed.yaml` | `benchmark` | Strict per-record WAL fsync plus full indexes, chunk-sync artifacts, L4 and OTS. |
| `benchmark-large-payload.yaml` | `benchmark` | Dedicated 16 KiB and 64 KiB payload profile. |

`benchmark*.yaml` files use separate data directories. Do not point them at an
existing proofstore: file, Pebble, and each TiKV namespace now require storage
schema v4 and intentionally refuse legacy or unversioned layouts instead of
deleting or migrating them.

## `run_profile`

Optional top-level string. It **does not change behavior**; `trustdb serve` logs the label and short risk hints so operators know which template mindset they started from.

Allowed values (aliases accepted): `development` (`dev`), `single_node_production` (`prod`, `production`, `single-node-prod`), `benchmark` (`bench`, `loadtest`).

Override via `TRUSTDB_RUN_PROFILE`.

If omitted, serve logs that the deployment is treated as **custom**.

## Admin Web (`admin`)

Optional block `admin` enables the operator UI mounted by `trustdb serve` (see repository README). Use `TRUSTDB_ADMIN_*` env vars in production; set `admin.password_hash` to a bcrypt string from `trustdb admin hash-password`, and `admin.session_secret` to at least 32 random bytes.
