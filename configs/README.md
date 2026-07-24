# TrustDB configuration templates

Shipped YAML files are **starting points** only: adjust paths, keys, `server.listen`, anchor calendars, and TiKV endpoints for your environment.

The production and container profiles enable mutual TLS and intentionally do
not start without mounted transport certificates. See
[`docs/integrations/TLS_MTLS.md`](../docs/integrations/TLS_MTLS.md) for TLS 1.2/1.3,
CA pinning, rotation, revocation, SDK, desktop, and health-check configuration.
Transport CA files are independent from every `keys.*` proof-signing path.

Every `keys.*` path points to a canonical
`trustdb.key-descriptor.v1` file, not raw Base64 key bytes. A software signer
descriptor references separate private material relative to the descriptor;
PKCS#11, SDF, and remote descriptors reference non-exportable provider keys.
Legacy raw-key files are rejected. See
[`formats/KEY_DESCRIPTOR_V1.md`](../formats/KEY_DESCRIPTOR_V1.md).

`anchor.poll_interval` controls the O(1) durable scheduler recovery lookup. Triggered work normally starts immediately; polling resumes pending or in-flight work after missed triggers and restarts. Benchmark profiles use `250ms`, while the default remains `2s` to limit idle store reads.

The optional `nats` section is disabled by default. Enabling, pre-provisioning,
securing, sizing, and consuming the JetStream ingress is documented in the
[NATS ingress guide](../docs/integrations/NATS_INGRESS.md). Keep the generated
configuration as the field reference; the guide explains the operational
semantics and recovery boundaries.

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

## Software key envelopes

`trustdb key generate` defaults to an authenticated `sm4-envelope-v1` material
file. The built-in development KEK provider reads
exactly one of `TRUSTDB_DEV_KEY_PASSPHRASE` or
`TRUSTDB_DEV_KEY_PASSPHRASE_FILE`; it is intentionally not a YAML field or
ordinary CLI flag, so configuration display and process arguments cannot
expose the value. The file source must be an owner-only regular file supplied
outside the envelope directory and its backup volume. Every process that opens
an encrypted software signer must receive the same source. This provider is
for development/offline deployments, not production HSM custody. Production
profiles should use an approved PKCS#11, SDF, HSM/KMS, or remote signer
descriptor. Windows software-envelope persistence fails closed until an
owner-only DACL is continuously runtime-qualified.

The owner-permissions-only compatibility path requires explicit
`--protection plaintext-dev-v1` and must not be used in production.

## Admin Web (`admin`)

Optional block `admin` enables the operator UI mounted by `trustdb serve` (see repository README). Use `TRUSTDB_ADMIN_*` env vars in production; set `admin.password_hash` to a bcrypt string from `trustdb admin hash-password`, and `admin.session_secret` to at least 32 random bytes.
