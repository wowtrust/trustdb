# TrustDB configuration templates

Shipped YAML files are **starting points** only: adjust paths, keys, `server.listen`, anchor calendars, and TiKV endpoints for your environment.

| File | `run_profile` | Purpose |
| --- | --- | --- |
| `development.yaml` | `development` | Local demos: file proofstore, `noop` anchor, debug-friendly logging. |
| `production.yaml` | `single_node_production` | Single-node baseline: Pebble (or TiKV) proofstore, OTS anchor, JSON logs. |
| `benchmark.yaml` | `benchmark` | Throughput experiments: Pebble, `wal.fsync_mode: batch`, async batch proofs, `noop` anchor. |
| `benchmark-l3-throughput.yaml` | `benchmark` | Reproduces the high-write L2/L3 profile from the April performance report. |
| `benchmark-production-safe.yaml` | `benchmark` | Group-fsync, full-index, L4 and OTS L5 performance validation. |
| `benchmark-large-payload.yaml` | `benchmark` | Dedicated 16 KiB/64 KiB claim and artifact pressure tests. |

`benchmark*.yaml` files use separate data directories. Do not point them at an
existing proofstore: the Pebble proofstore now requires storage schema v2 and
intentionally refuses legacy key layouts instead of deleting or migrating them.

## `run_profile`

Optional top-level string. It **does not change behavior**; `trustdb serve` logs the label and short risk hints so operators know which template mindset they started from.

Allowed values (aliases accepted): `development` (`dev`), `single_node_production` (`prod`, `production`, `single-node-prod`), `benchmark` (`bench`, `loadtest`).

Override via `TRUSTDB_RUN_PROFILE`.

If omitted, serve logs that the deployment is treated as **custom**.

## Admin Web (`admin`)

Optional block `admin` enables the operator UI mounted by `trustdb serve` (see repository README). Use `TRUSTDB_ADMIN_*` env vars in production; set `admin.password_hash` to a bcrypt string from `trustdb admin hash-password`, and `admin.session_secret` to at least 32 random bytes.
