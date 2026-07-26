# TrustDB configuration templates

Shipped YAML files are **starting points** only: adjust paths, keys, `server.listen`, anchor calendars, and TiKV endpoints for your environment.

The production and container profiles enable mutual TLS and intentionally do
not start without mounted transport certificates. See
[`docs/integrations/TLS_MTLS.md`](../docs/integrations/TLS_MTLS.md) for TLS 1.2/1.3,
CA pinning, rotation, revocation, SDK, desktop, and health-check configuration.
Transport CA files are independent from every `keys.*` proof-signing path.
For SM2/SM3 dual-certificate mutual authentication and SM4-GCM at an external
transport boundary, use the separate
[`docs/integrations/TLCP_GATEWAY.md`](../docs/integrations/TLCP_GATEWAY.md)
profile; TrustDB listeners remain loopback plaintext inside the restricted
gateway network namespace.

Every `keys.*` path points to a canonical
`trustdb.key-descriptor.v1` file, not raw Base64 key bytes. A software signer
descriptor references separate private material relative to the descriptor;
PKCS#11, SDF, and remote descriptors reference non-exportable provider keys.
Legacy raw-key files are rejected. See
[`formats/KEY_DESCRIPTOR_V1.md`](../formats/KEY_DESCRIPTOR_V1.md).

## External signer plugins

`software` descriptors work without extra configuration. A signer descriptor
whose provider is `remote`, `pkcs11`, or `sdf` requires a matching supervised
plugin configuration. For example:

```yaml
crypto:
  signer_plugins:
    remote:
      command: "/usr/local/bin/trustdb-kms-adapter"
      args: ["--config", "/etc/trustdb/kms-adapter.yaml"]
      inherit_env: ["AWS_REGION", "AWS_WEB_IDENTITY_TOKEN_FILE"]
      start_timeout: "10s"
      rpc_timeout: "30s"
      max_concurrency: 16
```

The child receives no ambient environment unless a variable name is listed in
`inherit_env`. Plugin arguments are redacted from config diagnostics. Provider
selection is exact: if a descriptor names an unconfigured or unavailable
provider, TrustDB fails instead of falling back to a software key. See
[`formats/SIGNER_PLUGIN_V1.md`](../formats/SIGNER_PLUGIN_V1.md).

The built-in standalone PKCS#11 sidecar, owner-only PIN file configuration,
explicit SM2 mechanism gate, SoftHSM interoperability target, rotation rules,
and production qualification checklist are documented in
[`docs/integrations/PKCS11_SIGNER.md`](../docs/integrations/PKCS11_SIGNER.md).
The native module is linked only into the sidecar built with `-tags=pkcs11`,
not into the TrustDB server.

The optional SDF sidecar, stable deployment-owned adapter ABI, exact
SM2-digest boundary, SM4 KEK handle/envelope rules, cross-platform gates, and
real-device qualification procedure are documented in
[`docs/integrations/SDF_SIGNER.md`](../docs/integrations/SDF_SIGNER.md). Vendor
SDKs and proprietary libraries remain outside TrustDB core.

Signer plugins are trusted executables and run with the TrustDB process's OS
account; environment filtering is not a filesystem or syscall sandbox. Do not
put credentials in `args`, because operating-system process listings may expose
them. Use descriptor credential references and narrowly scoped `inherit_env`
entries instead.

Shutdown is bounded and best-effort: TrustDB closes the RPC connection, asks
the child to exit with an OS interrupt where supported, and force-terminates it
if signaling is unavailable or the timeout expires. Windows currently takes the
force-termination path because Go does not implement `os.Interrupt` there.
Adapters must therefore keep provider state crash-safe and must not rely only on
shutdown hooks to release or reconcile HSM/KMS sessions.

`anchor.poll_interval` controls the O(1) durable scheduler recovery lookup. Triggered work normally starts immediately; polling resumes pending or in-flight work after missed triggers and restarts. Benchmark profiles use `250ms`, while the default remains `2s` to limit idle store reads.

`wal.max_segment_bytes` enables size-based directory-WAL rotation when greater
than zero. `wal.keep_segments` retains that many segments older than the
checkpoint-covered segment after a safe checkpoint advance; zero keeps only
the active and checkpoint-covered segments. Both values default to zero to
preserve the existing no-size-rotation policy. Explicit
`--wal-max-segment-bytes` and `--wal-keep-segments` flags override YAML and
environment values.

`backup` configures encrypted `.tdbackup v5` output. `compression` is applied
before encryption; `frame_bytes` is the authenticated SM4-GCM plaintext frame
size (64 KiB–16 MiB, default 1 MiB). `key_provider` selects the KEK adapter and
`key_id` is a non-secret reference stored in the archive header. The built-in
`passphrase-dev-v1` provider reads exactly one of
`TRUSTDB_BACKUP_PASSPHRASE` or `TRUSTDB_BACKUP_PASSPHRASE_FILE`; it is for
development and offline drills. It never follows key-registry descriptor
references to copy private material. See the
[backup and recovery guide](../docs/zh-CN/BACKUP_AND_RECOVERY.md) and
[format contract](../formats/BACKUP_V5.md).

The optional `nats` section is disabled by default. Enabling, pre-provisioning,
securing, sizing, and consuming the JetStream ingress is documented in the
[NATS ingress guide](../docs/integrations/NATS_INGRESS.md). Keep the generated
configuration as the field reference; the guide explains the operational
semantics and recovery boundaries.

| File | `run_profile` | Purpose |
| --- | --- | --- |
| `development.yaml` | `development` | Local demos: file proofstore, `noop` anchor, debug-friendly logging. |
| `production.yaml` | `single_node_production` | Single-node baseline: Pebble (or TiKV) proofstore, OTS anchor, JSON logs. |
| `china-production.yaml` | `china_production` | Enforced CN_SM_V1, non-software keys, pinned mTLS/TLCP boundary, explicit egress, signed audit, and Guomi FISCO BCOS. |
| `offline-isolated.yaml` | `offline_isolated` | Internet-independent runtime with all TrustDB outbound connections denied. |
| `assessment.yaml` | `assessment` | China production controls with signed, approved, maximum-30-day exceptions. |
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
schema v5 and intentionally refuse legacy or unversioned layouts instead of
deleting or migrating them.

## `run_profile`

Optional top-level string. `development`, `single_node_production`, and
`benchmark` retain their existing flexible behavior and guidance. The
`china_production`, `offline_isolated`, and `assessment` profiles are enforced
startup policies: TrustDB rejects unsafe transports, suites, key providers,
egress, anchor trust, audit, and backup custody before serving traffic.

Allowed values include `development`, `single_node_production`,
`china_production`, `offline_isolated`, `assessment`, and `benchmark`.

Override via `TRUSTDB_RUN_PROFILE`.

If omitted, serve logs that the deployment is treated as **custom**.

See [China deployment profiles](../docs/compliance/CHINA_DEPLOYMENT_PROFILES.md)
for the exact policy, egress/DNS syntax, offline mirror inventory, exception
contract, deployment sequence, and required negative tests.

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

The `admin` block points to a versioned, separated RBAC policy. Bootstrap it
with `trustdb admin policy bootstrap`; do not put plaintext passwords in YAML.
`admin.enabled` mounts the operator UI, while `admin.cli_enforce` independently
protects privileged commands. The production template enables CLI enforcement,
so bootstrap `/etc/trustdb/admin-policy.json` before running protected commands.
Set `admin.session_secret` to at least 32 random bytes only when the Web console
is enabled. See [Administrative RBAC](../docs/compliance/ADMINISTRATIVE_RBAC.md) and the
[Chinese guide](../docs/zh-CN/ADMINISTRATIVE_RBAC.md).

## Immutable security audit (`audit`)

`audit.enabled` opens a dedicated signed and hash-chained control-plane audit
trail. `audit.required` makes audit persistence a fail-closed prerequisite for
privileged CLI and Admin HTTP operations. The `single_node_production` profile
requires both values plus `require_synchronized_time`.

`signing_key` is a canonical signer descriptor and may select software, remote,
PKCS#11, or SDF custody. `path` and `checkpoint_path` must be different protected
files. `max_bytes` is a hard capacity boundary; TrustDB never silently deletes
or rotates audit history. `retention` is signed into each event as its retention
deadline. The time-reference file records source, sample age, offset,
uncertainty, synchronization, and confidence; a local-only reference cannot
satisfy production synchronized-time policy.

Use `trustdb audit status`, `audit export`, `audit verify`, and
`audit checkpoint export|verify` for operations and offline continuity checks.
The full setup, capacity formula, protected-file rules, external checkpoint
custody, backup boundary, and incident runbook are in
[Immutable security audit](../docs/compliance/IMMUTABLE_SECURITY_AUDIT.md) and
the [Chinese guide](../docs/zh-CN/IMMUTABLE_SECURITY_AUDIT.md).
