# Immutable security audit and trusted-time evidence

TrustDB maintains a dedicated security audit chain for privileged control-plane
activity. It is separate from application logs, Prometheus metrics, business
records, the WAL, and `.sproof` evidence. The chain is intended for incident
reconstruction, change accountability, separation-of-duty review, and
independent continuity checks.

Production mode fails closed when the audit chain, signer, protected storage,
or required synchronized-time reference is unavailable. A blocked operation is
recorded with `result=blocked` and the observed time status before the error is
returned whenever protected storage remains writable.

This feature does **not** claim that the local system clock, an NTP sample, or a
FISCO BCOS block timestamp is a legally recognized trusted timestamp. It records
the exact time source and confidence observed by TrustDB. Legal timestamping,
where required, remains an independently governed external service.

## 1. Security properties

Each event is canonical CBOR, signed, and linked to the previous event hash.

- `INTL_V1` uses Ed25519 and SHA-256.
- `CN_SM_V1` uses SM2 and SM3.
- Sequence gaps, event mutation, reordered events, invalid signatures,
  truncation, and rollback against the latest signed checkpoint are rejected.
- Sensitive context keys containing `password`, `secret`, `token`, `private`,
  `credential`, `cookie`, `authorization`, `payload`, or `content` are replaced
  by `<redacted>` before signing.
- Emergency reasons are represented by a SHA-256 digest; raw reasons are not
  written to the audit chain or normal structured logs.
- Audit files are regular, non-symlink files. On Unix they must be owned by the
  process user and inaccessible to group/other users; their parent directory
  must not be group/other writable. On Windows they use a protected DACL with
  one full-access ACE for the process owner.
- The mutable writer state remains O(1). Stable single-process appends use a
  signed-checkpoint fast path instead of rescanning the chain. A JSONL export
  fixes a signed byte-length snapshot and releases the cross-process writer lock
  before streaming output.

The event records actor, roles, action, object, result, request ID, source,
policy version, local time, time-source evidence, retention deadline, and
bounded redacted context. The audit signer may be a software, remote, PKCS#11,
or SDF signer descriptor; TrustDB never falls back to a different provider.

## 2. Audited operations

The CLI writes a durable authorization intent before every annotated operation
and a result after it completes. Searchable action families include:

| Action family | Examples |
| --- | --- |
| `security.policy.*` | RBAC bootstrap, inspect, update, offline recovery |
| `key.lifecycle` | generate, register, rotate, revoke, compromise, rewrap |
| `backup.*` | create, verify, restore |
| `anchor.configuration` | anchor configuration and management |
| `trust.configuration` | FISCO BCOS TrustConfig creation and checkpoint advancement |
| `system.configuration` | configuration changes |
| `system.operation` | server start/stop and privileged maintenance |
| `audit.*` | status, export, and checkpoint export |

Admin HTTP records login success/failure, authentication and authorization
denials, authorization intent, request outcome, logout, policy replacement, and
configuration replacement. A required audit write failure returns HTTP 503
before session issuance or before an authorized handler starts. The generic
Admin configuration endpoint cannot modify the `admin` or `audit` blocks.

Server lifecycle and listener-certificate reload failures are also recorded.
The request source is stored as a digest, not a raw IP address.

## 3. Configure the signer

Generate a dedicated audit identity before enabling required audit. The audit
key is independent from client and server proof-signing keys. For a local
`CN_SM_V1` development or offline test:

### Linux and macOS

```bash
mkdir -p .trustdb-audit-key
read -r -s -p 'Audit key passphrase: ' TRUSTDB_DEV_KEY_PASSPHRASE
printf '\n'
export TRUSTDB_DEV_KEY_PASSPHRASE
./bin/trustdb key generate \
  --suite CN_SM_V1 \
  --out .trustdb-audit-key \
  --prefix audit
unset TRUSTDB_DEV_KEY_PASSPHRASE
```

### Windows PowerShell

```powershell
# Disposable test only; use SDF/PKCS#11/remote custody in production.
New-Item -ItemType Directory -Force .trustdb-audit-key | Out-Null
.\bin\trustdb.exe key generate `
  --suite CN_SM_V1 `
  --out .trustdb-audit-key `
  --prefix audit `
  --protection plaintext-dev-v1
```

`--out` is a local output directory. These commands create `audit.key` (signer
descriptor), `audit.pub` (public verifier descriptor), and `audit.material`
(private material). The PowerShell example uses `plaintext-dev-v1` only because
Windows software-envelope persistence currently fails closed; it is disposable
test material. Production should use an approved SDF, PKCS#11, HSM/KMS, or
remote descriptor instead of either development path.

Keep `audit.pub` in the verifier's independently controlled trust store. An
export embeds a matching public key as metadata, but that embedded key is never
accepted as a trust root by itself.

## 4. Supply the time-reference file

When `require_synchronized_time` is true, a local time-monitor agent must
atomically refresh a protected JSON file before `time_max_sample_age` expires.
The agent should derive its values from the deployment's approved time source,
not from a hard-coded success value.

```json
{
  "schema_version": "trustdb.time-reference.v1",
  "source": "chrony-ntp-auth",
  "sampled_at_unix_nano": 1785037200000000000,
  "offset_nanos": 12000000,
  "uncertainty_nanos": 8000000,
  "synchronized": true,
  "confidence": "authenticated"
}
```

Supported confidence labels are `authenticated`, `network`, `hardware`, and
`local`. `local` is always recorded as `unverified` and cannot satisfy required
synchronization. TrustDB records one of `synchronized`, `stale`,
`drift-exceeded`, `unsynchronized`, `unavailable`, `invalid`, or `unverified`.
Future-dated samples, excessive `abs(offset)+uncertainty`, malformed JSON, an
unsafe file, and a missing file fail closed when synchronization is required.

Write the file atomically: create a new owner-protected file in the same
directory, fsync it, then replace the configured path. Do not update it in
place. The time monitor and TrustDB service must use an ownership/ACL model that
satisfies the protected-file checks.

## 5. Production YAML

The shipped `configs/production.yaml` contains the required baseline:

```yaml
audit:
  enabled: true
  required: true
  path: "/var/lib/trustdb/audit/security.audit"
  checkpoint_path: "/var/lib/trustdb/audit/security.checkpoint"
  signing_key: "/etc/trustdb/keys/audit.tdkey"
  max_bytes: 4294967296
  retention: "4380h"
  time_reference_path: "/run/trustdb/time-reference.json"
  time_max_sample_age: "2m"
  time_max_drift: "5s"
  require_synchronized_time: true
```

`single_node_production` requires `enabled`, `required`, and
`require_synchronized_time`. The log path and checkpoint path must differ.
`max_bytes` must be at least 1 MiB; `retention` must be at least 24 hours.

The retention value is signed into each event as a deadline. TrustDB does not
silently delete or rotate audit history. Reaching `max_bytes` blocks further
audited operations. Increase capacity before the limit is reached; never remove
the current log or checkpoint to regain space.

## 6. Operate and verify

Verify the live chain and its local checkpoint:

```bash
./bin/trustdb --config /etc/trustdb/trustdb.yaml audit status
```

Export a complete immutable JSONL snapshot:

```bash
./bin/trustdb --config /etc/trustdb/trustdb.yaml audit export \
  --out /secure-export/trustdb-audit-2026-07-26.jsonl
```

Verify it without a server, provider, or network connection:

```bash
./bin/trustdb audit verify \
  --file /secure-export/trustdb-audit-2026-07-26.jsonl \
  --public-key /verifier-trust/audit.pub
```

Export the compact signed chain head for independent retention or opaque-byte
anchoring:

```bash
./bin/trustdb --config /etc/trustdb/trustdb.yaml audit checkpoint export \
  --out /secure-export/trustdb-audit-checkpoint-2026-07-26.json

./bin/trustdb audit checkpoint verify \
  --file /secure-export/trustdb-audit-checkpoint-2026-07-26.json \
  --public-key /verifier-trust/audit.pub
```

The verifier performs no network access. Store periodic checkpoint artifacts in
an independent WORM/object-lock system or submit their exact bytes/digest to an
approved external timestamp/anchor process. Preserve the external service's
receipt alongside the checkpoint. TrustDB does not interpret that receipt as a
legal timestamp automatically.

An export contains the authorization intent that permitted the export. The
export command's final result event is appended after the snapshot is fixed and
will appear in the next export.

## 7. Retention and capacity planning

Use measured event sizes and peak control-plane activity:

```text
required bytes = peak events/day × measured bytes/event × retention days × safety factor
```

The default 4 GiB over `4380h` (182.5 days) permits about 23.5 MiB/day. At an
average encoded size of 2 KiB, that is roughly 12,000 events/day before adding a
safety margin. Login attacks can create audit events, so size from rejected as
well as successful requests. Alert on filesystem free space and audit-file
growth well before either the disk or `max_bytes` limit is reached.

`.tdbackup v5` does not replace the security-audit export. Back up proof data
with `trustdb backup`, and separately retain the audit JSONL, signed checkpoint,
trusted public-key descriptor, time-monitor configuration, and external anchor
receipt. A restore is itself audited, but it does not overwrite the destination
deployment's audit history.

## 8. Incident response

| Symptom | Required response |
| --- | --- |
| `audit rollback or truncation detected` | Stop privileged operations, preserve the log/checkpoint/lock files byte-for-byte, compare the latest independently retained checkpoint, and investigate rollback. Do not truncate or recreate files. |
| `unsafe storage` | Correct ownership, file mode/DACL, parent-directory writability, symlinks, or file type. Do not make an unsafe existing file acceptable by silently replacing evidence. |
| `configured audit capacity exhausted` | Preserve the chain, add disk capacity, raise the reviewed `max_bytes`, and restart. Never delete the checkpoint or tail. |
| `trusted time requirement is not satisfied` | Repair the time monitor/source, refresh the reference atomically, and confirm age, offset, uncertainty, confidence, permissions, and schema. The blocked attempt remains in the chain when storage was available. |
| signature or public-key mismatch | Verify with the independently distributed `audit.pub` matching suite, KeyID, algorithm, encoding, and bytes. Treat unexpected key changes as an incident. |

If an attacker can roll back the audit log, local checkpoint, all backups, and
every independently retained checkpoint together, a purely local verifier
cannot prove the missing history existed. Independent checkpoint custody is
therefore mandatory for rollback detection beyond one host's trust boundary.
