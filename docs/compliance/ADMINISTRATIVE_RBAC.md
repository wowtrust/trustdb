# Administrative RBAC, separation of duties, and recovery

TrustDB uses a versioned `trustdb.admin-policy.v1` document for every privileged
administrative identity. The policy replaces the former single-user Admin Web
credential. It is shared by the Admin Web and optional local CLI enforcement,
is stored with owner-only permissions, and retains each predecessor revision in
an immutable history directory.

The control protects operational access; it does not change record, Merkle,
Signed Tree Head, anchor, backup, or offline-proof semantics.

## Role and permission matrix

| Role | Intended owner | Permissions |
| --- | --- | --- |
| `system-admin` | Platform operations | `system.read`, `system.configure`, `system.operate` |
| `security-admin` | Security governance | security-policy read/write, trust-policy read/write, session management, `system.read` |
| `audit-admin` | Independent audit | audit read/export, security-policy read, `system.read` |
| `key-operator` | Key ceremony team | key read/manage |
| `backup-operator` | Recovery team | backup read/create/restore |
| `anchor-governor` | External-publication owner | anchor read/manage, trust read |
| `support-readonly` | Support | read-only system, key, backup, anchor, and trust views |
| `emergency-admin` | Sealed break-glass custody | all permissions, only during a bounded emergency interval |

An ordinary account cannot hold more than one of `system-admin`,
`security-admin`, and `audit-admin`. A valid policy must always contain an
active, non-emergency account for each of those three roles. Consequently, the
role that changes security policy cannot erase or approve the independent audit
trail. TrustDB exposes no audit-history deletion operation.

## Bootstrap

Supply three different passwords through environment variables or owner-only
files. Passwords never need to appear in process arguments.

Linux/macOS:

```bash
export TRUSTDB_ADMIN_BOOTSTRAP_SYSTEM_PASSWORD='replace-with-system-password'
export TRUSTDB_ADMIN_BOOTSTRAP_SECURITY_PASSWORD='replace-with-security-password'
export TRUSTDB_ADMIN_BOOTSTRAP_AUDIT_PASSWORD='replace-with-audit-password'

trustdb --config /etc/trustdb/production.yaml admin policy bootstrap \
  --out /etc/trustdb/admin-policy.json
```

PowerShell:

```powershell
$env:TRUSTDB_ADMIN_BOOTSTRAP_SYSTEM_PASSWORD = 'replace-with-system-password'
$env:TRUSTDB_ADMIN_BOOTSTRAP_SECURITY_PASSWORD = 'replace-with-security-password'
$env:TRUSTDB_ADMIN_BOOTSTRAP_AUDIT_PASSWORD = 'replace-with-audit-password'

.\trustdb.exe --config C:\TrustDB\production.yaml admin policy bootstrap `
  --out C:\TrustDB\admin-policy.json
```

Prefer the corresponding `*_PASSWORD_FILE` variables in production. Move the
three credentials into separate custody after bootstrap. The command refuses to
replace an existing policy and requires version 1. Its structured output and
log record the operating-system identity that performed the bootstrap.

Validate and inspect without exposing bcrypt verifiers:

```bash
export TRUSTDB_ADMIN_ACTOR=security-admin
export TRUSTDB_ADMIN_PASSWORD="$TRUSTDB_ADMIN_BOOTSTRAP_SECURITY_PASSWORD"
trustdb admin policy validate --file /etc/trustdb/admin-policy.json
trustdb admin policy inspect --file /etc/trustdb/admin-policy.json
```

## Configuration

```yaml
admin:
  enabled: true
  base_path: "/admin"
  policy_path: "/etc/trustdb/admin-policy.json"
  session_secret: "replace-with-at-least-32-random-bytes"
  web_dir: "/opt/trustdb/admin"
  cookie_secure: true
  session_ttl: "8h"
  login_max_failures: 5
  login_lockout: "15m"
  cli_enforce: true
  oidc_gateway_spki_sha256: []
```

- `enabled` controls only the Admin Web mount.
- `cli_enforce` independently protects annotated privileged commands. The
  production template enables it, so missing, unsafe, or invalid policy data
  fails closed.
- The generic Admin Web YAML endpoint cannot change any `admin` field. Change
  this bootstrap boundary through a reviewed deployment configuration.
- `session_secret` signs session v2 tokens. Tokens bind the account ID, roles,
  session epoch, policy version, and policy digest. Any policy revision or role
  change invalidates all existing sessions.
- Cookies are HttpOnly and SameSite=Strict. Set `cookie_secure=true` behind
  HTTPS.

## Admin Web authorization

The Admin Web enforces permissions per endpoint, not merely at login:

- metrics, effective configuration, overlays, and read-only proxy:
  `system.read`;
- YAML configuration write: `system.configure`;
- policy read: `security.policy.read`;
- policy update: `security.policy.write`.

The UI receives the current principal, role set, and permission set. It disables
configuration writes for read-only roles, while the server remains the final
authorization boundary.

The current public gRPC service contains submission, evidence, and health
methods only; it exposes no administrative mutation API. Any future
administrative gRPC method must use these same permission constants and an
actor-propagating interceptor before it can be registered.

Local-password login supports an MFA verification interface. Accounts marked
`mfa_required` fail closed unless a verifier succeeds. The standard binary can
accept OIDC identity headers only from an mTLS gateway whose certificate SPKI
is listed in `oidc_gateway_spki_sha256`; the gateway must validate JWT signature,
issuer, audience, expiry, nonce, and MFA before setting the fixed TrustDB
headers. Unpinned clients and raw issuer/subject headers are rejected. Direct
mTLS accounts bind the SHA-256 digest of their certificate SPKI to the policy.

## CLI authorization

When `admin.cli_enforce=true`, use an actor plus a password environment variable
or owner-controlled file:

Linux/macOS:

```bash
export TRUSTDB_ADMIN_ACTOR=backup-operator
export TRUSTDB_ADMIN_PASSWORD_FILE=/run/secrets/trustdb-backup-operator
trustdb --config /etc/trustdb/production.yaml backup create ...
```

PowerShell:

```powershell
$env:TRUSTDB_ADMIN_ACTOR = 'backup-operator'
$env:TRUSTDB_ADMIN_PASSWORD_FILE = 'C:\TrustDB\secrets\backup-operator.txt'
.\trustdb.exe --config C:\TrustDB\production.yaml backup create ...
```

Use exactly one of `TRUSTDB_ADMIN_PASSWORD` and
`TRUSTDB_ADMIN_PASSWORD_FILE`. Authorization is applied centrally before the
command runs, and the structured log records actor, permission, command, and
emergency status. MFA-required accounts cannot use the built-in local-password
CLI hook; integrate those workflows through an authenticated administrative
service.

Protected command families include service lifecycle, configuration, key
lifecycle, backup/restore, WAL repair/dump, metastore migration, anchor
maintenance, Global Log compaction, and FISCO BCOS TrustConfig mutation.

The same authorization boundary protects the online client-key lifecycle API.
See [Online client-key lifecycle](../integrations/ONLINE_KEY_LIFECYCLE.md) for
the request contract and deployment constraints.

## Online policy change

1. Authenticate as a `security-admin`.
2. GET `/admin/api/security/policy`; retain the `ETag` digest.
3. Increment `version` by exactly one and keep accounts sorted by `id`, with
   roles and identity bindings sorted and unique.
4. PUT the complete JSON document with `If-Match: "<digest>"`.

The online writer cannot modify its own account, any system/audit administrator
custody, or any emergency account. It may add and manage separated operator and
support identities. This prevents a security-policy writer from silently
seizing system or audit authority. Use another security administrator for the
writer's own account and the explicit offline recovery ceremony for
system/audit or emergency custody changes.

On success, the previous canonical policy is saved as:

```text
<policy_path>.history/v00000000000000000001-<sha256>.json
```

The current file is installed atomically with owner-only permissions. A stale
digest returns a conflict instead of overwriting concurrent work.

## Emergency access and offline recovery

An emergency account must have only `emergency-admin`, `emergency=true`, and
UTC `not_before`/`not_after` timestamps spanning no more than 24 hours. Every
emergency Web session or direct mTLS/OIDC request requires a 12–512 character
reason. CLI use additionally requires `TRUSTDB_ADMIN_EMERGENCY_REASON`.

Create or rotate emergency bindings only through offline recovery:

```bash
export TRUSTDB_ADMIN_EMERGENCY_REASON='approved incident INC-2026-0042 recovery'
trustdb admin policy recover \
  --file /etc/trustdb/admin-policy.json \
  --replacement /secure/reviewed-policy-vNEXT.json \
  --expect-current-digest <current-digest> \
  --offline-recovery
```

PowerShell:

```powershell
$env:TRUSTDB_ADMIN_EMERGENCY_REASON = 'approved incident INC-2026-0042 recovery'
.\trustdb.exe admin policy recover `
  --file C:\TrustDB\admin-policy.json `
  --replacement C:\TrustDB\reviewed-policy-vNEXT.json `
  --expect-current-digest <current-digest> `
  --offline-recovery
```

The replacement must be a valid next version and preserves immutable history.
Run this from a controlled console with the service stopped, require two-person
review, and retain the command output and policy files with the incident record.
The command records the operating-system actor and the mandatory recovery reason.

## Lockout and recovery runbook

- Failed local logins are bounded in memory and lock the normalized username
  after `login_max_failures`. A successful login clears the counter.
- At lockout expiry, a correct login succeeds without deleting server state.
- Disabling an account, changing roles, incrementing `session_epoch`, or
  installing any policy revision invalidates old sessions.
- If all online administrators are inaccessible, stop the Admin Web, verify the
  current digest offline, install a reviewed next policy with `policy recover`,
  restart, and verify that the old session no longer works.
- Never edit the current file in place, delete `.history`, lower the version, or
  copy an evidence-signing key into the administrative policy.

## Acceptance checks

Before production use, test all of the following with distinct people or test
identities: horizontal denial between tenants/accounts, vertical denial between
roles, session expiry, role-change invalidation, lockout and expiry, mTLS SPKI
matching, OIDC/MFA hook failure, stale `If-Match`, self-modification denial,
emergency reason and expiry, offline recovery, and immutable history retention.
