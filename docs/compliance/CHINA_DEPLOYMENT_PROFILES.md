# China production, offline, and assessment deployment profiles

TrustDB ships three fail-closed deployment profiles in addition to the flexible
development, benchmark, and single-node baseline profiles:

| Profile | Template | Intended boundary |
| --- | --- | --- |
| `china_production` | `configs/china-production.yaml` | Online production using `CN_SM_V1`, non-exportable keys, mTLS or a validated TLCP gateway, explicit egress, immutable audit, and Guomi FISCO BCOS anchoring. |
| `offline_isolated` | `configs/offline-isolated.yaml` | Internet-independent operation with no TrustDB outbound connection and L4 evidence available locally. |
| `assessment` | `configs/assessment.yaml` | The China production controls plus signed evidence for any narrow, approved, temporary exception used during assessment. |

Selecting one of these profiles changes runtime behavior. It is not a label:
TrustDB validates the merged YAML, then validates the loaded key descriptors and
the canonical FISCO BCOS TrustConfig before it opens the WAL, proofstore, or
listener.

## Enforced startup sequence

The strict startup gate checks:

1. the HTTP/gRPC boundary is mTLS with client-CA pins, or loopback plaintext
   behind a validated TLCP gateway profile and active identity manifest;
2. security audit is enabled, required, uses synchronized trusted-time input,
   and has opened its signed append-only writer;
3. server and audit signing descriptors use `CN_SM_V1` and do not select the
   built-in `software` provider;
4. the backup KEK provider is not `passphrase-dev-v1`;
5. China production and assessment use the `fisco-bcos` sink;
6. the FISCO BCOS TrustConfig uses `crypto_mode=guomi`, a non-software account
   provider, local CA hashes, and pinned peer-certificate hashes;
7. every NATS, TiKV, FISCO BCOS, remote signer, and remote BCOS account-signer
   endpoint exactly matches `deployment_policy.allowed_endpoints`;
8. every hostname used by an allowed endpoint also appears in
   `deployment_policy.dns_allowlist`;
9. built-in telemetry and update-check policy remain disabled.

An invalid boundary stops startup before serving traffic. TrustDB never
silently changes the suite, replaces an external key with a software key, uses
the public OTS pool, or accepts an unknown endpoint.

## Exact egress declarations

Allowlist entries are canonical `scheme://host:port` origins. Credentials,
paths, queries, wildcards, implicit ports, and suffix matching are rejected.
If a remote signer descriptor uses an HTTPS API path, TrustDB matches its
normalized HTTPS origin (default port 443) to this list; the path does not
broaden the network destination.

```yaml
deployment_policy:
  egress_mode: "allowlist"
  allowed_endpoints:
    - "gm-tls://10.0.0.20:20200"
    - "gm-tls://10.0.0.21:20200"
    - "https://kms.security.example.cn:443"
  dns_allowlist:
    - "kms.security.example.cn"
  telemetry_enabled: false
  update_checks_enabled: false
  exceptions: []
```

The allowlist is an application startup gate, not a replacement for host and
network controls. Apply the same destination set in the host firewall,
Kubernetes NetworkPolicy or CNI policy, security group, DNS policy, and egress
gateway. Alert when those controls differ from the reviewed YAML.

For TiKV, declare PD addresses with the synthetic `tikv://` scheme:

```yaml
deployment_policy:
  allowed_endpoints:
    - "tikv://10.0.1.10:2379"
    - "tikv://10.0.1.11:2379"
```

NATS must use `tls://`, enable certificate verification, and specify a CA file.
Plain `nats://` is rejected by strict profiles.
Guomi FISCO BCOS TrustConfig endpoints use `gm-tls://`; `tls://` belongs to the
standard BCOS mode and therefore fails the China profile's mode binding.

## Offline and isolated operation

`offline_isolated` requires `egress_mode: deny_all`, disables NATS, and permits
only `off`, `file`, or `noop` anchor sinks. It still requires `CN_SM_V1`,
non-software server/audit keys, mTLS or the validated TLCP boundary, immutable
audit, trusted time, and a non-development backup KEK.

This profile means the running TrustDB process does not open an outbound
connection. Before entering the isolated environment, mirror and verify:

- TrustDB binaries or container images, checksums, signatures, SBOM, and
  provenance;
- operating-system packages and container base images;
- Go modules and build toolchains when builds occur inside the boundary;
- SDF/PKCS#11 adapters, vendor libraries, firmware, licenses, and recovery
  packages;
- CA chains, CRLs, key descriptors, registry, trusted-time feed, and operator
  runbooks.

L4 evidence and `.sproof v2` offline verification continue without an anchor
network. `off`, `file`, and `noop` do not supply an independent external time
source and must not be described as equivalent to a FISCO BCOS L5 result.

## Time-bounded exceptions

Do not edit the profile to make a failing control disappear. An assessment
exception must identify one supported control, a reason, named approver,
change/security ticket, and RFC 3339 expiry no more than 30 days away:

```yaml
deployment_policy:
  exceptions:
    - id: "CAB-2026-0042"
      control: "server_key_custody"
      reason: "Temporary assessment HSM fixture; no production data"
      approved_by: "security-owner@example.cn"
      ticket: "SEC-42"
      expires_at: "2026-08-09T00:00:00Z"
```

Supported controls are `server_crypto_suite`, `audit_crypto_suite`,
`bcos_crypto_mode`, `server_key_custody`, `audit_key_custody`,
`bcos_key_custody`, `server_transport_pins`, `bcos_transport_pins`, `egress`,
`anchor`, and `backup_key`. This separation prevents one approval from
disabling adjacent checks. Missing, duplicate, unknown, expired, or over-30-day
exceptions fail startup. TrustDB writes every accepted exception to the signed
security audit as `deployment.policy.exception` before opening a listener. If
the audit writer is unavailable, the exception cannot be used.

An exception narrows a technical gate; it does not create a compliance
conclusion. Remove it before expiry, retest the strict profile, and retain the
approval, audit event, remediation, and negative-test result.

The generic Admin Web configuration endpoint cannot modify `run_profile` or
`deployment_policy` (just as it cannot modify `admin` or `audit`). Apply a
reviewed file change through the deployment/change-control path and restart;
this prevents an ordinary system-configuration session from disabling the
strict profile or self-approving an exception.

## Deployment procedure

1. Copy the closest template and replace every example address, pin, path,
   descriptor, key ID, and TrustConfig.
2. Generate or import `CN_SM_V1` public descriptors. Provision server, audit,
   backup, and BCOS account keys in SDF, PKCS#11, HSM/KMS, or an approved remote
   provider.
3. Build the canonical FISCO BCOS TrustConfig with Guomi mode, multiple
   endpoints/read quorum, local CA hashes, peer pins, validators, contract
   binding, and trusted checkpoint.
4. Make `allowed_endpoints` exactly match all enabled providers and services;
   list every DNS hostname explicitly.
5. Validate the merged configuration and inspect its redacted output:

   ```bash
   trustdb --config /etc/trustdb/trustdb.yaml config validate
   trustdb --config /etc/trustdb/trustdb.yaml config show
   trustdb --config /etc/trustdb/trustdb.yaml doctor
   ```

6. Start in an isolated staging boundary. A policy failure must terminate the
   process without a listening socket.
7. Submit a canary, reach the intended L4/L5 level, export `.sproof v2`, and
   verify it on a disconnected verifier with independently supplied trust
   roots.
8. Export and verify the security-audit chain and checkpoint. Confirm any
   exception event matches its approval.
9. Complete backup/restore into a fresh namespace before admitting production
   traffic.

## Deliberate failure tests

Before approval, prove startup fails after independently changing each of:

- server or audit descriptor from `CN_SM_V1` to `INTL_V1`;
- server, audit, or BCOS account provider to `software`;
- mTLS client-CA pins or BCOS peer pins to empty;
- one endpoint to an unlisted IP, hostname, port, or scheme;
- one hostname without the DNS allowlist entry;
- FISCO BCOS mode from `guomi` to `standard`;
- backup provider to `passphrase-dev-v1`;
- exception expiry to the current/past time;
- offline profile by enabling NATS, TiKV, FISCO BCOS, OTS, or a remote signer.

Retain the command, sanitized configuration digest, expected error, timestamp,
reviewer, and release identifier as assessment evidence.
