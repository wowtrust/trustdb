# SDF signing provider

TrustDB can keep SM2 signing keys and SM4 KEKs inside a deployment-selected
Chinese commercial-cryptography device. The optional
`trustdb-signer-sdf` process is the production isolation boundary:

```text
TrustDB core
  -> authenticated signer-plugin v1 over loopback gRPC
    -> trustdb-signer-sdf
      -> TrustDB SDF adapter ABI v1
        -> deployment-owned vendor shim and SDF SDK
          -> cryptographic device and non-exportable keys
```

TrustDB core never includes a vendor header, links a proprietary library,
receives an SM2 private key or plaintext SM4 key, or falls back to a software
key. The sidecar loads one deployment-supplied adapter shared library at
runtime. The adapter translates the stable TrustDB ABI to the exact structures,
symbols, algorithm identifiers, authentication extensions, and status codes of
the selected device SDK.

This boundary follows the application-interface model in
[GM/T 0018-2023](https://std.samr.gov.cn/hb/search/stdHBDetailed?id=1BF26B7A9FFDFD76E06397BE0A0A81D8),
which replaced GM/T 0018-2012, and is designed for qualification using the
controls represented by
[GM/T 0102-2020](https://www.oscca.gov.cn/sca/xwdt/2020-12/30/content_1060794.shtml).
Implementing these interfaces is not a product certification, a conformity
test result, or approval for a particular deployment. The exact device,
firmware, SDK, adapter, operating system, architecture, and configuration must
pass the gated qualification procedure below.

## Build and packaging

The native loader requires CGO and the explicit `sdf` build tag:

```bash
CGO_ENABLED=1 go build -trimpath -tags=sdf \
  -o trustdb-signer-sdf ./cmd/trustdb-signer-sdf
```

Normal TrustDB builds do not include the native loader. A build without the tag
produces a diagnostic sidecar stub and keeps all SDF/vendor native dependencies
out of the server. Linux release packaging includes the native SDF sidecar.

The SDF Provider workflow continuously tests:

- Linux amd64 and arm64 native loading against the repository fake adapter;
- macOS amd64 and arm64 portable and native contracts;
- Windows amd64 and arm64 portable contracts and diagnostic stubs;
- race behavior on Linux amd64; and
- the Linux release-package contents.

The Windows credential-file implementation currently fails closed because an
owner-only DACL policy is not continuously runtime-qualified. Windows therefore
receives the portable contract and diagnostic stub, not a production native
sidecar. A real Windows or macOS deployment additionally requires a vendor SDK,
shared library, CGO toolchain, and device driver supported by that vendor.

## Build a vendor adapter

Implement and export the function table in
[`sdk/sdfadapter/trustdb_sdf_adapter_v1.h`](../../sdk/sdfadapter/trustdb_sdf_adapter_v1.h).
The sidecar loads only `trustdb_sdf_adapter_get_api_v1`; it checks the ABI
version, structure size, every required function pointer, normalized
capabilities, and stable device identity before accepting work.

The deployment-owned shim normally maps the following SDF operation families:

| TrustDB ABI operation | Common SDF operation family |
| --- | --- |
| device/session lifecycle and identity | `SDF_OpenDevice`, `SDF_OpenSession`, `SDF_GetDeviceInfo`, close operations |
| canonical SM2 public key | `SDF_ExportSignPublicKey_ECC` |
| indexed internal SM2 signing | device authentication, `SDF_GetPrivateKeyAccessRight`, `SDF_InternalSign_ECC` |
| random bytes | `SDF_GenerateRandom` |
| generate/import SM4 key under KEK | `SDF_GenerateKeyWithKEK`, `SDF_ImportKeyWithKEK` |
| SM4-CBC and MAC through an opaque handle | `SDF_Encrypt`, `SDF_Decrypt`, `SDF_CalculateMAC` |
| session-key disposal | `SDF_DestroyKey` |

Those names describe common operation families, not an assumed binary ABI.
The shim owns every vendor-specific structure layout, symbol name, algorithm
identifier, padding rule, credential ceremony, library initialization rule,
timeout, and error mapping. It must return only the fixed TrustDB status set;
raw vendor status values and strings must not cross the ABI or appear in logs.

The adapter configuration is a bounded byte buffer supplied to `open_device`.
The sidecar clears its copy immediately after that call. If the shim needs any
configuration later, it must make and protect its own copy and clear it during
close. Configuration, credentials, messages, digests, IVs, and output buffers
are borrowed only for the duration of one call.

## Exact SM2 signing semantics

The `CN_SM_V1` signature profile is deliberately split at one unambiguous
boundary:

1. the sidecar retrieves the exact canonical 65-byte uncompressed SM2 public
   key for the descriptor's non-zero internal key index;
2. it calculates SM2 `ZA` using the immutable user ID
   `1234567812345678`, then calculates `SM3(ZA || message)`;
3. it passes that exact 32-byte digest to `sm2_sign_digest`;
4. the adapter performs the SM2 private operation and returns exactly
   64 bytes `r || s`, each integer fixed to 32 bytes;
5. the sidecar rejects invalid ranges, encodes canonical ASN.1 DER, and verifies
   the result locally against the pinned public key and original message; and
6. TrustDB core performs the signer-plugin binding and local signature
   verification again before evidence is accepted.

The adapter must not calculate `ZA`, hash the digest again, select another user
ID, add domain framing, or return DER. A module that exposes only a complete
message-signing operation requires a vendor shim able to satisfy this exact
digest contract; otherwise it is unsupported and must fail closed.

## Sidecar configuration

The sidecar has no command-line configuration. Every variable must be listed
explicitly in `crypto.signer_plugins.sdf.inherit_env`, because the signer
supervisor removes the ambient environment:

```yaml
crypto:
  signer_plugins:
    sdf:
      command: "/usr/local/libexec/trustdb-signer-sdf"
      args: []
      inherit_env:
        - "TRUSTDB_SDF_ADAPTER"
        - "TRUSTDB_SDF_ADAPTER_CONFIG_FILE"
        - "TRUSTDB_SDF_DEVICE_REF"
        - "TRUSTDB_SDF_CREDENTIAL_REF"
        - "TRUSTDB_SDF_CREDENTIAL_FILE"
        - "TRUSTDB_SDF_CAPABILITIES"
        - "TRUSTDB_SDF_KEK_ID"
        - "TRUSTDB_SDF_KEK_INDEX"
        - "TRUSTDB_SDF_PLUGIN_ID"
        - "TRUSTDB_SDF_MAX_CONCURRENCY"
      start_timeout: "10s"
      rpc_timeout: "30s"
      max_concurrency: 16
```

| Variable | Meaning |
| --- | --- |
| `TRUSTDB_SDF_ADAPTER` | Required clean absolute path to the deployment-built adapter shared library. |
| `TRUSTDB_SDF_ADAPTER_CONFIG_FILE` | Required owner-only regular file, at most 64 KiB, containing opaque adapter configuration. |
| `TRUSTDB_SDF_DEVICE_REF` | Required stable device selector. It must equal the adapter's returned device ID. |
| `TRUSTDB_SDF_CREDENTIAL_REF` | Required stable, non-secret name used to bind configuration and descriptors. |
| `TRUSTDB_SDF_CREDENTIAL_FILE` | Required owner-only regular file, at most 4 KiB, containing the device credential. |
| `TRUSTDB_SDF_CAPABILITIES` | Optional comma-separated `sign`, `random`, and `sm4-kek`; default `sign`. |
| `TRUSTDB_SDF_KEK_ID` | Required stable non-secret KEK identity when `sm4-kek` is enabled. |
| `TRUSTDB_SDF_KEK_INDEX` | Required non-zero decimal internal KEK index when `sm4-kek` is enabled. |
| `TRUSTDB_SDF_PLUGIN_ID` | Optional stable process identity; default `trustdb.sdf.v1`. |
| `TRUSTDB_SDF_MAX_CONCURRENCY` | Device-side concurrency limit, 1–1024; default 16. |

`sign` is always required. `random` and `sm4-kek` are explicit all-or-nothing
capability gates: requesting one requires the adapter/device to advertise the
complete corresponding ABI surface. Unknown, duplicate, missing, or partially
implemented capabilities stop startup.

The config and credential files must be regular, not symlinks, and must deny
group and other permissions on Unix. Credentials are read immediately before
the native call, passed through mutable buffers, and cleared afterward. Runtime
and C libraries may still create short-lived copies, so protect the file,
sidecar account, process inspection, crash dumps, and host. There is no inline
credential environment variable, YAML value, or command argument.

Do not log adapter/config/credential paths, device references, credential
references, key or KEK indexes, opaque handles, configuration contents,
credentials, messages, or native errors.

## Descriptor, identity, and rotation

An SDF signer descriptor contains:

```text
sdf.device_ref       stable device selector
sdf.key_index        non-zero internal signing-key index
sdf.credential_ref   stable credential identity
```

The descriptor also pins the suite, algorithm, key ID, SM2 user ID, canonical
public key, and optional certificate chain. Private key material is never
stored in the descriptor, TrustDB configuration, evidence, API responses, or
logical backups.

At startup the adapter returns `adapter_id`, `adapter_version`, `device_id`,
`serial`, and `firmware`. These values remain pinned for the sidecar lifetime.
Every new session repeats identity checks, and each key index's first accepted
public key is pinned. Device replacement or public-key drift fails closed.

Rotate by provisioning another internal key, publishing a new canonical
descriptor and Registry V2 event, changing the intended role, and restarting
the signer resolver. Do not reuse an index or descriptor for a different key.
Historical evidence continues to verify with its historical public descriptor.

## Provider recovery artifact

[`trustdb.sdf-recovery-bundle.v1`](../../formats/SDF_RECOVERY_BUNDLE_V1.md) is
the bounded, deterministic provider recovery artifact owned by this
integration. It contains:

- the exact stable device identity;
- 1–128 complete canonical SDF signer descriptors, including each public key
  and `{device_ref, key_index, credential_ref}` provider binding; and
- 0–1024 optional canonical wrapped-SM4 envelopes.

Export first reads every indexed public key from the live device and compares
it to the descriptor. Restore strictly rejects duplicate/unknown fields, tags,
indefinite values, trailing bytes, non-canonical CBOR, oversized bytes or
declared collection counts, duplicate KeyIDs/handles, and an unsupported
schema. It then rebinds the complete device identity, credential identity,
every live public key, and every configured KEK. All public-key pins are
published to the process cache atomically only after every descriptor and
wrapped key passes, so a late conflict cannot leave a partially restored
inventory.

The artifact contains no credential value, adapter configuration/path, private
key, plaintext SM4 key, or same-session native handle. Its unkeyed SM3 checksum
detects accidental corruption but cannot authenticate an attacker who can
rewrite the artifact and recompute the checksum.

The current `.tdbackup v5` is an authenticated, SM4-encrypted logical format.
It can preserve the V2 key registry's public descriptors and signed lifecycle
audit log, but it does **not** contain this SDF provider recovery artifact,
credentials, or device key material. Operators must not claim that a logical
archive alone recovers an SDF deployment; retain and restore the recovery
bundle through the independent provider ceremony.

### SM4 KEK boundary

When `sm4-kek` is enabled, the adapter may generate a 128-bit SM4 session key
under the configured internal KEK or import its wrapped representation. The
plaintext key never crosses the adapter ABI. Encryption, decryption, and MAC
use an opaque same-session handle, and close destroys that handle.

`trustdb.sdf-wrapped-sm4-key.v1` is a canonical CBOR envelope containing the
fixed `CN_SM_V1` suite and algorithm, complete device identity, stable KEK
identity/index, bounded wrapped bytes, and an SM3 checksum. It can be persisted
and imported after reopening the adapter only if every device and KEK binding
still matches.

The envelope's SM3 checksum also detects accidental corruption only; it is
deliberately unkeyed and does not authenticate attacker-controlled bytes. The
device's KEK wrapping provides the key-custody boundary. If the selected
vendor's wrapping format is not authenticated, deployment storage and backup
v5 must add a separate AEAD/MAC.

## Failure, timeout, and shutdown behavior

- Busy and unavailable conditions are retryable for a later host operation.
- A failed or timed-out `Sign` is never replayed automatically because the
  device may already have produced a randomized signature.
- Invalid requests, bad credentials, permission denial, unsupported
  capabilities, missing keys, identity drift, and public-key drift fail closed.
- No error path selects software, another device, another key, another
  algorithm, or a weaker capability set.
- RPC and supervisor waits are bounded. SM4 session cleanup returns to its
  caller after a two-second default even if a native call remains blocked.
- The supervisor interrupts the sidecar where supported, then force-terminates
  it on timeout; Windows takes the force-termination path.

A Go context cannot preempt a blocked vendor C function. The vendor shim and
device SDK therefore must enforce bounded native-call behavior, tolerate
abrupt process loss, clean orphaned sessions according to the device's own
rules, and document reconciliation after ambiguous failures.

## Automated and real-device qualification

The ordinary `SDF Provider` workflow uses a fake shared adapter to exercise
ABI loading, exact digest/signature semantics, capability negotiation,
identity drift, corrupt outputs, ambiguous failures, bounded shutdown, wrapped
SM4 restart, concurrency, race behavior, and cross-platform build paths. It
does not qualify a commercial product.

Real hardware is intentionally tested only by the manually dispatched
`SDF Vendor Qualification` workflow:

1. attach a change-controlled Linux x64 runner with labels
   `self-hosted`, `linux`, `x64`, and `sdf-vendor`;
2. place the vendor SDK, device driver, adapter library, owner-only adapter
   config, and owner-only credential file on that runner;
3. protect the GitHub environment `sdf-vendor-qualification` with required
   approvers and a deployment branch rule that permits only `main`; the job
   also checks `github.ref == refs/heads/main` so hardware credentials never
   execute code from a pull request, tag, or arbitrary branch;
4. configure environment variables `SDF_ADAPTER_PATH`,
   `SDF_ADAPTER_CONFIG_FILE`, `SDF_DEVICE_REF`, `SDF_CREDENTIAL_REF`,
   `SDF_CREDENTIAL_FILE`, `SDF_CAPABILITIES`, `SDF_KEK_ID`,
   `SDF_KEK_INDEX`, `SDF_MAX_CONCURRENCY`, `SDF_SIGNING_KEY_INDEX`, and
   the independently verified 65-byte `SDF_SIGNING_PUBLIC_KEY_HEX`;
5. dispatch the workflow with a change-record `qualification_id` and
   non-secret `vendor_profile`; each must be a 1–128 byte single-line
   identifier containing only ASCII letters, digits, dot, underscore, or
   hyphen; and
6. retain the JSON test stream, qualification metadata, reviewed adapter
   source/binary checksum, device certificate, key ceremony, and approvals.

The test confirms the exact public key, direct native health/signing, complete
provider-recovery export/restore across a fresh backend, the full supervised
signer-plugin path, local verification of 16 concurrent signatures, and—when
enabled—random generation plus wrapped-SM4 recovery. Before upload, the
workflow verifies byte-for-byte that neither the credential-file content nor
adapter-config-file content occurs in the JSON test stream. The artifacts
contain only that sanitized Go test stream and the bounded non-secret
qualification identifiers, commit, and run ID. No vendor is considered
qualified merely because its library loads.

Before production acceptance also record and test:

- exact module and adapter checksums, SDK/driver versions, firmware, OS, CPU
  architecture, device identity fields, and algorithm identifiers;
- public-key encoding, SM2 user-ID behavior, and negative double-hash behavior;
- wrong/expired/locked credentials and least-privilege device roles;
- device removal, restart, session exhaustion, native timeouts, and abrupt
  sidecar termination;
- concurrency at the configured cap and device audit-event correlation;
- key rotation without index reuse or public-key drift;
- KEK backup, restore, rotation, and destruction ceremonies when `sm4-kek` is
  enabled; and
- independent conformity/certification evidence required by the deployment's
  actual legal and assessment scope.

Offline proof verification never starts this sidecar, opens the adapter,
contacts the device, or trusts a device-supplied key. It uses the evidence
bytes and verifier-local trust roots only.
