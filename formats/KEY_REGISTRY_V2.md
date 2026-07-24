# TrustDB Key Registry V2

Status: implemented

Schema: `trustdb.key-registry.v2`

Event schema: `trustdb.key-event.v2`

## Purpose

Key Registry V2 is the append-only, suite-bound lifecycle record for TrustDB client signing identities. It preserves the complete canonical key descriptor needed for historical verification and provider inventory while keeping private key material outside the registry.

## File layout

All integers in framing are unsigned big-endian.

```text
"TDBKEYR2\n"
manifest_frame
event_frame[0]
event_frame[1]
...
```

Every frame is:

```text
uint32 payload_length
byte[payload_length] canonical_cbor_payload
uint32 crc32c_castagnoli(payload)
```

`payload_length` must be between 1 byte and 4 MiB. CBOR uses RFC 8949 Core Deterministic Encoding, forbids tags, indefinite lengths, duplicate keys, unknown fields, NaN, infinity, trailing data, and non-canonical re-encoding.

CRC32C detects torn writes and accidental corruption. It is not an authenticity mechanism.

## Manifest

The first frame is exactly one manifest:

| Field | Rule |
| --- | --- |
| `schema_version` | exactly `trustdb.key-registry.v2` |
| `format_version` | exactly `2` |
| `crypto_suite` | known `INTL_V1` or `CN_SM_V1` |
| `registry_key_id` | non-empty and exact |
| `registry_algorithm` | suite signature algorithm |
| `registry_public_encoding` | suite public-key encoding |
| `registry_public_key` | canonical public-key bytes |

The manifest fixes one suite and one registry signer for the entire file. An existing registry must be opened with a verifier-local trusted public descriptor whose suite, KeyID, algorithm, encoding, and bytes exactly match the manifest. The embedded public key is never accepted as a self-authorizing trust root.

## Events

Every event contains:

- `schema_version = trustdb.key-event.v2`;
- `crypto_suite` equal to the manifest suite;
- contiguous `sequence` starting at 1;
- `prev_event_hash` equal to the preceding event hash, empty only for sequence 1;
- one lifecycle payload;
- `registry_signature` over the canonical unsigned event;
- `event_hash` over the canonical signed event with `event_hash` omitted.

The signature input is selected by the suite's `key_event` purpose and domain framing. The event hash uses the suite's `KeyEventHash` and `KeyEventHash` domain. Consequently `INTL_V1` uses Ed25519/SHA-256 and `CN_SM_V1` uses SM2-SM3/SM3 without algorithm inference from byte length.

### `KEY_REGISTERED`

Requires `tenant_id`, `client_id`, `key_id`, `key_descriptor`, `valid_from_unix_nano`, and optional `valid_until_unix_nano`. The descriptor is the complete canonical `trustdb.key-descriptor.v1` object and must match the manifest suite and event KeyID.

An exact retry is idempotent. Reusing the same identity with different suite, algorithm, public material, provider reference, certificate chain, or validity is rejected.

### `KEY_ROTATED`

Requires a new `key_id`, `previous_key_id`, replacement `key_descriptor`, and `rotated_at_unix_nano == valid_from_unix_nano`. One durable event retires the previous key and activates the replacement at the same instant. Historical lookups before that instant continue to resolve the old key.

### `KEY_REVOKED`

Requires `revoked_at_unix_nano`. The key remains valid for lookups before that instant and is rejected at or after it.

### `KEY_COMPROMISED`

Requires `compromised_at_unix_nano`. Compromise takes precedence over revoked status when both are effective, preserving incident semantics for auditors.

## Certificates and providers

Registration and rotation preserve the complete descriptor, including:

- public key encoding and bytes;
- fixed SM2 user ID;
- leaf-first DER certificate chain;
- software, PKCS#11, SDF, or remote provider reference.

If a certificate chain exists, registry validity must remain within the leaf certificate interval. An omitted validity end is set to leaf `NotAfter`. Certificate roots embedded in descriptors are evidence material, not verifier trust roots.

The registry never contains software private material, PIN values, provider credentials, or exported HSM/SDF/KMS private keys.

## Durability and recovery

Writers validate a transition, sign it, verify the provider-produced signature against the manifest key, hash it, append one frame, and `fsync` before updating memory.

A final incomplete frame is an uncommitted torn append. Read-only opens ignore it; writable opens truncate it to the last complete frame before accepting another event. A complete frame with invalid CRC, CBOR, signature, hash, sequence, suite, or lifecycle transition fails closed and is never skipped or repaired.

Initial manifest publication is atomic and no-replace. Concurrent initializers may only converge on the same manifest; a competing signer cannot overwrite the winning trust boundary.

## Compatibility

V2 is a destructive cutover. Implementations do not read, migrate, guess, or fall back to the previous per-event V1 file. A missing magic value, wrong manifest schema, future event schema, or unknown field fails explicitly.

Changing the manifest, framing, event fields, or lifecycle meaning requires a new registry/event version. Historical registry files remain independently verifiable with their original trusted public descriptor.
