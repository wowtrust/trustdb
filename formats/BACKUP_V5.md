# TrustDB Logical Backup V5

Status: available for `INTL_V1` and `CN_SM_V1` proofstore-v5 namespaces.

## Security boundary

`.tdbackup v5` is an encrypted logical proofstore archive. It preserves
portable evidence and resumable anchor state, but never carries private keys,
KEKs, passphrases, provider credentials, HSM/SDF state, or verifier trust
roots. A restore still requires independently controlled configuration,
signer/provider recovery material, certificates, BCOS TrustConfig, object
storage, WAL, and broker recovery where applicable.

V5 is a breaking format. Readers reject v4, plain tar, format guessing,
migration, and fallback.

## Outer envelope

The file begins with:

```text
magic                 "TRUSTDB-TDBACKUP-V5\x00"
header_length         uint32 big endian, 1..65536
header                RFC 8949 deterministic CBOR EnvelopeHeader
encrypted_frames      zero or more data frames plus one final frame
```

The header binds the exact archive schema, BackupID, creation time,
compression, crypto suite, proofstore format generation, source NodeID, LogID,
NamespaceID, content algorithm, frame size, nonce prefix, KEK provider, KEK
key reference, and opaque wrapped DEK. Unknown/duplicate CBOR fields, tags,
indefinite values, non-canonical encodings, unknown suites, and unsupported
algorithms fail closed.

The content algorithm is `SM4-GCM-FRAMED-V1`. Each archive gets a fresh random
128-bit DEK and 64-bit nonce prefix. The KEK provider wraps the DEK while
authenticating every immutable header field. The archive never requires the
core to export a KEK; an HSM or KMS adapter may keep that key opaque.

## Frames

Each frame is:

```text
ordinal               uint32 big endian, starts at zero and is contiguous
plaintext_length      uint32 big endian
flags                 uint8; bit 0 is FINAL, all other bits are zero
ciphertext             plaintext_length bytes
tag                    16 bytes
```

The 96-bit nonce is `nonce_prefix || ordinal`. AAD is the domain
`trustdb.backup-frame.v1`, SM3(header bytes), and the exact frame header.
Frame plaintext is limited to 64 KiB..16 MiB; writers default to 1 MiB.

Writers emit all data frames with flags zero, then an authenticated FINAL
frame with zero plaintext. Readers require exact ordinal order, authenticate
every frame, require the final frame, and reject any bytes after it. This makes
reordering, substitution, truncation, tag modification, and concatenation
deterministic failures.

## Inner archive and manifest

The decrypted stream is either raw PAX tar or gzip(PAX tar), as selected by
the authenticated header. Every structured payload is deterministic CBOR and
is at most 128 MiB. The final tar member is the untracked
`manifest.tdmanifest`; no member may follow it.

Every preceding member has exactly these TrustDB PAX controls:

```text
trustdb.backup_id
trustdb.ordinal
trustdb.digest
trustdb.digest_algorithm
trustdb.type
trustdb.crypto_suite
```

`path` is permitted only when emitted by PAX for the exact member name. Other
PAX controls are rejected. Ordinals are contiguous from one. `INTL_V1` uses
SHA-256 entry digests and `CN_SM_V1` uses SM3. The manifest repeats the exact
ordered inventory and object counts; any mismatch fails verification.

Known entry families are batch manifests, ProofBundles, batch roots, batch
tree leaves/nodes, Global Log leaves/nodes/state/tiles/outbox, Signed Tree
Heads, immutable STH anchor results, and STH anchor schedules. Unknown paths
or types are rejected. The optional `recovery/key-registry.tdkeys` member
preserves the V2 public key-descriptor and signed key-lifecycle audit log; it
never follows descriptor references to copy private material or credentials.
Writers parse the complete registry and validate its canonical frames, event
chain, signatures, descriptors, and suite before admitting it. This establishes
internal coherence only: the embedded registry public key is evidence, not a
trust root, and restore operators must verify it against a separately trusted
registry public descriptor.

## Restore contract

Restore performs a complete verify pass before publishing its first object.
It then reopens and re-authenticates the archive, comparing the second header
and manifest with the verified values. This prevents a file replacement
between verification and restore from silently changing the imported data.

The destination must use proofstore generation 5 and the exact suite, NodeID,
and LogID. It must be empty unless it is the target of the matching resumable
restore checkpoint. The target NamespaceID may differ from the source, which
preserves logical portability across new directories and storage backends.
Checkpoint v2 binds BackupID, suite, NodeID, LogID, source NamespaceID, target
NamespaceID, last completed ordinal, and member name.

Derived latest-anchor references, L5 coverage checkpoints, and idempotency
indexes are rebuilt from canonical objects. Process-local leases are cleared
before scheduler state is restored. WAL checkpoints are intentionally not
imported.

## Failure behavior

Wrong KEKs, unregistered providers, modified headers/tags/manifests, mixed
suites, digest mismatches, unknown fields or entries, duplicate paths,
non-contiguous ordinals, frame reordering, truncation, trailing bytes,
namespace conflicts, stale checkpoints, and non-empty targets fail closed.
Diagnostics never include passphrases, KEKs, DEKs, provider credentials, or
private material.
