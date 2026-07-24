# TrustDB single proof v2

Status: implemented by [#455](https://github.com/wowtrust/trustdb/issues/455).

Schema: `trustdb.sproof.v2`

Format version: `2`

## Purpose

`.sproof v2` is the portable, deterministic CBOR evidence container for one
TrustDB record. It carries every immutable object needed to recompute the
available L1-L5 proof path while disconnected from TrustDB, certificate
services, timestamp providers, and anchor networks.

The file is evidence, not a trust store. Public keys, certificate chains,
registry manifests, validator sets, checkpoints, or CA certificates carried by
the file never authorize themselves. A verifier supplies its trusted public
keys, CA roots, registry signer, anchor policy, and chain checkpoints through
local configuration.

## Encoding and cutover

- The encoding is RFC 8949 Core Deterministic CBOR.
- The complete file is limited to 24 MiB.
- Unknown fields, duplicate map keys, tags, indefinite-length values,
  non-canonical values, trailing data, unknown suites, and mixed suites fail
  closed.
- Readers accept only schema `trustdb.sproof.v2` and `format_version = 2`.
- The retired v1 schema is not read, migrated, guessed, or used as a fallback.

## Top-level fields

| Field | Rule |
| --- | --- |
| `schema_version` | exactly `trustdb.sproof.v2` |
| `format_version` | exactly `2` |
| `crypto_suite` | exactly `INTL_V1` or `CN_SM_V1` |
| `record_id` | exactly the embedded `ProofBundle.record_id` |
| `proof_level` | descriptive only; the verifier recomputes it |
| `node_id` | required and equal in the bundle, Global Log proof, STH, and anchor |
| `log_id` | required and equal in the bundle, Global Log proof, STH, and anchor |
| `proof_bundle` | the complete V2 L1-L3 proof bundle |
| `global_proof` | optional V2 batch-root inclusion proof targeting one exact STH |
| `anchor_result` | optional exact anchor result for that same STH |
| `identity_evidence` | optional bounded public identity and status evidence |
| `exported_at_unix_nano` | export metadata; never used as trusted proof time |

Every nested V2 object must carry the same `crypto_suite`. Equal digest length
does not establish algorithm compatibility.

## Global and anchor evidence

When `global_proof` exists, its inclusion path proves the batch root directly
against the carried Signed Tree Head. Its suite, NodeID, LogID, TreeSize, tree
algorithm, leaf, root, and signature input are recomputed.

When `anchor_result` exists:

- `global_proof` is mandatory;
- suite, NodeID, LogID, TreeSize, RootHash, and the complete Signed Tree Head
  are exactly equal;
- the sink-specific immutable proof bytes are complete;
- a larger TreeSize is not accepted as a substitute for an exact binding.

Provider evidence such as a FISCO BCOS transaction, receipt proof, block
header, PBFT finality material, and validator transition chain is carried
inside the versioned anchor proof. Receipt inclusion, finality, TrustDB STH
binding, and trust-root selection remain separate fail-closed stages.

## Identity evidence

`identity_evidence` contains at most 16 entries. An entry is uniquely keyed by
`(role, key_id)`, where role is `client` or `server`, and must reference a key
actually used by an embedded signature.

Each entry contains:

- schema `trustdb.proof-identity-evidence.v1`;
- the same `crypto_suite`;
- one canonical public `trustdb.key-descriptor.v1` verifier descriptor;
- optional complete Key Registry V2 bytes for reconstructing client
  signing-time lifecycle;
- up to 16 certificate status objects.

Signer descriptors and private provider references are not accepted as the
public descriptor. A carried Key Registry V2 stream remains untrusted until
its manifest and event chain are verified against a verifier-local registry
public key.

Certificate status schema
`trustdb.certificate-status-evidence.v1` currently permits only strict DER
CRLs. Each status object carries the suite-specific issuer fingerprint and at
most 4 MiB of signed status bytes. Unknown status types, duplicate issuer
statuses, a status without a certificate chain, wrong-suite status, malformed
CRL, ambiguous issuer, bad signature, stale interval, or a revocation effective
at the signature time fails verification.

OCSP is intentionally not inferred from arbitrary response bytes. Adding OCSP
requires a new reviewed status profile that fixes responder authorization,
signature algorithm, request/certificate binding, produced/this/next-update
rules, nonce/replay policy, and unavailable-responder behavior.

## Offline verification sequence

1. Enforce the total file bound before decoding.
2. Decode the exact schema and re-encode canonically.
3. Enforce all component, collection, path, certificate, status, and anchor
   limits.
4. Require one suite and exact NodeID/LogID bindings throughout.
5. Hash the supplied content with the suite content hash.
6. Verify the client claim and signing-time lifecycle against local trust.
7. Recompute the record ID, receipts, and batch Merkle path.
8. Recompute the Global Log leaf/path and verify the STH with local server
   trust.
9. Verify certificate chains and signed status material against local CA
   roots when the selected profile requires certificates.
10. Verify the exact anchor proof and any provider-specific offline trust
    chain.
11. Report each stage and derive L1-L5 only from successful recomputation.

The verifier performs no HTTP, gRPC, NATS, DNS, CA, OCSP, CRL distribution,
provider, or blockchain RPC request. Missing local trust material is an
explicit precondition failure, never a network fallback.

## Structured offline result

The offline verifier reports these ordered stages:

1. `sproof_container`
2. `identity_evidence`
3. `proof_bundle`
4. `content`
5. `client_claim`
6. `bundle_bindings`
7. `accepted_receipt`
8. `committed_receipt`
9. `batch_merkle`
10. `global_log`
11. `anchor`
12. `bcos_receipt_inclusion`
13. `bcos_pbft_finality`
14. `bcos_exact_anchor_binding`

Each stage is `passed`, `failed`, `not_present`, `skipped`, or `not_run`.
A failed stage prevents every later applicable stage from running. Optional
Global Log or anchor evidence is reported as `not_present`; an anchor ignored
by explicit verifier policy is `skipped`. The result also reports
`external_network_access=false` and `external_provider_access=false`.

For a raw FISCO BCOS anchor, generic `anchor` is `not_present`. The three
provider stages are independently recomputed from verifier-local
`TrustConfig`; all three must pass before the offline result reports L5.
`--skip-anchor` marks all three provider stages `skipped`.

The CLI uses the verifier-local public descriptors passed through
`--client-public-key`, `--server-public-key`, and
`--registry-public-key`. When accepted receipts, committed receipts, and STHs
span a server-key rotation, repeatable `--additional-server-public-key` flags
provide the other verifier-local historical keys. Each signature is verified
only with the exact trusted descriptor matching its `key_id`; one current
server key is never substituted for a referenced historical key. Repeatable
`--client-ca-certificate` and `--server-ca-certificate` flags accept strict
DER or certificate-only PEM roots. `--require-certificate-status` requires a
CRL covering every actual signature time for every carried certificate chain.

If a file carries any identity evidence, the CLI requires complete evidence
for every referenced client and server signature key. An incomplete subset
fails closed. Local `.sproof` verification never launches an external anchor
plugin; provider-specific offline verification must be implemented as a
bounded in-process verifier whose trust roots are supplied locally.
