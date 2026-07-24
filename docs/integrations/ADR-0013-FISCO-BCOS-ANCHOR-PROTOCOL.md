# ADR-0013: Versioned FISCO BCOS anchor payload and local trust configuration

- Status: Accepted protocol boundary; publication, receipt verification, and PBFT finality remain follow-up work
- Date: 2026-07-24
- Issue: [#462](https://github.com/wowtrust/trustdb/issues/462)
- Compatibility baseline: [ADR-0012](ADR-0012-FISCO-BCOS-3X-COMPATIBILITY-BASELINE.md)
- Golden vectors: [`fisco-bcos-anchor-payload-v1.json`](../../test/vectors/fisco-bcos-anchor-payload-v1.json) and [`fisco-bcos-trust-config-v1.json`](../../test/vectors/fisco-bcos-trust-config-v1.json)

## Decision

TrustDB defines three independent versioned objects for FISCO BCOS anchoring:

1. `AnchorPayload v1` is a chain-neutral, canonical binary binding to one exact TrustDB Signed STH.
2. `TrustConfig v1` is local configuration that pins one BCOS chain, group, checkpoint, contract, validator set, certificate configuration, endpoint quorum, and account provider.
3. `AnchorProof v1` is the immutable evidence envelope carried in `STHAnchorResult.Proof` and therefore in `.sproof`. It combines the canonical payload with untrusted chain claims, all signed transaction attempts, receipt and Merkle material, a block header, and PBFT commit signatures.

The same `AnchorPayload` bytes can be published to a standard or Guomi BCOS network. The proof is not portable across those networks: `ChainContextID` binds the explicit mode and locally pinned chain context. This separation preserves TrustDB cryptographic semantics while allowing BCOS-native transaction and consensus cryptography to vary independently.

This ADR does not implement a BCOS sink, a Solidity contract, native receipt decoding, Merkle verification, or PBFT finality verification. A structurally valid `AnchorProof` is not an L5 success by itself. Offline verification must later pass the separate exact-STH, receipt-inclusion, and finality stages using local trust material.

## Cryptographic modes are explicit

Neither endpoint shape nor returned data may select a crypto mode.

| `crypto_mode` | Protocol binding hash | BCOS-native hash | BCOS-native signature | Transport certificate mode |
| --- | --- | --- | --- | --- |
| `standard` | SHA-256 | Keccak-256 | ECDSA/secp256k1 | TLS |
| `guomi` | SM3 | SM3 | SM2/SM3 | GM TLS dual certificate |

Every `TrustConfig` and `AnchorProof` serializes all three algorithm identifiers. Validation rejects any mismatched combination, including standard mode with SM3, Guomi mode with Keccak-256, standard TLS for a Guomi endpoint, an SM2 account on a standard chain, or a standard account on a Guomi chain.

The protocol binding hash is not a replacement for BCOS-native hashing. Standard transaction, receipt, and block hashes remain Keccak-256; Guomi native objects remain SM3. Follow-up verifiers must decode and hash the native object format selected by `crypto_mode`.

## Canonical TrustDB anchor payload

`AnchorPayload v1` begins with the eight bytes `54 44 42 42 43 4f 53 00` (`TDBBCOS\0`) and a big-endian `uint16` version. It then encodes these fields in order:

| Field | Encoding |
| --- | --- |
| `crypto_suite` | `uint16 length || UTF-8 bytes` |
| `tree_algorithm` | `uint16 length || UTF-8 bytes` |
| `root_hash_algorithm` | `uint16 length || UTF-8 bytes` |
| `sth_digest_algorithm` | `uint16 length || UTF-8 bytes` |
| `node_id` | `uint16 length || UTF-8 bytes` |
| `log_id` | `uint16 length || UTF-8 bytes` |
| `sink_name` | `uint16 length || "fisco-bcos"` |
| `tree_size` | big-endian `uint64` |
| `root_hash` | `uint16 length || raw digest bytes` |
| `signed_sth_digest` | `uint16 length || raw digest bytes` |
| `stream_id` | exactly 32 raw bytes |
| `anchor_id` | exactly 32 raw bytes |

The decoder rejects an unknown version, wrong magic, oversized field, invalid suite/algorithm combination, stale derived ID, short input, and trailing input. There is no permissive or heuristic parser.

The canonical Signed STH digest is:

```text
Suite.AnchorDigest(
  RFC 8949 Core Deterministic CBOR(exact SignedTreeHead)
)
```

The exact Signed STH includes its schema, tree algorithm, tree size, root hash, timestamp, NodeID, LogID, signature algorithm, KeyID, and signature bytes. Changing any field changes `signed_sth_digest` and `anchor_id`.

The payload carries the existing TrustDB root bytes exactly. Anchoring an `INTL_V1` STH on a Guomi chain does not convert its SHA-256 Merkle tree into SM3. Anchoring a `CN_SM_V1` STH on a standard chain does not convert its SM3 tree into SHA-256 or Keccak-256.

## Domain-separated identifiers

The domain frame is:

```text
uint16_be(domain length)
domain bytes
uint16_be(field count)
repeat field count times:
  uint32_be(field length)
  field bytes
```

`StreamID` identifies the immutable TrustDB log stream:

```text
Suite.AnchorDigest(
  Frame("trustdb/fisco-bcos/stream/v1",
        crypto_suite, node_id, log_id, "fisco-bcos")
)
```

`AnchorID` identifies one exact Signed STH publication intent:

```text
Suite.AnchorDigest(
  Frame("trustdb/fisco-bcos/sth-anchor/v1",
        crypto_suite,
        tree_algorithm,
        node_id,
        log_id,
        "fisco-bcos",
        stream_id,
        uint64_be(tree_size),
        root_hash_algorithm,
        root_hash,
        sth_digest_algorithm,
        signed_sth_digest)
)
```

The ID is chain-neutral so retries and multi-network publication keep one logical TrustDB anchor identity. A proof's `ChainContextID` provides the chain-specific binding.

## Local trust configuration

`TrustConfig v1` uses RFC 8949 Core Deterministic CBOR with duplicate-key, indefinite-length, unknown-field, and trailing-data rejection. Canonicalization sorts set-like endpoint, CA, certificate-pin, and validator collections before encoding.

The configuration includes:

- explicit mode and protocol/native algorithm identifiers;
- chain ID and group ID;
- genesis hash and a trusted block number/hash checkpoint;
- exact contract address, code hash, protocol version, and event signature;
- RPC endpoints and a required read quorum;
- a non-secret account provider, KeyID, and key reference;
- TLS or GM TLS certificate references and local CA/peer certificate hashes;
- a fixed `fisco-bcos-pbft-2f-plus-1-v1` validator quorum policy;
- locally pinned validator NodeIDs, algorithms, encodings, and public keys;
- the fixed SM2 user ID `1234567812345678` in Guomi mode.

Private keys are never serialized into this configuration. Guomi mode requires separate signing and encryption certificate/key references. Standard mode rejects those Guomi-only encryption references.

`TrustConfigDigest` covers the complete canonical local configuration. `ChainContextID` covers the immutable offline chain trust boundary: mode and algorithms, chain/group, genesis/checkpoint, contract, quorum policy, SM2 user ID, and validator-set digest. Runtime endpoint order, account provider references, and transport-certificate rotation do not change the chain context.

## Evidence cannot supply trust roots

`AnchorProof v1` deliberately does not contain:

- validator public keys or a validator-set threshold;
- CA roots or peer certificate pins;
- endpoint configuration or read quorum;
- account-provider configuration or private keys;
- a TrustDB server public key to auto-trust.

It may contain validator NodeIDs alongside PBFT signatures, but membership and quorum must be computed from the verifier's local `TrustConfig`. The proof's chain, group, checkpoint, contract, mode, and algorithm fields are untrusted claims. `ValidateProofAgainstTrustConfig` compares them to local pins and recomputes `ChainContextID`; it never adopts them.

Certificate pins remain a local transport control rather than part of offline block finality. Rotating a locally trusted SDK certificate can change `TrustConfigDigest` without changing `ChainContextID` or invalidating already exported chain evidence.

## Complete proof envelope

`trustdb.fisco-bcos-anchor-proof.v1` contains:

- explicit mode and algorithm identifiers;
- chain/group/genesis/checkpoint and contract claims;
- `ChainContextID`;
- the exact canonical payload bytes;
- every immutable signed transaction attempt, sender, transaction hash, block limit, and submission time;
- the successful transaction hash;
- raw canonical receipt, receipt hash, transaction/receipt indexes and Merkle paths, log index, and decoded anchor event;
- raw canonical block header, block hash, and block number;
- PBFT view, round, and unique validator-node signatures.

The schema has bounded counts and byte sizes and rejects duplicate transaction hashes and duplicate finality signers. Structural validation does not trust the decoded event, receipt status, Merkle paths, block header, signatures, or claimed context. Follow-up issues must recompute each native hash and semantic binding.

`STHAnchorResult` retains its current outer schema. For the `fisco-bcos` sink:

- `AnchorID` is lowercase hexadecimal `AnchorPayload.anchor_id`;
- NodeID, LogID, TreeSize, RootHash, and the complete Signed STH must exactly match the Global Log proof STH;
- `Proof` is deterministic CBOR `AnchorProof v1`;
- `.sproof v1` can carry the proof without ambiguity and now strictly decodes the provider proof during container validation.

No rule is relaxed to `anchor.TreeSize >= proof.TreeSize`. A historical batch may use a later covering STH only when the Global Log inclusion path targets that exact later STH and the anchor result binds that same STH.

## Verification stages

The final offline verifier must report and enforce these stages separately:

1. Verify the TrustDB Signed STH with a locally trusted TrustDB public key.
2. Verify the batch inclusion path into that exact Signed STH.
3. Recompute and compare the canonical payload, StreamID, AnchorID, and local ChainContextID.
4. Decode the BCOS transaction and receipt, recompute native hashes and Merkle inclusion, and match the pinned contract event.
5. Decode the block header and verify PBFT finality against the locally pinned checkpoint and validator set.

Only success at every stage may produce L5. Transaction existence, receipt existence, a transaction hash reference, multiple agreeing RPC nodes, or a block timestamp is not an offline finality proof. BCOS block time is consensus metadata and must not be represented as an RFC 3161 trusted timestamp.

## Compatibility and follow-up boundaries

- #463 implements the immutable `TrustDBAnchorV1` contract and event from this payload.
- #464 implements the standard-mode driver and sink without changing anchor scheduler semantics. Its raw observation keeps only signatures bound to the requested historical block; the latest-only `getPbftView` value is never relabeled as that block's view or round. An exact record already visible through every configured endpoint prevents an immediate duplicate submission, but #464 does not claim recovery when the original transaction is still pending or temporarily invisible.
- #465 persists byte-identical transaction, receipt, Merkle, block, and finality material plus every block-limit retry.
- #470 adds deterministic lookup/rebroadcast, block-limit refresh, duplicate handling, and bounded stale-endpoint/read-quorum retry policy before a replacement transaction may be created.
- #466 independently verifies transaction/receipt inclusion.
- #467 independently verifies static-validator PBFT finality.
- #468 adds Guomi-native account, dual-certificate, hash, receipt, block, proof, and finality handling without changing the chain-neutral TrustDB payload.

The golden vectors are protocol artifacts. Any intentional byte change requires a new payload/proof/config version and reviewed vector replacement; it must not silently rewrite v1.
