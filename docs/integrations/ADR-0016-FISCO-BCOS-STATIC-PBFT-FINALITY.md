# ADR-0016: Offline FISCO BCOS static-validator PBFT finality

- Status: Accepted
- Date: 2026-07-25
- Issue: [#467](https://github.com/wowtrust/trustdb/issues/467)
- Depends on: [ADR-0015](ADR-0015-FISCO-BCOS-OFFLINE-RECEIPT-INCLUSION.md)
- Current TrustConfig/proof schemas and the optional transition policy are
  defined by [ADR-0017](ADR-0017-FISCO-BCOS-VALIDATOR-SET-TRANSITIONS.md).
- Admitted node baseline: FISCO BCOS `v3.16.3`, commit
  `274f864e7725fef5b8ed4c6b7a3363ee5396f104`

## Decision

TrustDB verifies a carried FISCO BCOS block's PBFT proof against the
verifier-local static validator checkpoint. Offline verification exposes three
provider stages after the ordinary TrustDB and Global Log stages:

1. `bcos_receipt_inclusion` first checks the immutable proof container, exact
   STH/result envelope, and verifier-local crypto, chain, checkpoint, and
   contract context, then proves that the canonical transaction and successful
   receipt belong to the roots of the carried block header. It deliberately
   does not interpret the call data or event as a TrustDB publication;
2. `bcos_pbft_finality` proves that the locally trusted static validator quorum
   signed the exact hash of that header; and
3. `bcos_exact_anchor_binding` defensively reapplies the common container and
   local-context checks, then proves that the exact Signed STH payload,
   successful contract call, event, publisher, and outer anchor result all
   identify one TrustDB publication.

The raw immutable `STHAnchorResult` remains
`evidence_stage=external_observation`. A local offline result is promoted from
L4 to L5 only when the ordinary TrustDB proof, Global Log proof, all three BCOS
stages, and exact namespace/STH bindings pass. Verification does not mutate
the proof, result, proofstore, L5 projector, or backup.

`--skip-anchor` marks all three BCOS stages `skipped` and leaves the result at
L4. Missing local BCOS trust fails the first applicable stage; a receipt
failure leaves finality and binding `not_run`; a finality failure leaves
binding `not_run`.

## Pinned upstream consensus semantics

The implementation follows these primary-source rules from the admitted
release:

- [`TarsHashable.h`](https://github.com/FISCO-BCOS/FISCO-BCOS/blob/v3.16.3/bcos-tars-protocol/bcos-tars-protocol/impl/TarsHashable.h)
  defines the signature-excluding block-header hash projection already pinned
  by ADR-0015.
- [`PBFTMessageFactory.h`](https://github.com/FISCO-BCOS/FISCO-BCOS/blob/v3.16.3/bcos-pbft/bcos-pbft/pbft/interfaces/PBFTMessageFactory.h)
  signs the proposal hash, and
  [`LedgerStorage.cpp`](https://github.com/FISCO-BCOS/FISCO-BCOS/blob/v3.16.3/bcos-pbft/bcos-pbft/pbft/storage/LedgerStorage.cpp)
  copies each validator index and proof signature into the committed block
  header.
- [`BlockValidator.cpp`](https://github.com/FISCO-BCOS/FISCO-BCOS/blob/v3.16.3/bcos-pbft/bcos-pbft/pbft/engine/BlockValidator.cpp)
  requires the header sealer/weight lists to equal the configured consensus
  list, verifies each signature over `blockHeader->hash()`, sums signer vote
  weights, and compares the result to `minRequiredQuorum`.
- [`PBFTConfig.cpp`](https://github.com/FISCO-BCOS/FISCO-BCOS/blob/v3.16.3/bcos-pbft/bcos-pbft/pbft/config/PBFTConfig.cpp)
  computes `maxFaultyWeight = floor((totalWeight - 1) / 3)` and
  `minRequiredQuorum = totalWeight - maxFaultyWeight`.
- [`JsonRpcImpl_2_0.cpp`](https://github.com/FISCO-BCOS/FISCO-BCOS/blob/v3.16.3/bcos-rpc/bcos-rpc/jsonrpc/JsonRpcImpl_2_0.cpp)
  exposes each proof as `sealerIndex` plus signature and exposes the ordered
  `sealerList` separately. TrustDB resolves the index while capturing evidence
  and stores the corresponding canonical validator NodeID.

TrustDB additionally rejects duplicate signer identities. The upstream honest
producer cache keys votes by validator index, but accepting duplicated evidence
would otherwise count the same local trust root more than once.

## Static membership and quorum profile

`TrustConfig v2` pins each validator public key, ordered membership, and
positive vote weight. Under `static-validator-set-v1`, the target header must
match that complete local state exactly. The admitted quorum policy is
`fisco-bcos-weighted-pbft-v2`:

```text
totalWeight    = sum of locally pinned validator vote weights
faultyWeight   = floor((totalWeight - 1) / 3)
requiredWeight = totalWeight - faultyWeight
```

For four unit-weight validators, three distinct valid signatures are required.
Weighted headers are accepted only when every ordered weight exactly matches
the local configuration; weights are never inferred from the evidence.

Every local validator public key uses canonical SEC1 uncompressed 65-byte
encoding. The BCOS NodeID is exactly lowercase `0x` plus the 64-byte `X || Y`
public key. The header must carry every local raw NodeID exactly once, no
unknown key, no omission, no duplicate, the same count of unit weights, and a
valid sealer index. Finality signatures must use those exact canonical NodeIDs.

## Checkpoint and no-ancestry rule

The local checkpoint is an explicit operator assertion that its pinned static
validator set remains authoritative from the checkpoint until the verifier
locally replaces the configuration. The target block must not precede the
checkpoint. If it is at the checkpoint height, its hash must equal the locally
pinned checkpoint hash.

For a later target, no header ancestry path is needed to verify finality:
the required quorum of already-local public keys directly signs the target
header hash, and that signed header repeats the exact local static membership.
An ancestry path would be necessary only to *derive* a changed validator set
from chain governance. This version never does so. A target header with changed
membership or weights fails closed; authenticated membership transitions are
reserved for [#469](https://github.com/wowtrust/trustdb/issues/469).

This model intentionally treats updating the static checkpoint as a local
trust-root operation. It does not claim to prove that governance before the
checkpoint was legitimate, and it does not auto-follow an online node's
current sealer list.

## Signature profiles

### Standard mode

Each PBFT proof is exactly 65 bytes `[R || S || V]` over the already computed
Keccak-256 block hash. The admitted v3.16.3 verifier accepts recovery IDs
`0..3`, while its libsecp256k1 producer emits canonical low-S signatures.
TrustDB pins that producer form:

- `0 < R,S < secp256k1.N`;
- `S <= secp256k1.N/2`;
- `V` is in `0..3`; and
- recovering the public key from the block hash and signature must yield the
  exact locally pinned validator key.

Wrong length, zero/out-of-range scalar, high-S malleation, invalid recovery ID,
recovery failure, or a different recovered key fails.

### Guomi mode

Each PBFT proof is exactly 64 bytes `[R || S]`. FISCO BCOS v3.16.3
`SM2Crypto` passes the 32-byte SM3 block hash as the message to its SM2
implementation, which then applies ZA plus SM3 using the fixed
`1234567812345678` user ID before signing. TrustDB reproduces that exact
preprocessing with the locally pinned SM2 public key. A signature made
directly over the block hash without ZA preprocessing fails closed.

BCOS mode and TrustDB proof suite remain independent. Tests deliberately cover
a standard BCOS block carrying a `CN_SM_V1` TrustDB STH and a Guomi BCOS block
carrying an `INTL_V1` STH.

## CLI and SDK

The CLI consumes one canonical verifier-selected config and does not open any
endpoint or key/certificate reference stored inside it:

```bash
trustdb verify \
  --file ./artifact.bin \
  --sproof ./artifact.sproof \
  --client-public-key ./client-public.cbor \
  --server-public-key ./server-public.cbor \
  --fisco-bcos-trust-config /absolute/path/fisco-bcos-trust.cbor
```

SDK callers decode or construct the same local config and pass it explicitly:

```go
result, err := sdk.VerifySingleProofOffline(
    content,
    proof,
    sdk.OfflineTrust{
        Proof:     trustedProofKeys,
        FISCOBCOS: &localBCOSTrust,
    },
    sdk.OfflineVerifyOptions{},
)
```

`sdk.OfflineStageBCOSReceiptInclusion`,
`sdk.OfflineStageBCOSPBFTFinality`, and
`sdk.OfflineStageBCOSAnchorBinding` are stable names for examining the
structured result. Callers must use `result.Valid` and the recomputed
`result.ProofLevel`; the descriptive L4 label embedded in the immutable raw
file is not a locally verified finality decision.

## Offline and bounded failure contract

The verifier performs no endpoint, DNS, CA, certificate-reference,
account-provider, HSM, or blockchain request. All collections and byte strings
were already bounded by `AnchorProof v3`; finality performs one bounded pass
over at most 1,024 validators/signatures and uses maps keyed only by bounded
canonical NodeIDs.

Tests cover four-validator Standard/Guomi quorum, a target later than the
checkpoint without a direct ancestry edge, wrong/nonmember/duplicate signer,
insufficient quorum, changed membership, weighted quorum, invalid sealer, malformed or
noncanonical signatures, checkpoint mutations, and a fully disconnected
`.sproof` that reaches L5 only after every stage passes.
