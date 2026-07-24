# ADR-0015: Offline FISCO BCOS receipt inclusion verification

- Status: Accepted receipt-inclusion boundary; PBFT completion is defined by
  [ADR-0016](ADR-0016-FISCO-BCOS-STATIC-PBFT-FINALITY.md)
- Date: 2026-07-25
- Issue: [#466](https://github.com/wowtrust/trustdb/issues/466)
- Depends on: [#465](https://github.com/wowtrust/trustdb/issues/465) and
  [#455](https://github.com/wowtrust/trustdb/issues/455)
- Protocol boundary:
  [ADR-0013](ADR-0013-FISCO-BCOS-ANCHOR-PROTOCOL.md)
- Persistence boundary:
  [ADR-0014](ADR-0014-FISCO-BCOS-ANCHOR-EVIDENCE-PERSISTENCE.md)

## Decision

TrustDB verifies persisted FISCO BCOS transaction and receipt inclusion as a
separate offline stage named `bcos_receipt_inclusion`. Passing this stage means:

1. one canonically encoded, correctly signed BCOS transaction called the
   locally pinned TrustDB anchor contract with the exact payload derived from
   the carried Signed Tree Head;
2. the transaction hash is included at the exact transaction index in the
   transaction root of the carried block header;
3. the exact successful receipt hash is included at the same receipt index in
   the receipt root of that block header; and
4. the receipt contains exactly one correctly encoded `AnchorPublished` event
   at the claimed log index, binding the contract, publisher, anchor ID,
   stream ID, TreeSize, RootHash, Signed STH digest, and payload version.

This is an inclusion statement about a specific carried BCOS block header. It
is not evidence that the block belongs to the verifier's trusted finalized
PBFT chain. The immutable result therefore remains
`evidence_stage=external_observation`; receipt inclusion alone remains L4 and
does not change projector or proofstore state. ADR-0016 adds independent PBFT
finality and exact-binding stages that may promote only the local offline
verification result to L5.

## Verifier-local trust only

The verifier requires an independent canonical `TrustConfig`. Evidence cannot
supply, override, or extend:

- BCOS standard/Guomi mode;
- chain ID, group ID, genesis hash, or trusted checkpoint;
- contract address, code hash, protocol version, or event signature;
- validator set, SM2 user ID, or quorum policy; or
- certificate, endpoint, and account-provider configuration.

Receipt inclusion compares the committed chain context to this local config.
It never opens an endpoint, resolves DNS, reads a provider key, loads a
certificate reference, contacts a CA, or fetches missing bytes. Endpoint and
file-reference strings may point to unavailable resources and verification
still succeeds when the carried evidence is complete. Certificates or keys
inside an evidence file are never promoted to trust roots.

The CLI accepts the local config only through:

```text
trustdb verify \
  --file ./artifact.bin \
  --sproof ./artifact.sproof \
  --client-public-key ./client-public.cbor \
  --server-public-key ./server-public.cbor \
  --fisco-bcos-trust-config /absolute/path/fisco-bcos-trust.cbor
```

The file must be canonical deterministic CBOR, absolute, clean, regular, and
non-symlinked. Loading that one verifier-selected file is local input, not
network or provider access. SDK callers set
`sdk.OfflineTrust.FISCOBCOS`; leaving it nil fails the named inclusion stage
when raw BCOS evidence is present. `SkipAnchor` skips this optional stage but
does not convert its unverified bytes into an anchor claim.

## Independent cryptographic profiles

BCOS chain mode and the TrustDB proof suite are independent:

| Input | Standard BCOS | Guomi BCOS |
| --- | --- | --- |
| BCOS transaction/receipt/block hash | Keccak-256 | SM3 |
| ABI function selector/event topic | Keccak-256 | SM3 |
| Publisher signature | secp256k1 `[R || S || V]` | SM2 `[R || S || public key]` |
| Publisher address | Keccak-256 public-key suffix | SM3 public-key suffix |

TrustDB payload bytes, RFC 6962 tree algorithm, Signed STH signature, and STH
digest remain governed exclusively by the `INTL_V1` or `CN_SM_V1` TrustDB
suite carried by the Signed STH. A standard BCOS chain may anchor a
`CN_SM_V1` STH, and a Guomi BCOS chain may anchor an `INTL_V1` STH. The BCOS
mode must never silently select a TrustDB suite.

Guomi transaction verification uses the fixed verifier-local SM2 user ID
required by the versioned trust profile. The public key embedded in the
128-byte BCOS transaction signature is used only to verify that transaction
and derive its sender. It is not a general trust root.

## Canonical transaction decoding

The transaction is decoded by the pinned pure-Go TARS implementation and
re-encoded byte for byte. Before that decoder runs, a bounded TARS preflight
walks every header, scalar, string, list, map, simple list, and nested struct.
Every wire length must fit inside the already bounded transaction; nesting and
element counts are capped. A transaction-schema preflight additionally
requires the generated reader's fixed-size `dataHash` field, and the optional
`sender` field when present, to use canonical byte SimpleLists of exactly 32
and 20 bytes. This rejects malicious LIST counts before they can index the
SDK's fixed arrays. The SDK decode call has a narrow panic-to-error boundary as
defense in depth; it does not replace the schema checks. TrustDB performs the
canonical re-encoding itself in the pinned field order because the generated
Go writer dereferences a nil optional sender even though the C SDK legitimately
omits that field. Unknown fields, alternate encodings, trailing bytes,
oversized allocation claims, and non-canonical round trips fail.

This proof version admits BCOS transaction-data versions 0 and 1 only. The
current TrustDB writer generates version 0: its repository-pinned Go wrapper
calls `bcos_sdk_create_transaction_data`, whose pinned
`TransactionBuilder::createTransactionData` path is asserted as version 0 by
the same C SDK's `testTransaction.cpp`. The `V1` suffix in the Go wrapper
method name does not mean BCOS transaction-data version 1. The verifier also
supports and directly tests the separate version-1 consensus hash projection
implemented by the pinned Go SDK. Version 2 and every other value fail before
signature or inclusion verification: Go SDK `v3.0.2` does not define the
version-2 extension-field hash projection used by this verifier, so accepting
it would silently omit consensus fields.

The verifier then requires exact equality for:

- chain ID and group ID;
- positive block limit;
- contract address;
- complete mode-specific `publish(...)` call data;
- signature and optional encoded sender;
- declared transaction data hash, recomputed hash, successful-attempt hash,
  and receipt transaction hash; and
- recovered/verified publisher address and event publisher.

Every historical attempt remains in the immutable proof. Receipt inclusion
uses only the attempt selected by the exact contiguous 1-based successful
ordinal and successful transaction hash. It does not delete or rewrite earlier
attempts.

## Native receipt, block, and Merkle encoding

Receipt and block-header consensus preimages are reconstructed from the exact
field order pinned in ADR-0014 and hashed under the local BCOS mode. JSON-RPC
serialization is never a consensus preimage.

FISCO BCOS `v3.16.3` uses a width-two Merkle proof represented as a flat
sequence:

```text
big-endian uint32 group_count
group_count × 32-byte ordered hashes
... repeated until the root
```

Each group count must be one or two. The current hash must occur exactly once
in each group. Ordered concatenation is hashed under the selected BCOS chain
mode to produce the next level. Its position also derives the leaf-index bit;
the derived index must equal the carried transaction or receipt index. The
transaction and receipt indices must be equal. A one-leaf tree is represented
by the one 32-byte root and requires index zero.

Count nodes of any other size, zero/wide groups, truncated groups, dangling
nodes, non-32-byte hashes, duplicate/missing current hashes, index overflow,
wrong order, wrong root, or trailing data fail closed. Parsing is limited to
512 proof nodes and the existing receipt aggregate byte budget.

Repository-generated conformance vectors in
`test/vectors/fisco-bcos-receipt-inclusion-{standard,guomi}-v1.json` pin the
standard and Guomi hashes and ABI identifiers derived from the documented flat
proof format in the FISCO BCOS `v3.16.3` Merkle implementation. These are
TrustDB-authored, format-derived test inputs, not captured upstream fixtures
or live-node evidence.

## Strict event binding

The verifier derives the event topic from the locally pinned exact event
signature and selected BCOS mode. It requires:

- one canonical lowercase 20-byte hex log address without `0x`;
- exactly four 32-byte topics;
- exactly four 32-byte ABI data words;
- zero ABI padding for `uint64`, `address`, and `uint16`;
- exactly one matching event for the pinned contract and event topic; and
- exact equality between the decoded native log, the canonical stored event,
  the anchor payload, and the successful transaction sender.

A second matching event is ambiguous and fails. The event log index is exact;
the verifier does not search for a convenient alternative event after an
index mismatch.

## `.sproof`, API, SDK, and export behavior

Global evidence export may carry a covering raw FISCO BCOS result together
with the inclusion proof generated directly against that result's exact
Signed STH. This makes the offline file complete without changing generic
anchor semantics.

For raw BCOS evidence:

- `global_log` verifies normally;
- generic `anchor` is `not_present`, because no offline L5 anchor has been
  established;
- `bcos_receipt_inclusion` is `passed`, `failed`, `skipped`, or `not_run`;
- the recomputed proof level remains L4 unless the independent ADR-0016
  finality and exact-binding stages also pass; and
- `AnchorSink` and `AnchorID` are reported only after inclusion succeeds.

Generic `AnchorBindingConsistency` continues to require
`offline_verified`. The BCOS path does not weaken it and cannot make other raw
or custom providers eligible for L5. The raw proof is retained byte for byte
in `STHAnchorResult`; no store, scheduler, L5 projector, backup, or restore
mutation is introduced by verification.

## Failure and test contract

The verifier fails on mutation of any transaction byte, hash, signature,
sender, call data, transaction/receipt index, Merkle count/hash/order, receipt
field, log, event topic/data/padding/index, block root, contract binding,
payload field, or Signed STH field. Wrong chain mode, wrong contract, wrong
chain context, and missing local trust fail.

Tests cover:

- format-derived standard and Guomi conformance vectors, explicitly identified
  as TrustDB-authored rather than upstream fixtures;
- standard BCOS with a `CN_SM_V1` STH and Guomi BCOS with an `INTL_V1` STH;
- disconnected/nonexistent endpoint, provider, and certificate references;
- wrong mode and exact Signed STH suite drift;
- mutation, strict bounds, fixed-array decoder regressions, and explicit
  transaction-data v0/v1 admission with all other versions rejected;
- fuzzing of TARS and Merkle parsers;
- L4 stage reporting and skip behavior; and
- export of a covering raw BCOS result without L5 promotion.

The verifier is untagged pure Go and does not require cgo or the BCOS C SDK.
Windows and macOS builds compile the same verification path.

## Rejected alternatives

- **Treat a successful RPC response as inclusion.** A node assertion is not a
  portable proof.
- **Trust the proof's crypto mode or contract.** Evidence cannot select its
  own trust boundary.
- **Accept `anchor.TreeSize >= proof.TreeSize`.** Inclusion binds the exact
  Signed STH carried by the global proof and result.
- **Use transaction and receipt hashes without exact indices.** This permits
  ambiguous or reordered proof claims.
- **Promote receipt inclusion to L5.** Inclusion in an unfinalized carried
  header is not trusted PBFT finality.
- **Fetch validators, certificates, or missing proof nodes while offline.**
  It makes validity depend on current network/provider state and is forbidden.

## Normative upstream references

- FISCO BCOS `v3.16.3`
  [`Merkle.h`](https://github.com/FISCO-BCOS/FISCO-BCOS/blob/v3.16.3/bcos-crypto/bcos-crypto/merkle/Merkle.h)
  defines the flat proof sequence, big-endian count nodes, width-two grouping,
  proof generation, and verification.
- FISCO BCOS `v3.16.3`
  [`TarsHashable.h`](https://github.com/FISCO-BCOS/FISCO-BCOS/blob/v3.16.3/bcos-tars-protocol/bcos-tars-protocol/impl/TarsHashable.h)
  defines the pinned receipt and block-header hash projections.
- The repository-pinned Go SDK `v3.0.2` defines the standard/SM transaction
  data hash and canonical TARS transaction structures.
- The repository-pinned C SDK commit
  [`a278b4749e34`](https://github.com/FISCO-BCOS/bcos-c-sdk/blob/a278b4749e342d2b111d736045db9ed98a63224d/bcos-c-sdk/bcos_sdk_c_uti_tx.cpp)
  defines the writer's `bcos_sdk_create_transaction_data` path; its
  [`testTransaction.cpp`](https://github.com/FISCO-BCOS/bcos-c-sdk/blob/a278b4749e342d2b111d736045db9ed98a63224d/test/testTransaction.cpp)
  asserts that this path decodes to transaction-data version 0.
