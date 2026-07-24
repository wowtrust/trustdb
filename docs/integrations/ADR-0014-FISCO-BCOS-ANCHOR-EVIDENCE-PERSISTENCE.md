# ADR-0014: Durable FISCO BCOS anchor attempts and immutable evidence

- Status: Accepted implementation design
- Date: 2026-07-24
- Issue: [#465](https://github.com/wowtrust/trustdb/issues/465)
- Depends on: [#464](https://github.com/wowtrust/trustdb/issues/464)
- Protocol boundary: [ADR-0013](ADR-0013-FISCO-BCOS-ANCHOR-PROTOCOL.md)

## Decision

TrustDB persists two different FISCO BCOS objects for one logical anchor:

1. `trustdb.fisco-bcos-attempt-journal.v1` is mutable, append-only provider
   recovery state attached to the scheduler's one immutable `InFlight` Signed
   Tree Head.
2. `trustdb.fisco-bcos-anchor-proof.v2` is the immutable result evidence copied
   into `STHAnchorResult.Proof` after one journaled transaction is proven to
   have emitted the exact expected contract event.

The journal exists because an external submission can succeed before the
process receives a response or commits a local result. It is not an L5 proof.
The completed proof exists because a transaction hash, contract readback, RPC
agreement, or receipt without its native inclusion material is not portable
offline evidence.

The generic anchor scheduler continues to own one `Pending` target and one
immutable `InFlight` target. BCOS `blockLimit` expiry may append and sign a new
transaction attempt, but it never changes the `InFlight` Signed Tree Head,
canonical anchor payload, stream ID, anchor ID, generation, NodeID, LogID,
TreeSize, or RootHash.

## Durable state boundaries

### Before an external side effect

The BCOS driver is split into prepare, submit, and recover operations.
Preparation produces the complete canonical signed transaction without sending
it. Before the first network submission, TrustDB atomically appends that
transaction to the `InFlight` provider journal through a generation,
lease-token, revision, and previous-bytes compare-and-swap.

A prepared attempt is always treated as **possibly submitted** after a crash.
This is intentional: a process can fail immediately after the network write
but before recording any post-submit state. Recovery must query the exact
persisted transaction hash and exact anchor ID before it sends or signs
anything else.

### During retry and recovery

The journal is an ordered history, not a queue whose head is overwritten.
Every attempt remains present in byte-identical form. A state transition may
only add evidence to the current final attempt or append the next attempt.
Existing canonical transaction, signature, sender, hash, block limit, payload
binding, and observations are immutable.

Recovery applies this order:

1. Recompute the canonical payload from the immutable `InFlight` Signed Tree
   Head and require exact equality with the journal.
2. Query every journaled transaction hash and the stable contract anchor ID
   across the configured read quorum.
3. If an exact successful receipt is found, collect its canonical receipt,
   logs, transaction and receipt proofs, block header, event, and consensus
   material, then complete the same logical anchor.
4. If the newest transaction is still admissible, retry only the exact signed
   bytes; do not silently re-sign it.
5. If the newest transaction has a deterministic block-limit rejection, or
   its block limit has passed with no receipt while the exact contract record
   remains absent, append a newly signed attempt for the same payload.
6. If endpoints disagree, the contract contains a different record, or an
   observation cannot be bound exactly, retain the journal and fail closed.

An unknown submission outcome never allows a newer STH to replace the
`InFlight` target. Newer STHs continue to coalesce only into the separate
`Pending` window.

### Completion

Completion is one backend transaction or crash-safe local journal operation:

- write the immutable `STHAnchorResult`, including every signed attempt;
- verify byte equality if the immutable result key already exists;
- clear the matching `InFlight` generation;
- monotonically advance the latest-result reference.

The successful transaction is selected by a 1-based attempt ordinal and exact
hash. It must identify one and only one journal entry. All preceding attempts
remain auditable in the immutable proof.

## Attempt journal format

`trustdb.fisco-bcos-attempt-journal.v1` uses RFC 8949 Core Deterministic CBOR
and contains:

| Field | Rule |
| --- | --- |
| `schema_version` / `format_version` | Exact known values only |
| `generation` | Exact non-zero scheduler `InFlight` generation |
| `revision` | Starts at one and increases by exactly one per CAS update |
| `node_id`, `log_id`, `sink_name` | Exact scheduler key; sink is `fisco-bcos` |
| `tree_size`, `root_hash`, `signed_sth_digest` | Exact immutable target binding |
| `chain_context_id` | Exact 32-byte digest derived from local trust config |
| `canonical_payload` | Exact `AnchorPayload v1` bytes |
| `attempts` | One to 32 ordered attempt records |

Each attempt record contains:

- a contiguous 1-based ordinal;
- the canonical signed transaction bytes;
- the exact signature bytes and sender;
- transaction hash, block limit, and preparation time;
- a bounded outcome enum;
- optional canonical receipt, status, logs, inclusion-proof observations,
  block reference, and observation time.

The transaction hash is an index into recovery and audit data. It is never
accepted as offline evidence by itself.

Allowed outcome transitions are monotonic:

```text
prepared
  -> submit_unknown
       -> receipt_success
       -> receipt_block_limit_rejected
       -> receipt_terminal_rejected
```

`prepared` is recovery-equivalent to `submit_unknown`. The implementation may
persist `submit_unknown` after a send error, but correctness must not depend on
that second write.

Only a deterministic block-limit outcome or a passed block limit with quorum
absence may authorize appending another attempt. A non-block-limit terminal
receipt is retained and makes the scheduler attempt fail closed.

## Immutable proof format

The completed `AnchorProof v2` contains:

- explicit chain mode and algorithm identifiers;
- exact chain, group, genesis checkpoint, contract, and chain-context claims;
- the exact canonical TrustDB anchor payload;
- all journaled canonical signed transaction attempts in ordinal order;
- the successful attempt ordinal and transaction hash;
- canonical successful receipt bytes and explicit numeric/bounded status;
- every canonical receipt log plus the exact decoded `AnchorPublished` event;
- transaction and receipt indexes and native Merkle proof nodes;
- canonical block header bytes, block number, and block hash;
- the block's unique validator signatures. The SDK's live PBFT-view RPC is
  deliberately excluded because it is not a block-specific observation.

The exact event must bind contract address, anchor ID, stream ID, TreeSize,
RootHash, Signed STH digest, publisher, payload version, log index, and the
successful transaction. Contract readback is an additional consistency check,
not a substitute for the event and receipt evidence.

#466 now verifies transaction and receipt inclusion as the independent
`bcos_receipt_inclusion` stage documented in
[ADR-0015](ADR-0015-FISCO-BCOS-OFFLINE-RECEIPT-INCLUSION.md). Until #467
verifies PBFT finality from verifier-local trust roots, the proof remains
`external_observation` and cannot promote records to L5.

## Canonical encodings

The pinned standard SDK's Go structs and normalized JSON are RPC observations,
not canonical native evidence. Receipt and header hash preimages are the exact
ordered field projections defined by
`bcos-tars-protocol/impl/TarsHashable.h` at FISCO BCOS v3.16.3 commit
`274f864e7725fef5b8ed4c6b7a3363ee5396f104`, including its big-endian
integer encoding. They are deliberately not the TARS `data.writeTo(output)`
serialization used by a later upstream implementation. Changing that
projection requires a separately admitted compatibility baseline and live-node
evidence.
The driver must expose independently named native encoders for:

- signed transaction bytes;
- receipt bytes covered by the receipt hash;
- log bytes and event bytes;
- block-header bytes covered by the block hash; and
- transaction and receipt proof nodes.

No function may copy RPC JSON into a field named `raw_canonical_*`. Decoders
must round-trip native bytes and recompute the claimed hash before the evidence
can enter an immutable result. #466 remains responsible for complete offline
Merkle verification, but #465 must not persist knowingly ambiguous encodings.

## Size and count limits

Limits are checked before collection allocation, before cryptographic parsing,
before backend writes, during backup streaming, and again during restore.
Nothing is truncated.

| Object | Limit |
| --- | ---: |
| Attempts per logical anchor | 32 |
| One canonical transaction | 4 MiB |
| One signature | 1 KiB |
| Sender | 256 bytes, exactly 20 in standard mode |
| Receipt, logs, and transaction/receipt proof aggregate | 4 MiB |
| Merkle nodes per path | 512 |
| One proof node | 128 KiB |
| Canonical block header | 2 MiB |
| Commit signatures | 1,024 |
| One commit signature | 1 KiB |
| Block/finality aggregate | 8 MiB |
| Attempt journal | 16 MiB |
| Completed anchor proof | 16 MiB |
| Sink-specific proof in one `STHAnchorResult` | 16 MiB |

Nested and aggregate limits apply together. Thirty-two individually valid
transactions do not bypass the 16 MiB journal/proof ceiling.

## Proofstore contract

The scheduler store gains a provider-state CAS operation scoped by:

```text
(NodeID, LogID, SinkName, generation, lease_token,
 expected_provider_state_bytes)
```

The update succeeds only while the same generation owns the live lease and the
stored provider bytes exactly match the expected bytes. It preserves the
target, retry counters, lease, pending window, and next generation. A stale
worker receives a conflict and must stop.

- File storage uses the existing per-schedule lock and crash-safe publication
  journal.
- Pebble writes the schedule revision and provider bytes in one synchronous
  batch.
- TiKV uses one transaction and compare-and-swap retry without weakening the
  generation/lease/previous-bytes checks.

Immutable result insertion compares complete deterministic CBOR bytes.
Same-key byte differences are data loss, including a missing attempt,
reordered logs, changed status text, changed proof node, or changed finality
signature.

## Logical backup and restore

Logical backup remains mandatory:

- the complete attempt journal is carried inside the backed-up `InFlight`
  schedule;
- the complete immutable proof is carried inside the backed-up
  `STHAnchorResult`;
- lease owner, token, and deadline are cleared on restore;
- provider-state bytes, generation, target, retry history, attempts, and
  evidence are otherwise byte-identical;
- restore validates every nested size/count/schema boundary before the first
  backend mutation;
- restoring a different journal or immutable result at the same key fails
  closed.

Latest-anchor references and L5 projection checkpoints remain derived and are
rebuilt. No logical backup path may omit BCOS provider state merely because the
anchor has not completed.

The current stacked implementation uses the repository's active logical-backup
container. When #454 lands the V2/proofstore-v5/backup-v5 cutover, this object
contract is carried unchanged into typed backup-v5 entries; no v4 fallback,
dual reader, or migration path is added.

## Crash matrix

| Crash point | Required recovery |
| --- | --- |
| Before journal append | No external send occurred; prepare again |
| After journal append, before send | Treat as possibly submitted; lookup first |
| During/after send, before response | Lookup exact hash and anchor ID |
| After receipt, before journal enrichment | Re-fetch and revalidate exact receipt |
| After proof construction, before result commit | Reconstruct byte-identical proof |
| After result write, before schedule cleanup | Existing result reconciles and clears matching `InFlight` |
| After backup restore | Lease cleared; resume the same generation and attempt journal |

## Rejected alternatives

- **Store only the transaction hash.** It cannot prove the signed bytes,
  sender, receipt inclusion, contract event, block identity, or finality.
- **Create one logical result per block-limit retry.** It misrepresents one
  immutable STH publication intent as several anchors and loses the scheduler
  binding.
- **Replace failed or unknown attempts.** It destroys the audit trail and can
  hide a transaction that was accepted externally.
- **Complete from contract readback alone.** It cannot identify or prove the
  transaction and receipt that emitted the event.
- **Fetch missing evidence during offline verification.** It changes a
  portable proof into an online availability claim and is forbidden.
