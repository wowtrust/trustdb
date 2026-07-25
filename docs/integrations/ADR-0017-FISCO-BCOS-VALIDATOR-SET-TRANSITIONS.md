# ADR-0017: Offline FISCO BCOS validator-set transitions

- Status: Accepted
- Date: 2026-07-25
- Issue: [#469](https://github.com/wowtrust/trustdb/issues/469)
- Depends on: [#467](https://github.com/wowtrust/trustdb/issues/467)
- Scope: FISCO BCOS v3.16.3 PBFT, standard and Guomi cryptographic modes
- TrustConfig: `trustdb.fisco-bcos-trust-config.v2`
- Anchor proof: `trustdb.fisco-bcos-anchor-proof.v3`

## Decision

TrustDB authenticates validator changes with a contiguous, fully offline chain
from a verifier-local checkpoint to the anchored block. A later committee does
not authenticate itself. The trust bridge is:

1. the verifier locally pins the exact checkpoint block hash plus the ordered
   validator set and vote weights active in checkpoint block `N`;
2. every post-checkpoint block is the exact child of its predecessor and is
   finalized by the committee derived for that block height;
3. predecessor block `N` includes every transaction and receipt when the validator set in
   block `N+1` differs;
4. the transaction and receipt lists independently reconstruct `txsRoot` and
   `receiptsRoot`;
5. successful calls to consensus precompile `0x0000000000000000000000000000000000001003`
   are applied in transaction-index order;
6. the exact derived membership and weights appear in block `N+1`; and
7. the new weighted committee finalizes block `N+1`.

The required PBFT weight is pinned to the v3.16.3 rule:

```text
totalWeight - floor((totalWeight - 1) / 3)
```

This verification performs no RPC, DNS, certificate lookup, signer-provider
call, or other network access.

## Local policy is authoritative

`TrustConfig v2` requires one of two local policies:

- `static-validator-set-v1` keeps static verification. It rejects transition
  history and requires the target header to match the local ordered membership
  and weights exactly.
- `authenticated-validator-transitions-v1` requires a contiguous history for
  every target after the checkpoint. Removing history from an evidence file
  cannot fall back to static verification.

Each validator descriptor contains its canonical 65-byte public key and a
positive `vote_weight`. Validator order is checkpoint state because BCOS commit
signatures refer to header sealer indices. Endpoint and certificate-pin sets
remain canonical-sorted.

The checkpoint also carries a positive generation and, after the first
advancement, the digest of the previous TrustConfig. Evidence never contains
an authoritative validator policy, checkpoint generation, or previous
configuration digest.

## Evidence layout

`AnchorProof v3` retains the exact anchor transaction, receipt inclusion,
target header, and target finality evidence. It adds `validator_history`:

- item zero is the exact locally trusted checkpoint block and omits redundant
  checkpoint finality signatures;
- subsequent items are contiguous predecessor blocks;
- the top-level anchor block is the immediate successor of the last history
  item;
- intermediate blocks carry their weighted PBFT commit signatures;
- transaction and receipt arrays are omitted when the next header has the same
  validator membership and weights; and
- when the next header changes, the predecessor carries the complete ordered
  transaction and receipt arrays, not only consensus-precompile calls.

Complete arrays prevent an evidence producer from hiding another membership
mutation in the same block. TrustDB reconstructs every transaction hash and
receipt hash, then rebuilds both BCOS binary Merkle roots. A transition receipt
must have execution status zero and the consensus precompile must return the
canonical ABI-encoded integer zero before its mutation is applied.

Supported PBFT mutations are:

- `addSealer(string,uint256)`
- `addObserver(string)`
- `remove(string)`
- `setWeight(string,uint256)`

RPBFT candidate/term-weight operations, working-sealer rotation, unknown
selectors, duplicate validators, zero weights, arithmetic overflow, malformed
ABI, unsupported transaction-data versions, cross-mode keys, and
non-canonical preimages fail closed. Transition-block transaction-data and
receipt version zero are supported because the pinned Go SDK RPC model does
not expose every version-one fee field needed to reconstruct that consensus
preimage.

## Explicit checkpoint advancement

Checkpoint advancement is a local administrative decision:

```bash
trustdb anchor fisco-bcos trust-config advance \
  --input /etc/trustdb/fisco-bcos-trust.cbor \
  --evidence anchor.sproof \
  --expect-current-digest 0xCURRENT_TRUST_CONFIG_DIGEST \
  --out /etc/trustdb/fisco-bcos-trust.cbor
```

`--out` must name the same canonical file as `--input`; staged forks are
rejected. The command acquires an exclusive adjacent lock, re-reads the current config,
compares the mandatory expected digest, verifies the complete `.sproof`
transition chain, requires a strictly higher target block, increments the
generation, records the previous digest, syncs the replacement file, performs
an atomic write-through replacement, persists the parent-directory entry where
the platform requires it, and prints old/new checkpoint identities for the
audit log.

A stale lock is not silently removed. An operator must investigate an
interrupted advancement before removing it, preventing automated rollback or
concurrent replacement from being mistaken for recovery.

## Limits and performance

- One proof carries at most 4,096 predecessor blocks and remains subject to the
  16 MiB anchor-proof limit.
- Complete transition contents across one proof carry at most 4,096 ordered
  transaction/receipt pairs; over-limit blocks or histories fail closed rather
  than being truncated.
- Unchanged blocks require only header and finality evidence.
- Complete transactions and receipts are fetched only for predecessor blocks
  whose next header changes membership or weight.
- Collection requires the configured endpoint read quorum to return
  byte-identical canonical evidence.
- Advancing the local checkpoint compacts future proof history without
  changing already exported evidence under its original local TrustConfig.

## Compatibility

This is a deliberate breaking upgrade. TrustDB does not read, migrate, or
silently reinterpret `trustdb.fisco-bcos-trust-config.v1` or
`trustdb.fisco-bcos-anchor-proof.v2`. Deployments must create a new v2 local
checkpoint and produce v3 evidence.
