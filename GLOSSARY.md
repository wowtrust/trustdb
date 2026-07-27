# TrustDB Glossary

This glossary covers the proof and storage vocabulary used in the root READMEs and current V2 format documents. These terms describe TrustDB evidence semantics only; they do not assert legal validity or bind a cryptographic key to a real-world identity by themselves.

## claim

A claim is the client-created statement that binds a content hash and metadata to a client signature before server acceptance. In current V2 evidence it appears as `SignedClaim`, and L1 is reached only when the content hash matches that signed claim and the client signature verifies against verifier-local trust material; see [Proof Levels](README.md#proof-levels) and [`.sproof v2` offline verification](formats/SPROOF_V2.md#offline-verification-sequence).

## accepted receipt

An accepted receipt is the server-signed `AcceptedReceipt` returned after the server validates a claim and appends the accepted record to the WAL boundary used by the configured fsync policy. It is the L2 artifact and is not the same as batch commit, Global Transparency Log append, or anchor publication; see [Proof Levels](README.md#proof-levels) and [Architecture](README.md#architecture).

## L1-L5

L1-L5 are TrustDB's recomputed proof levels: L1 verifies content hash and client signature; L2 adds a valid accepted receipt; L3 adds committed receipt and batch Merkle inclusion proof; L4 adds a valid batch-root-to-STH Global Transparency Log inclusion proof; L5 adds an STH/global-root external anchor result. The verifier derives the level from verified evidence instead of trusting a supplied label; see [Proof Levels](README.md#proof-levels) and [`.sproof v2` offline verification](formats/SPROOF_V2.md#offline-verification-sequence).

## batch root

A batch root is the Merkle root for one committed batch of accepted records, stored with its batch identity, tree size, close time, and `node_id`/`log_id` scope when present. It is the value carried from L3 into the Global Transparency Log for L4 evidence; see [Proof Levels](README.md#proof-levels) and [Architecture](README.md#architecture).

## Global Transparency Log

The Global Transparency Log is TrustDB's append-only log of committed batch roots for one logical `(node_id, log_id)` stream. It persists leaves, tree state, STHs, inclusion proofs, consistency proofs, and history tiles, but it is not a globally unique log across namespaces or independent deployments; see [Architecture](README.md#architecture) and [distributed/storage-compute notes](formats/DISTRIBUTED_ARCHITECTURE.md).

## STH

STH means Signed Tree Head: the server-signed root of the Global Transparency Log after a specific tree size for a specific `node_id` and `log_id`. L4 proves a batch root is included in a target STH, and L5 anchors the STH/global root rather than a per-batch root; see [`.sproof v2` global and anchor evidence](formats/SPROOF_V2.md#global-and-anchor-evidence).

## anchor

An anchor is a supported sink result that binds an exact STH/global root to sink-specific evidence, such as file, OpenTimestamps, FISCO BCOS, or a supervised external plugin. Only a genuinely external sink can add independent time semantics, and offline L5 still requires verifier-local trust material and exact recomputation; see [Proof Levels](README.md#proof-levels), [`.sproof v2` global and anchor evidence](formats/SPROOF_V2.md#global-and-anchor-evidence), and [L5 external anchor plugins](formats/ANCHOR_PLUGIN_V1.md).

## proofstore

A proofstore is the storage backend that persists proof bundles, batch roots, Global Transparency Log metadata, STH anchor results, scheduler state, indexes, and related proof data. Current backends include file, Pebble, and TiKV using proofstore storage schema v5, with TiKV namespaces scoped to one logical `(node_id, log_id)` stream; see [Architecture](README.md#architecture) and [distributed/storage-compute notes](formats/DISTRIBUTED_ARCHITECTURE.md).

## WAL

WAL means write-ahead log: the ingest durability boundary where accepted records are appended before later batch, Global Transparency Log, and anchor processing. `strict`, `group`, and `batch` fsync modes change when WAL data is flushed, while recovery accepts only V2 WAL/checkpoint data bound to the configured suite, NodeID, LogID, and storage namespace; see [Architecture](README.md#architecture).

## trust root

A trust root is verifier-local material used to decide which public keys, CA roots, registry signer, anchor policy, or provider checkpoints are trusted during verification. Evidence files, key registries, descriptors, backups, and certificate chains can carry public evidence, but they never authorize themselves as trust roots; see [`.sproof v2` purpose](formats/SPROOF_V2.md#purpose), [Key Registry V2](formats/KEY_REGISTRY_V2.md), and [Backup V5](formats/BACKUP_V5.md#security-boundary).

## .sproof

`.sproof` is the recommended single-file proof container for exchange and desktop verification. Current builds accept only suite-bound `.sproof v2`, a deterministic CBOR file that contains the L3 `ProofBundle` plus optional L4 `GlobalLogProof`, optional L5 `STHAnchorResult`, and bounded public identity/status evidence for offline recomputation; see [`.sproof v2`](formats/SPROOF_V2.md).
