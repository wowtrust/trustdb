# FISCO BCOS production qualification gates

This guide defines the reproducible evidence required before a FISCO BCOS
deployment can be described as a qualified TrustDB L5 anchor target. It applies
to the exact component pins in
[ADR-0012](ADR-0012-FISCO-BCOS-3X-COMPATIBILITY-BASELINE.md); results from a
different release, cryptographic mode, deployment architecture, operating
system, or CPU architecture are separate qualifications.

## What the automated gate proves

The Linux/amd64 CI gate creates a fresh four-validator Air network for each of
the `standard` and `guomi` modes. Each run performs all of the following:

1. verifies the SHA-256 and size of every pinned node, C SDK, compiler, and
   certificate-tool artifact;
2. creates independent certificates and a short-lived publisher key, compiles
   and deploys the production `TrustDBAnchorV1` contract, and verifies its
   runtime code hash;
3. submits real transactions through the native Go/C SDK path and checks the
   contract event, stored anchor record, transaction proof, receipt proof,
   containing block roots, and PBFT commit signatures;
4. stops one validator, proves that the remaining three continue making
   progress, restarts the validator, and requires it to catch up;
5. changes one validator's vote weight through the consensus precompile,
   publishes another transaction, and restores the original weight;
6. publishes a real signed TrustDB STH through the durable BCOS sink, preserving
   and replaying the exact append-only provider-state journal;
7. exports a complete `.sproof`, shuts down all four nodes, verifies that all
   RPC and P2P listeners are closed, and then verifies L5 inside a Linux network
   namespace with no network interfaces;
8. separately rejects changed content, receipt inclusion evidence, PBFT
   signatures, and exact anchor binding at the expected verification stage;
9. exercises logical backup, verification, restore, and immutable anchor-result
   comparison for `INTL_V1`. `CN_SM_V1` backup remains fail closed until the
   authenticated backup-v5 work tracked by #473 is available.

The gate never treats an SDK response, transaction inclusion, or a block
timestamp as sufficient L5 evidence. L5 is produced only after the ordinary
TrustDB proof, Global Log inclusion, BCOS receipt inclusion, PBFT finality, and
exact anchor binding all pass against verifier-local trust roots.

## Run it locally

Requirements are Linux/amd64, Go from `go.mod`, Python 3, `util-linux` with a
working `unshare --net`, and enough capacity for four BCOS nodes. The work
directory must not already exist.

```bash
sudo unshare --net -- true

scripts/fisco-bcos/smoke-air.sh \
  --mode standard \
  --qualification \
  --work-dir /tmp/trustdb-bcos-standard \
  --cache-dir /tmp/trustdb-bcos-cache

scripts/fisco-bcos/smoke-air.sh \
  --mode guomi \
  --qualification \
  --work-dir /tmp/trustdb-bcos-guomi \
  --cache-dir /tmp/trustdb-bcos-cache
```

The cache contains only hash-verified upstream release artifacts. Standard and
Guomi work directories, networks, certificates, publisher keys, and evidence
must remain independent. The runner removes the short-lived publisher key on
success, failure, signal, or timeout.

## Evidence and failure stages

The GitHub Actions job uploads a curated artifact set for 14 days. It excludes
node private keys, SDK private keys, publisher keys, and certificate directories.

| Evidence | Purpose |
| --- | --- |
| `artifact-verification.json` | Exact upstream filenames, sizes, and SHA-256 pins. |
| `client-evidence.json` | Contract deployment, transactions, node fault/recovery, validator-weight transition, proofs, and raw timings. |
| `consensus-preimage.json` | Recomputed receipt/block preimages and PBFT signature verification. |
| `qualification/live-qualification.json` | Durable TrustDB publication, provider/transport/storage gates, replay, and backup result. |
| `qualification/portable.sproof` | Complete portable L5 evidence container. |
| `qualification/trust-roots.json` | Verifier-local public trust configuration used by the gate; it is not adopted from the `.sproof`. |
| `qualification/offline-verification.json` | Disconnected L5 result and stage-specific tamper failures. |
| `qualification/proofstore.tdbackup` | Standard-mode logical backup when the active backup format supports the suite. |
| node and qualification logs | Bounded diagnostic output for failed infrastructure or semantic stages. |

Failures are attributable to distinct boundaries:

- `provider`: publisher key/provider creation or signing failed;
- `transport`: TLS/TLCP, certificate pinning, endpoint identity, or native SDK
  connection failed;
- `storage`: durable journal, proofstore, backup, or restore failed;
- `receipt_inclusion`: transaction or receipt Merkle evidence did not bind to
  the containing block;
- `pbft_finality`: validator membership, weight, quorum, commit signature, or
  authenticated transition evidence failed;
- `anchor_binding`: the contract event/record did not exactly bind the expected
  NodeID, LogID, TreeSize, root hash, and signed STH digest.

FISCO BCOS v3.16.3 uses ledger error code `3008` both when a transaction or
receipt row is not yet visible and when its underlying storage read fails.
TrustDB therefore treats this code only as a retryable, temporarily
unobservable lookup. It never accepts the transaction without subsequently
retrieving and verifying the complete immutable evidence.

## Architecture admission

| Target | Automated status | Required next evidence |
| --- | --- | --- |
| Air Linux/amd64 Standard | Four-node qualification in CI. | Required workflow result and retained artifact. |
| Air Linux/amd64 Guomi | Independent four-node qualification in CI. | Required workflow result and retained artifact. |
| Air Linux/arm64 | Exact Standard/Guomi artifacts verified in CI. | Native four-node runtime qualification on labelled arm64 hardware before admission. |
| macOS/arm64 | Development runtime smoke. | Not a Linux production qualification. |
| Windows/amd64 | Compiler, native SDK link, and Windows-safe tests. | No v3.16.3 Windows node exists, so no node-runtime claim. |
| Pro / Max | Not admitted for the pinned binary release. | Separately attested service artifacts or source build, then the manual procedure below. |

## Pro and Max production procedure

Air evidence cannot be copied to Pro or Max. When complete pinned service
artifacts become available, execute the following on dedicated infrastructure
and retain the output under an explicit gated-hardware label:

1. record the TrustDB commit, BCOS/BcosBuilder/Tars/TiKV commits, container or
   binary digests, host OS/kernel/CPU, topology, and sanitized configuration;
2. deploy at least four consensus members and redundant gateway/RPC services;
   for Max, also record executor placement, TiKV TLS identity, failover policy,
   and storage replication state;
3. compile and deploy `TrustDBAnchorV1` from the repository source and bind the
   configured address, runtime code hash, event signature, chain/group IDs,
   genesis hash, and validator checkpoint;
4. run the same Standard and Guomi semantic qualification cases as Air through
   every configured endpoint and enforce the configured read quorum;
5. inject one consensus-node loss, one gateway/RPC loss, one service restart,
   and, for Max, one executor and one TiKV failover; prove continued progress
   and complete catch-up after recovery;
6. exercise an unknown submission outcome and prove restart resumes the same
   durable transaction journal instead of signing an untracked replacement;
7. perform validator weight or membership transitions, export proof evidence
   spanning the transition, and verify it from the locally trusted checkpoint;
8. stop or firewall every TrustDB and BCOS endpoint before offline verification,
   run the verifier in a network namespace, and retain positive and tamper-case
   stage reports;
9. create, verify, restore, and compare a logical backup for every admitted
   TrustDB cryptographic suite; and
10. obtain review from the owners of the BCOS infrastructure, TrustDB evidence
    verifier, and deployment security boundary before changing the compatibility
    matrix.

Any missing artifact, stage report, trust pin, fault-recovery observation, or
offline negative case keeps that exact architecture fail closed.
