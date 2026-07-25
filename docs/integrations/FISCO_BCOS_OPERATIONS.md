# FISCO BCOS operations runbook

This runbook tells an operator how to deploy, govern, monitor, back up, and
recover a supported TrustDB FISCO BCOS anchor integration. It applies only to
the exact component baseline pinned by
[ADR-0012](ADR-0012-FISCO-BCOS-3X-COMPATIBILITY-BASELINE.md): FISCO BCOS
`v3.16.3` (commit `274f864e7725fef5b8ed4c6b7a3363ee5396f104`), Go SDK `v3.0.2`,
C SDK native `v3.6.0`, FISCO Solidity `v0.8.11`, and TASSL `V_1.4`. Any other
release, topology, operating system, CPU architecture, or cryptographic mode is
a separate qualification; see
[FISCO_BCOS_QUALIFICATION.md](FISCO_BCOS_QUALIFICATION.md) for the admission
gate this runbook depends on.

Normative semantics live in the protocol ADRs and are not repeated here:

- [ADR-0013](ADR-0013-FISCO-BCOS-ANCHOR-PROTOCOL.md) — `AnchorPayload v1`,
  `TrustConfig v2`, `AnchorProof v3`, explicit crypto modes;
- [ADR-0014](ADR-0014-FISCO-BCOS-ANCHOR-EVIDENCE-PERSISTENCE.md) — durable
  attempt journal and immutable evidence;
- [ADR-0015](ADR-0015-FISCO-BCOS-OFFLINE-RECEIPT-INCLUSION.md) — offline
  receipt inclusion;
- [ADR-0016](ADR-0016-FISCO-BCOS-STATIC-PBFT-FINALITY.md) — static-validator
  PBFT finality;
- [ADR-0017](ADR-0017-FISCO-BCOS-VALIDATOR-SET-TRANSITIONS.md) — authenticated
  validator-set transitions and checkpoint advancement.

> ## Claim boundaries — read before operating or reporting
>
> - **Never describe a FISCO BCOS block timestamp as a legally trusted
>   timestamp.** STH time, BCOS block time, and a trusted-timestamp authority
>   token are three different things and must be labeled separately in every
>   report, dashboard, and customer-facing statement.
> - **Never describe BCOS inclusion as automatic judicial recognition.** Hash
>   values, electronic signatures, trusted timestamps, and blockchain storage
>   are authenticity *review factors*, not automatic acceptance conclusions;
>   evidential weight still depends on the complete generation, collection,
>   storage, transmission, and trust material of the specific record.
> - **MLPS （网络安全等级保护） grading and commercial-cryptography application
>   security assessment （商用密码应用安全性评估， "密评") are separate formal
>   assessments of the deployed system, its cryptography application plan, and
>   its operating environment.** Supporting SM2/SM3/SM4, TLCP, or FISCO BCOS
>   demonstrates technical capability only. Product certification applicability
>   must be checked against the current certification catalogue for the exact
>   delivery form. See
>   [docs/compliance/CHINA_COMPLIANCE_SCOPE_AND_CONTROL_MATRIX.zh-CN.md](../compliance/CHINA_COMPLIANCE_SCOPE_AND_CONTROL_MATRIX.zh-CN.md)
>   and the directions tracked by issues [#483](https://github.com/wowtrust/trustdb/issues/483)/[#484](https://github.com/wowtrust/trustdb/issues/484) before making any external
>   compliance claim.
> - A passing smoke or qualification run is engineering evidence for the exact
>   tested row. It is not a product certification, a conformity test result,
>   or an approval of a particular deployment.

## 1. Supported topologies and admission status

FISCO BCOS documents three deployment architectures and two cryptographic
modes. TrustDB admits a topology only for the exact rows backed by committed
evidence:

| Topology | Standard mode | Guomi mode | Status |
| --- | --- | --- | --- |
| Air (all-in-one), Linux/amd64 | Admitted: four-node qualification in CI | Admitted: independent four-node qualification in CI | Production-deployable per this runbook |
| Air, Linux/arm64 | Artifact-verified only | Artifact-verified only | Fail closed until a native four-node runtime qualification on labelled arm64 hardware is committed |
| Air, Darwin/arm64 | Development runtime smoke | Development runtime smoke | Development only; not a Linux production qualification |
| Pro (separated gateway/RPC/node services) | Not admitted: the `v3.16.3` release lacks the `BcosRpcService`/`BcosGatewayService`/`BcosNodeService` archives | Same artifact gap | Fail closed; see §3.4 for the manual admission procedure once pinned service artifacts exist |
| Max (executor scaling, TiKV, Tars) | Not admitted: the release also lacks `BcosMaxNodeService`/`BcosExecutorService` | Same gap | Fail closed; same procedure as Pro |
| Container execution | Not admitted: no `v3.16.3` image digest exists | Same | Fail closed |

The machine-readable matrix and every artifact name, URL, byte size, and
SHA-256 pin is [`configs/compatibility/fisco-bcos-v3.16.3.json`](../../configs/compatibility/fisco-bcos-v3.16.3.json).
Standard and Guomi are separate rows in every dimension: independent compiler
artifacts, certificates, keys, networks, negotiated modes, and evidence. Never
copy evidence, caches of unverified bytes, certificates, publisher keys, or
trust roots across modes.

Check the current admission state of any row before planning a deployment:

```bash
python3 scripts/fisco-bcos/compatibility.py validate

python3 scripts/fisco-bcos/compatibility.py check \
  --deployment air --crypto standard --platform linux/amd64

python3 scripts/fisco-bcos/compatibility.py check \
  --deployment air --crypto guomi --platform linux/amd64
```

## 2. Deployment prerequisites

A supported production anchor publisher needs:

1. Linux/amd64 hosts for the BCOS nodes and the TrustDB server;
2. Go at the version pinned by `go.mod`, Python 3, and `util-linux` with a
   working `unshare --net` for offline verification;
3. a TrustDB binary built with `CGO_ENABLED=1`, the `fiscobcos_sdk` build tag,
   and the pinned C SDK `v3.6.0` native library available to the dynamic
   loader;
4. hash-verified upstream artifacts in a local cache — the cache must contain
   only bytes that passed `verify-artifacts`:

   ```bash
   python3 scripts/fisco-bcos/compatibility.py verify-artifacts \
     --platform linux/amd64 \
     --cache-dir /var/cache/trustdb/fisco-bcos
   ```

5. for Guomi, a CA and dual (signing + encryption) client certificate/key
   pairs issued under the deployment's own certificate process; and
6. a publisher account whose private key lives inside an HSM/SDF/PKCS#11
   provider (§5).

Build and check the anchor contract artifacts before any deployment:

```bash
python3 scripts/fisco-bcos/build_anchor_contract.py \
  --platform linux/amd64 \
  --cache-dir /var/cache/trustdb/fisco-bcos \
  --check
```

This verifies the pinned compiler archives, compiles standard and Guomi
artifacts with identical settings, and compares them against
`contracts/fisco-bcos/artifacts/manifest.json`. Use `--write` only when
intentionally creating a new contract version.

## 3. Deploying a supported topology

### 3.1 Air — reproduce the qualification locally

Before trusting any new environment, reproduce the full four-node
qualification on it. The work directory must not already exist; standard and
Guomi runs are separate, sequential invocations:

```bash
sudo unshare --net -- true

scripts/fisco-bcos/smoke-air.sh \
  --mode standard \
  --qualification \
  --work-dir /tmp/trustdb-bcos-standard \
  --cache-dir /var/cache/trustdb/fisco-bcos

scripts/fisco-bcos/smoke-air.sh \
  --mode guomi \
  --qualification \
  --work-dir /tmp/trustdb-bcos-guomi \
  --cache-dir /var/cache/trustdb/fisco-bcos
```

One `--qualification` run performs, in order: artifact SHA-256/size
verification; independent certificate and short-lived publisher-key creation;
production `TrustDBAnchorV1` compilation, deployment, and runtime-code-hash
verification; real transactions through the native Go/C SDK path with receipt
inclusion, block-root, and PBFT commit-signature checks; a one-validator stop,
continued three-node progress, restart, and catch-up; a consensus-precompile
vote-weight transition and restore; a durable TrustDB STH publication with
provider-state journal replay; `.sproof` export; full node shutdown with
listener-release verification; disconnected L5 verification inside a Linux
network namespace; stage-specific tamper rejections; and (standard mode)
`INTL_V1` logical backup, verification, restore, and immutable anchor-result
comparison.

Bounded performance comparison pairs are supported:

```bash
scripts/fisco-bcos/smoke-air.sh \
  --mode standard --work-dir /tmp/fisco-standard-perf \
  --performance-warmup 5 --performance-samples 20
```

Keep warmup (3–20) and sample (20–100) counts identical between a standard and
Guomi pair on the same otherwise-idle host. `--raw-evm-fixture` is a
compiler-bypassing diagnostic whose evidence can never admit a row.

### 3.2 Air qualification artifacts

A qualification run leaves the following under the work directory (the CI gate
retains a curated subset for 14 days; node keys, SDK keys, publisher keys, and
certificate directories are never uploaded):

| Artifact | Purpose |
| --- | --- |
| `artifact-verification.json` | Exact upstream filenames, sizes, and SHA-256 pins. |
| `client-evidence.json` | Deployment, transactions, fault/recovery, weight transition, proofs, raw timings. |
| `consensus-preimage.json` | Recomputed receipt/block consensus preimages and PBFT signature verification. |
| `qualification/live-qualification.json` | Durable publication, provider/transport/storage gates, replay, backup result. |
| `qualification/portable.sproof` | Complete portable L5 evidence container (`.sproof v2`). |
| `qualification/content.bin` | Original content bound by the proof. |
| `qualification/trust-roots.json` | Verifier-local trust configuration used by the gate; never adopted from the `.sproof`. |
| `qualification/offline-verification.json` | Disconnected L5 result and stage-specific tamper failures. |
| `qualification/proofstore.tdbackup` | `INTL_V1` logical backup when the active backup format supports the suite. |
| `evidence-standard.json` / `evidence-guomi.json` | Curated per-mode runtime evidence summary. |

### 3.3 Production Air deployment

1. Provision at least four consensus nodes on independent failure domains,
   using the pinned `v3.16.3` node binary and the tag-pinned `build_chain.sh`
   flow; Guomi networks additionally require the `-s` Guomi build mode.
2. Keep the P2P and RPC four-port ranges outside the Linux ephemeral port
   range and non-overlapping with each other (the smoke runner rejects such
   ranges before building anything; production layouts must follow the same
   rule).
3. Record every node identity, certificate chain, and endpoint in the
   deployment evidence repository before configuring TrustDB.
4. Deploy the contract (§4) and build the canonical TrustConfig (§7).
5. Start TrustDB with the native sink:

   ```bash
   trustdb serve \
     --anchor-sink=fisco-bcos \
     --anchor-fisco-bcos-trust-config=/etc/trustdb/fisco/trust-config.cbor
   ```

   The sink requires at least two configured endpoints and `read_quorum >= 2`.
   Startup fails closed on any certificate, chain-identity, contract-code, or
   crypto-mode mismatch (§7.4).

### 3.4 Pro and Max manual admission

Air evidence cannot be copied to Pro or Max. These topologies stay fail closed
until complete pinned service artifacts (or a separately attested source
build) exist and the full ten-step manual procedure in
[FISCO_BCOS_QUALIFICATION.md](FISCO_BCOS_QUALIFICATION.md#pro-and-max-production-procedure)
has been executed on dedicated infrastructure: recorded commits and digests,
at least four consensus members plus redundant gateway/RPC, contract
deployment and pinning, the same standard and Guomi semantic cases through
every endpoint with enforced read quorum, injected consensus/gateway/executor/
TiKV faults with proven catch-up, unknown-outcome journal recovery, validator
transitions with exported evidence, disconnected offline verification, logical
backup/restore for every admitted suite, and joint review by the BCOS
infrastructure, evidence-verifier, and security-boundary owners. For Max,
additionally record executor placement, TiKV TLS identity, failover policy,
and storage replication state.

## 4. Contract deployment and role governance

### 4.1 Deployment procedure

`TrustDBAnchorV1` (`contracts/fisco-bcos/TrustDBAnchorV1.sol`) is the immutable
publication boundary. It stores no business payload, personal information,
proof, private key, or mutable implementation address; there is no proxy,
implementation slot, delegate call, self-destruct path, or administrator
replacement.

1. Verify artifacts with `build_anchor_contract.py --check` (§2).
2. Deploy from `contracts/fisco-bcos/artifacts/standard` or
   `contracts/fisco-bcos/artifacts/guomi` — never mix an artifact with the
   other mode's network. The constructor fixes one immutable administrator and
   at least one initial publisher.
3. Fetch the deployed runtime bytecode and require its mode-native digest
   (Keccak-256 standard, SM3 Guomi) to equal
   `artifacts/manifest.json` `modes.<mode>.runtime_code_hash`.
4. Record the deployment by copying
   `contracts/fisco-bcos/deployments/deployment-record.template.json` into the
   controlled deployment evidence repository, filling every field from
   finalized chain data (chain/group IDs, genesis hash, checkpoint block
   number and hash, contract address, deployment transaction hash and block
   number, runtime code hash and algorithm, artifact manifest SHA-256,
   administrator, initial publishers, RFC 3339 timestamp, change-ticket or
   operator ID), and signing it under the operator's change-control process.
   The record must never contain key material, and production addresses,
   account identifiers, or certificate material must not be committed to the
   TrustDB repository.

### 4.2 Role model

The machine-readable role contract is
[`contracts/fisco-bcos/roles.v1.json`](../../contracts/fisco-bcos/roles.v1.json):

| Role | Cardinality | Mutable | Permissions | Constraints |
| --- | --- | --- | --- | --- |
| `administrator` | exactly 1 | no | `authorize-publisher`, `revoke-publisher` | `cannot-revoke-last-publisher`; `cannot-publish-unless-separately-authorized` |
| `publisher` | at least 1 | by administrator | `publish-anchor` | `authorization-checked-on-every-publication` |

Operational rules:

- Keep the administrator key offline, dedicated, and separate from the
  publisher. Losing the administrator key permanently freezes role governance;
  recovery requires deploying and locally pinning a new contract (§12.3).
- Back the publisher with an HSM/KMS account (§5). Every role change is
  emitted as a contract event; monitor for unexpected authorization changes.
- Revoking the last publisher is rejected on-chain, but always authorize the
  replacement publisher *before* revoking the old one (§12.3).
- Duplicate publication of the exact same payload returns `false` without a
  second event and stays safe for retry; reusing an AnchorID with changed
  fields, regressing a stream tree size, or publishing a different root at the
  current tree size reverts. Duplicate equality does not cover the submitting
  account, so a replacement publisher can retry a payload and the stored
  record keeps its original publisher.

## 5. Publisher account and key custody

### 5.1 Supported custody boundaries

Production publisher keys must never exist as files on the TrustDB host. The
`account_provider` section of the TrustConfig references one signer provider;
the plugin must advertise the exact profile `FISCO_BCOS_STANDARD_V1` or
`FISCO_BCOS_GUOMI_V1` (defined in `sdk/signerplugin/types.go`):

| Provider | Boundary | Reference |
| --- | --- | --- |
| `sdf` | `trustdb-signer-sdf` sidecar → deployment-owned vendor adapter → SDF device with non-exportable keys. Owner-only adapter config (≤64 KiB) and credential (≤4 KiB) files; no inline credentials anywhere. Example: `{"device_ref":"device-a","key_index":7,"credential_ref":""}`. | [SDF_SIGNER.md](SDF_SIGNER.md) |
| `pkcs11` | `trustdb-signer-pkcs11` sidecar → vendor PKCS#11 module → non-exportable key. Owner-only PIN file is the only PIN source. | [PKCS11_SIGNER.md](PKCS11_SIGNER.md) |
| `remote` | Supervised remote signer plugin. | signer-plugin configuration |

Common rules from both signer integrations: TrustDB core never receives a
private key and never falls back to a software signer; a failed or timed-out
`Sign` is never replayed automatically; device/token identity and each key's
first accepted public key are pinned and drift fails closed; rotate by
provisioning a new key/index/URI, publishing a new descriptor, and restarting
the resolver — never reuse an index or URI for a different key; offline proof
verification never loads the sidecar or contacts the device.

### 5.2 Development-key anti-pattern and its containment

The qualification gate deliberately demonstrates the *development* pattern so
its containment is auditable: `scripts/fisco-bcos/smoke-air.sh` generates a
short-lived publisher scalar with Python `secrets`, writes it to
`<work-dir>/publisher.key` with mode `0600`, and deletes it on success,
failure, signal, or timeout. This is acceptable **only** because the network
is ephemeral, the key never leaves the work directory, and cleanup is
trap-guaranteed. Do not copy this pattern to any persistent network: a
file-backed `software` account provider on a production chain is a forbidden
shortcut (§11).

## 6. Certificate management and rotation

### 6.1 What the TrustConfig pins

The `certificates` object of the TrustConfig (schema in
`internal/anchor/fiscobcos/trust.go`) carries references and public
fingerprints only — never private key bytes:

| Key | Meaning |
| --- | --- |
| `trusted_ca_references` | Local CA certificate file paths. |
| `trusted_ca_certificate_hashes_hex` | Mode-protocol-hash digests (SHA-256 standard, SM3 Guomi) of the exact trusted CA file bytes. |
| `pinned_peer_certificate_hashes_hex` | Optional additional peer certificate pins. |
| `client_signing_certificate_ref` / `client_signing_key_ref` | Client signing identity. |
| `client_encryption_certificate_ref` / `client_encryption_key_ref` | Guomi-only client encryption identity; must be distinct from the signing pair. Standard mode must not set these. |

Compute a Guomi CA pin as:

```bash
openssl dgst -sm3 /etc/trustdb/fisco/sm_ca.crt
```

Before connecting, the native driver
(`internal/anchor/fiscobcos/standardsdk/factory_native.go`) and
`internal/tlcpprofile/certificates.go` validate the Guomi CA, both certificate
chains against it, current validity, signing/encryption key usages,
private-key-to-certificate matches, and distinct dual-certificate identities.
The driver rejects standard TLS endpoints, secp256k1 validators, standard
contract artifacts, and standard-chain transaction material under a Guomi
configuration (and vice versa).

### 6.2 Client certificate rotation (BCOS SDK side)

1. Issue the new signing (and, for Guomi, encryption) certificate/key pair
   under the same CA.
2. Place the new files at the configured reference paths (or update the JSON
   manifest and re-run `trust-config create` to produce a new canonical
   config — note this changes the trust-config digest, §7.3).
3. Restart TrustDB; startup revalidates every chain, usage, and key match and
   fails closed on any defect.
4. If the **CA itself** rotates, its hash changes, so a new TrustConfig must be
   created and every verifier's local configuration updated through the
   operator trust process. Checkpoint advancement (`trust-config advance`)
   covers only the validator checkpoint, not certificate roots.

### 6.3 TrustDB-facing transports

- Standard TLS/mTLS for TrustDB's own HTTP/gRPC listeners follows
  [TLS_MTLS.md](TLS_MTLS.md): the certificate/key pair, CA pool, CA pins, and
  revocation list load as one immutable snapshot; an invalid, mismatched,
  not-yet-valid, or expired replacement fails reload and the last known-good
  snapshot stays active.
- Guomi client-facing exposure uses the pinned Tengine/Tongsuo TLCP gateway
  ([TLCP_GATEWAY.md](TLCP_GATEWAY.md)). Its signing certificate/key,
  encryption certificate/key, CA files, readiness identities, identity
  manifest, and CRLs rotate as one immutable generation: enroll distinct
  non-exportable keys, stage a sibling generation directory, validate the
  profile with
  `go run ./cmd/trustdb-tlcp-profile validate --profile <profile.json>`, run a
  candidate gateway on canary ports through both credentialed readiness
  probes, atomically switch the `active` symlink via `rename(2)`, run
  `tlcp-gateway-prepare-runtime reload`, `SIGHUP` the Tengine master, repeat
  both live probes, and retain the previous generation for bounded rollback.
  Never replace individual files in the active directory, and never delete the
  previous generation before the rollback window and active-connection
  lifetime have elapsed.

## 7. Trust configuration and checkpoint governance

### 7.1 Genesis versus checkpoint semantics

The TrustConfig binds two different chain identities:

- `genesis_hash_hex` pins **chain identity only** — which chain this is. It
  carries no finality trust: the genesis block has no PBFT commit signatures.
- `trusted_checkpoint` (`block_number` + `block_hash_hex`) pins the **finality
  trust root**: the exact ordered validator set and vote weights that the
  verifier trusts from that height forward. The checkpoint must be a
  post-genesis block whose validator set the operator has independently
  verified; the qualification gate rejects a block-number-0 checkpoint.

For a target block later than the checkpoint, no header ancestry path is
needed: the locally pinned quorum directly signs the target header hash. A
target earlier than the checkpoint fails; a target exactly at checkpoint
height must equal the pinned hash. Updating the checkpoint is always a local
trust-root operation — it never follows an online node's current sealer list
automatically (ADR-0016).

### 7.2 Creating the canonical config

Start from
[`configs/fisco-bcos-guomi-trust-config.example.json`](../../configs/fisco-bcos-guomi-trust-config.example.json)
(structurally valid, but its chain, checkpoint, contract, CA hash, certificate
paths, and account reference are **not** production trust roots) and replace
every value with data collected from at least two mutually trusted endpoints.
The full JSON key set is: `crypto_mode`, `chain_id`, `group_id`,
`genesis_hash_hex`, `trusted_checkpoint.{block_number, block_hash_hex}`,
`contract.{address_hex, code_hash_hex, protocol_version, event_signature}`,
`endpoints`, `read_quorum`, `validator_transition_policy`,
`account_provider.{provider, key_id, key_reference}`, `certificates.*` (§6.1),
and `validators[].{node_id, public_key_hex, vote_weight}`.

- Endpoint schemes must match the mode: `tls://` standard, `gm-tls://` Guomi.
- Every validator `public_key_hex` is the canonical 65-byte uncompressed key
  (`0x04 || X || Y`); `node_id` must equal `0x` plus its 64-byte body.
- `contract.protocol_version` must be exactly `trustdb-anchor-v1` and
  `contract.event_signature` exactly
  `AnchorPublished(bytes32,bytes32,uint64,bytes32,bytes32,address,uint16)`.
- Set `validator_transition_policy` to `static-validator-set-v1` for a
  deliberately static committee (ADR-0016) or
  `authenticated-validator-transitions-v1` to admit offline-authenticated
  membership/weight changes (ADR-0017). The choice is local policy; evidence
  cannot override it.

Create and inspect the canonical CBOR file:

```bash
trustdb anchor fisco-bcos trust-config create \
  --input /etc/trustdb/fisco/trust-config.guomi.json \
  --out /etc/trustdb/fisco/trust-config.guomi.cbor

trustdb anchor fisco-bcos trust-config inspect \
  --input /etc/trustdb/fisco/trust-config.guomi.cbor
```

`create` derives every algorithm, encoding, transport, and (for Guomi) the
fixed SM2 user ID `1234567812345678` from `crypto_mode`; unknown JSON fields,
malformed hex, invalid curve points, node-ID/public-key mismatch, wrong
endpoint schemes, and mixed standard/Guomi values fail before anything is
written. The output is atomic with mode `0600`. `inspect` prints the derived
trust identities: `trust_config_digest`, `chain_context_id`, checkpoint
(including `generation` and `previous_config_digest`), endpoints, quorum, and
validator set. Record the digest and chain-context ID in the deployment
record. Deterministic golden vectors for both modes are in
[`test/vectors/fisco-bcos-trust-config-v2.json`](../../test/vectors/fisco-bcos-trust-config-v2.json).

There is deliberately no migration from `trustdb.fisco-bcos-trust-config.v1`
or `trustdb.fisco-bcos-anchor-proof.v2`; deployments must create a new v2
checkpoint and produce v3 evidence (ADR-0017).

### 7.3 Checkpoint advancement

After an exported `.sproof` has verified a strictly newer finalized block,
advance the local checkpoint in place:

```bash
trustdb anchor fisco-bcos trust-config advance \
  --input /etc/trustdb/fisco/trust-config.guomi.cbor \
  --evidence /var/lib/trustdb/evidence/latest-anchor.sproof \
  --expect-current-digest 0xCURRENT_TRUST_CONFIG_DIGEST \
  --out /etc/trustdb/fisco/trust-config.guomi.cbor
```

The command requires `--out` to name the same canonical file as `--input`
(staged forks are rejected), takes an exclusive `.advance.lock`, re-reads and
digests the current config, requires the mandatory `--expect-current-digest`
to match (rollback/concurrency protection), verifies the complete offline
transition chain, requires a strictly higher target block, increments
`checkpoint_generation`, records `previous_config_digest`, and atomically
replaces the file. Retain the JSON report — old/new config digests and both
checkpoint identities — in the operator audit log. **Never delete a stale
`.advance.lock` until the interrupted operation has been investigated**; an
unexamined removal can mask a rollback or concurrent replacement.

### 7.4 What the publisher checks at startup and probe time

The sink (`internal/anchor/fiscobcos_sink.go`) requires at least two
endpoints, `read_quorum >= 2`, one driver per configured endpoint, and no
endpoint outside the TrustConfig. Each probe compares chain ID, group ID,
genesis hash, checkpoint hash, negotiated crypto mode, and deployed contract
runtime-code hash against the local config. Mismatches are permanent failures
(`ErrWrongNetwork`, `ErrContractMismatch`, `ErrUnsupportedSDK`); an endpoint
more than two blocks behind the conservative quorum height is marked stale and
excluded from routing.

## 8. Backup and restore

### 8.1 What a backup contains

`.tdbackup` (`trustdb.backup.v4`, `internal/backup`) is a **logical**,
backend-independent proofstore archive: deterministic CBOR objects in a tar
stream (optional gzip), so file and Pebble stores can restore each other's
data. The manifest records Global Log state presence and counts manifests,
bundles, roots, Global Log leaves/nodes/tiles/outboxes, STHs, anchor results,
and anchor schedules, and every
entry carries its ordinal, type, size, and SHA-256.

A backup does **not** contain private keys, signer descriptors, credentials,
device material, or the SDF recovery bundle
(`trustdb.sdf-recovery-bundle.v1`). Never claim that a `.tdbackup` alone
recovers a signer deployment; provider recovery follows
[SDF_SIGNER.md](SDF_SIGNER.md#provider-recovery-artifact). Backup v4 is
currently writable for `INTL_V1`; `CN_SM_V1` backup remains fail closed until
the authenticated, encrypted backup-v5 work tracked by issue [#473](https://github.com/wowtrust/trustdb/issues/473) lands.
Logical backup/restore is part of the standard-mode qualification gate for
exactly this reason.

### 8.2 Routine operations

```bash
# Create (proofstore flags: --metastore file|pebble, --metastore-path or
# --proof-dir; --crypto-suite is required; server.id and
# global_log.log_id must be configured)
trustdb backup create \
  --out /var/backups/trustdb/proofstore-$(date -u +%Y%m%dT%H%M%SZ).tdbackup \
  --compression gzip \
  --metastore file \
  --proof-dir /var/lib/trustdb/proofs \
  --crypto-suite INTL_V1

# Verify readability and internal typing
trustdb backup verify \
  --file /var/backups/trustdb/proofstore-20260101T000000Z.tdbackup

# Restore (resumes through a checkpoint file, default
# <file>.restore-checkpoint.json)
trustdb backup restore \
  --file /var/backups/trustdb/proofstore-20260101T000000Z.tdbackup \
  --metastore file \
  --proof-dir /var/lib/trustdb/proofs-restored \
  --crypto-suite INTL_V1 \
  --resume
```

Rules:

- Verify every archive immediately after creation and again before any
  restore. Retain the JSON create/verify/restore reports in the audit log.
- After a restore, re-verify a sample of exported `.sproof` files offline
  (§10) and compare immutable anchor results against pre-backup records, as
  the qualification gate does.
- Preserve restore checkpoint files from interrupted restores until the
  resumed restore completes; do not point two concurrent restores at the same
  checkpoint path.
- Schedule backups so that the retained chain of archives covers the slowest
  expected verifier's checkpoint-advancement cadence (§7.3).

## 9. Monitoring and incident response

### 9.1 Metrics

The sink exports bounded-label Prometheus metrics (endpoint identities are
exposed only as configuration indexes, never URLs):

| Metric | Labels | Meaning |
| --- | --- | --- |
| `trustdb_anchor_provider_quorum_healthy` | `sink` | Latest probe found enough identity-matched, non-stale endpoints. |
| `trustdb_anchor_provider_endpoint_healthy` | `sink`, `endpoint_index` | Endpoint passed the latest identity and stale-height probe. |
| `trustdb_anchor_provider_endpoint_stale` | `sink`, `endpoint_index` | Endpoint lagged the quorum height beyond the bounded allowance (2 blocks). |
| `trustdb_anchor_provider_endpoint_height` | `sink`, `endpoint_index` | Latest observed endpoint block height. |
| `trustdb_anchor_provider_quorum_failures_total` | `sink`, `operation`, `reason` | Quorum failures; operations are `probe`, `anchor`, `receipt`, `block`, `validator_history`. |
| `trustdb_anchor_provider_retry_events_total` | `sink`, `reason` | Bounded retry decisions: `exact_transaction`, `block_limit_refresh`, `duplicate_lookup`. |
| `trustdb_anchor_published_total` | `sink` | Anchor publish successes. |

### 9.2 Quorum failure classification

| `reason` | Class | Meaning | Response |
| --- | --- | --- | --- |
| `insufficient` | transient/ambiguous | Fewer than `read_quorum` healthy, identity-matched, non-stale endpoints answered, or an exact positive anchor observation could not be corroborated. Publication holds; the durable journal is retained. | Investigate endpoint availability and clock/height lag. Safe minority loss (§12.2) self-heals. |
| `disagreement` | permanent | Endpoints returned conflicting chain identities, contract code, or anchor records for the same query. | **Treat as a security event.** Stop publication, capture the conflicting responses, and do not resume until the cause (misconfiguration, chain split, or hostile endpoint) is identified. |

Routing is deterministic: submissions and exact-byte rebroadcasts use the
lexicographically first healthy configured endpoint, and block-limit refresh
is authorized only by the conservative quorum height (the lowest height among
the highest `read_quorum` identity-matched observations).

### 9.3 Durable publication failure stages

A durable BCOS publication separates failure attribution into distinct stages
(the qualification gate exercises each one):

| Stage | Covers |
| --- | --- |
| `provider` | Publisher key/provider creation or signing. |
| `transport` | TLS/TLCP, certificate pinning, endpoint identity, native SDK connection. |
| `storage` | Durable journal, proofstore, backup, restore. |
| `receipt_inclusion` | Transaction/receipt Merkle evidence did not bind to the containing block. |
| `pbft_finality` | Validator membership, weight, quorum, commit signature, or authenticated transition evidence. |
| `anchor_binding` | Contract event/record did not exactly bind NodeID, LogID, TreeSize, root hash, and Signed STH digest. |

Ledger error code `3008` (`GetStorageError`) means both "row not yet visible"
and "storage read failed" in `v3.16.3`; TrustDB treats it only as a retryable,
temporarily unobservable lookup and never accepts the transaction without the
complete immutable evidence.

The attempt journal (`trustdb.fisco-bcos-attempt-journal.v1`, ADR-0014) makes
crash recovery deterministic: a prepared transaction is always treated as
possibly submitted; recovery recomputes the canonical payload, queries every
journaled hash and the anchor ID across the read quorum, completes from an
exact receipt if found, retries only the exact signed bytes while admissible,
appends a newly signed attempt only on deterministic block-limit rejection or
proven absence, and fails closed — retaining the journal — on any disagreement
or unbindable observation. A rising
`trustdb_anchor_provider_retry_events_total{reason="duplicate_lookup"}` rate
indicates repeated recovery from unknown submission outcomes and warrants
endpoint investigation.

## 10. Offline trust roots and evidence verification

### 10.1 The sidecar principle

A `.sproof` ([formats/SPROOF_V2.md](../../formats/SPROOF_V2.md), schema
`trustdb.sproof.v2`, deterministic CBOR, 24 MiB limit) is evidence, **not a
trust store**. Validator sets, checkpoints, CA roots, public keys, and
certificate chains carried inside it never authorize themselves. The verifier
supplies every trust root locally:

- client/server public verifier descriptors (plus repeatable historical server
  keys for rotations), optional CA roots, and the registry public key; and
- the canonical FISCO BCOS TrustConfig (§7).

The qualification gate's `qualification/trust-roots.json` (schema
`trustdb.fisco-bcos-qualification-trust-roots.v1`,
`scripts/fisco-bcos/qualificationformat`) exists precisely to keep this
boundary explicit: it carries `crypto_suite`, `client_public_keys`,
`server_public_keys`, the local `fisco_bcos` TrustConfig, and
`expected_record_id` as a verifier-local sidecar. **Never adopt trust roots
from the evidence file being verified.**

### 10.2 Verifying exported evidence

Export through the SDK (`Client.ExportSingleProof` /
`Client.WriteSingleProofFile`) or take the gate's
`qualification/portable.sproof`. Verify with local trust only:

```bash
trustdb verify \
  --file ./content.bin \
  --sproof ./portable.sproof \
  --client-public-key ./client-public.cbor \
  --server-public-key ./server-public.cbor \
  --fisco-bcos-trust-config /etc/trustdb/fisco/trust-config.cbor
```

Useful additional flags: `--additional-server-public-key` (repeatable,
historical server keys), `--client-ca-certificate` / `--server-ca-certificate`
(repeatable roots), `--registry-public-key`, and `--skip-anchor` (marks
`anchor` and the three BCOS stages `skipped` and caps the result at L4).

The offline result reports ordered stages: `sproof_container`,
`identity_evidence`, `proof_bundle`, `content`, `client_claim`,
`bundle_bindings`, `accepted_receipt`, `committed_receipt`, `batch_merkle`,
`global_log`, `anchor`, then the three provider stages
`bcos_receipt_inclusion`, `bcos_pbft_finality`,
`bcos_exact_anchor_binding`. L5 is derived only when every applicable stage
passes; a receipt-inclusion failure leaves finality and binding `not_run`, and
a finality failure leaves binding `not_run`. The verifier performs no network,
DNS, CA, provider, HSM, or blockchain request — the result reports
`external_network_access=false` and `external_provider_access=false`. Use
`result.Valid` and the recomputed proof level; the descriptive level embedded
in the immutable file is not a locally verified finality decision. SDK callers
use `sdk.VerifySingleProofOffline` with `sdk.OfflineTrust{Proof, FISCOBCOS}`
and the stable stage names `sdk.OfflineStageBCOSReceiptInclusion`,
`sdk.OfflineStageBCOSPBFTFinality`, `sdk.OfflineStageBCOSAnchorBinding`.

### 10.3 Reproducing the disconnected gate

The gate binary verifies a complete L5 case plus four tamper rejections
(content, receipt inclusion, PBFT finality, exact binding), each at its
expected stage, inside a network namespace with no interfaces:

```bash
go build -o offline-qualification ./scripts/fisco-bcos/offline-qualification

sudo env TRUSTDB_NETWORK_DISABLED=1 unshare --net -- \
  ./offline-qualification \
  --proof qualification/portable.sproof \
  --content qualification/content.bin \
  --trust-roots qualification/trust-roots.json \
  --output qualification/offline-verification.json
```

For low-level consensus evidence review of a live run,
`go run ./scripts/fisco-bcos/evidence-check --input <client-evidence.json>
--cert-dir <sdk-cert-dir>` recomputes the receipt and block consensus
preimages and verifies the PBFT commit signatures.

### 10.4 Static and dynamic validator support

Under `static-validator-set-v1` (ADR-0016), the target header must match the
complete local ordered membership and weights exactly; a changed committee
fails closed. Under `authenticated-validator-transitions-v1` (ADR-0017), the
evidence carries a contiguous offline chain from the local checkpoint to the
anchored block: every post-checkpoint block is the exact child of its
predecessor and finalized by the committee derived for its height, and
successful calls to consensus precompile
`0x0000000000000000000000000000000000001003` (`addSealer`, `addObserver`,
`remove`, `setWeight`) are applied in transaction-index order with complete
transition-block transaction/receipt arrays. Bounds: at most 4,096 predecessor
blocks and 4,096 ordered transaction/receipt pairs per proof, within the
16 MiB anchor-proof limit. Removing history from an evidence file cannot fall
back to static verification. The PBFT weight rule is pinned to the `v3.16.3`
formula `totalWeight - floor((totalWeight - 1) / 3)` (three of four
unit-weight validators); weights are never inferred from evidence.

## 11. Forbidden shortcuts

Every item below has caused, or would cause, a fail-closed gate. Do not:

1. **Skip PBFT finality verification.** An SDK response, transaction
   inclusion, receipt, or block timestamp is never sufficient L5 evidence; all
   three BCOS offline stages plus exact anchor binding must pass against
   verifier-local trust roots.
2. **Adopt trust roots from evidence.** Validators, checkpoints, CA roots,
   and keys travel only through the operator trust process and local config.
3. **Treat a single-node or developer chain as production-compatible
   evidence.** Admission requires the four-node qualification row for the
   exact topology/mode/platform.
4. **Copy evidence across boundaries.** Mode, topology, OS, CPU, or release
   changes each require their own qualification; `--raw-evm-fixture` output
   can never admit a row.
5. **Run a production publisher from a file-backed `software` key.** Use the
   HSM/SDF/PKCS#11 custody boundary (§5).
6. **Re-sign a replacement transaction after an unknown submission
   outcome.** Recovery resumes the durable journal's exact signed bytes;
   silent re-signing is forbidden (ADR-0014).
7. **Auto-follow an online sealer list or update a checkpoint without the
   `trust-config advance` ceremony**, and never delete an `.advance.lock`
   without investigation.
8. **Mix modes.** Standard artifacts/keys/endpoints on a Guomi chain (or the
   reverse) are compatibility failures, not misconfigurations to work around.
9. **Accept ledger code 3008 as absence** or infer validator weights from
   evidence.
10. **Describe block time as legal time or BCOS inclusion as judicial
    recognition**, and never claim MLPS grading, 密评， or product
    certification from engineering evidence (see the banner at the top).
11. **Log secrets or trust internals**: private keys, PINs, credentials,
    adapter configs, device references, key indexes, or raw provider error
    strings must never reach application logs or metrics labels.
12. **Claim backup coverage for `CN_SM_V1`** until the authenticated backup-v5
    integration ([#473](https://github.com/wowtrust/trustdb/issues/473)) is admitted.

## 12. Disaster recovery drills

Run each drill at least once before production acceptance and on a scheduled
cadence afterwards; retain the drill outputs as deployment evidence.

### 12.1 Total chain outage

1. Detection: `trustdb_anchor_provider_quorum_healthy == 0` with
   `quorum_failures_total{operation="probe", reason="insufficient"}`
   increasing.
2. TrustDB behavior: publication holds; the durable journal retains every
   in-flight attempt; no replacement transaction is signed. Confirm that
   `retry_events_total` grows only through bounded reasons.
3. Recovery: restore at least `read_quorum` healthy, identity-matched
   endpoints on the **same** chain (genesis hash and checkpoint must match the
   pinned TrustConfig). The scheduler resumes the journaled attempts, queries
   each hash across the quorum, and either completes from the exact receipt or
   rebroadcasts the exact bytes.
4. Verification: export the affected records' `.sproof` files and verify them
   offline (§10.2); confirm `trustdb_anchor_published_total` resumes.
5. If the chain cannot be restored to the same identity, do **not** point the
   existing TrustConfig at a new chain; that is a new deployment (§4, §7) and
   previously exported evidence still verifies under its original local
   config.

### 12.2 Single endpoint loss (quorum degradation)

1. Expected behavior: with three or more endpoints and `read_quorum=2`, one
   loss flips `endpoint_healthy{endpoint_index=N}` to 0 but keeps
   `quorum_healthy` at 1 (the probe reports `degraded`). Submission routing
   deterministically uses the lexicographically first remaining healthy
   endpoint.
2. An endpoint that is reachable but more than two blocks behind the quorum
   height is reported through `endpoint_stale` and excluded from routing.
3. Drill: stop one BCOS node (the qualification gate stops node 3 of 4),
   confirm continued publication progress, restart it, and require it to
   rejoin the consensus group and catch up before closing the drill.
4. Escalate immediately if `reason="disagreement"` appears at any point —
   degraded availability is routine; contradictory identity is not (§9.2).

### 12.3 Contract role rotation (publisher/administrator)

1. Provision the replacement publisher account inside the HSM/KMS boundary
   (§5) and record its address in the change ticket.
2. From the offline administrator key, submit `authorize-publisher` for the
   new account; confirm the role-change event on-chain.
3. Update `account_provider.key_reference` in the JSON manifest, re-run
   `trust-config create`, record the new digest, and restart TrustDB with the
   new canonical config.
4. Confirm a successful publication by the new publisher (the stored record
   preserves the publisher that created it).
5. Only then submit `revoke-publisher` for the old account. The contract
   rejects revoking the last publisher, but the operational order above is
   mandatory regardless.
6. If the administrator key is lost or compromised: role governance is
   permanently frozen on that contract. Deploy a new `TrustDBAnchorV1`, pin
   its address and runtime code hash in a new TrustConfig, cut publishers
   over, and record the succession in the deployment evidence repository.
   Historical evidence remains bound to the old contract address and still
   verifies under its original local config.

### 12.4 Certificate expiry or compromise

1. Detection: native startup or probe `transport`-stage failures reporting
   expired, not-yet-valid, mismatched, or revoked certificate material.
2. Client SDK certificates: follow §6.2. Because startup validation is fail
   closed, an expired replacement never silently activates; stage the new
   files, restart, and confirm a clean probe.
3. CA expiry/compromise: issue under the new CA, recompute
   `trusted_ca_certificate_hashes_hex`, create a new TrustConfig, distribute
   it to every publisher **and verifier** through the operator trust process,
   and record both digests in the audit log.
4. TLCP gateway certificates (if exposed): execute the full generation
   rotation in §6.3, including candidate canaries, atomic symlink switch,
   reload, post-switch probes, and retained rollback generation. For emergency
   client revocation, stage a complete replacement CRL bundle as a new
   generation; a revoked client keeps an already-established connection until
   it closes but must fail every new handshake.
5. Drill evidence: keep the pre/post profiles, validation output, probe
   results, and rollback-generation retention note.

### 12.5 TrustDB restore from backup

1. Stop the affected TrustDB instance.
2. `trustdb backup verify --file <archive>`; reject the archive on any error.
3. `trustdb backup restore --file <archive> --metastore <kind>
   --metastore-path <new-path> --crypto-suite INTL_V1 --resume` into a clean
   proofstore path; retain the restore checkpoint file until completion.
4. Start TrustDB against the restored store with the unchanged TrustConfig;
   the durable journal and anchor schedules resume from the restored state.
5. Export a sample of `.sproof` files spanning pre- and post-backup STHs and
   verify them offline (§10.2); compare immutable anchor results against the
   pre-incident records.
6. Separately restore signer custody from the provider recovery artifact
   (SDF bundle / token ceremony) — the `.tdbackup` never carries it (§8.1).

## 13. Asset and responsibility register

### 13.1 Secrets

| Secret | Custody | Rotation | Recovery owner |
| --- | --- | --- | --- |
| Contract administrator key | Offline, dedicated, single copy under change control | None possible on-chain; loss ⇒ contract redeployment (§12.3) | Contract governance owner |
| Publisher private key | HSM/SDF/PKCS#11, non-exportable | New key/index/URI + descriptor + config (§5) | Key custodian |
| SDF adapter config / credential files | Owner-only regular files (≤64 KiB / ≤4 KiB), never logged | Device ceremony | Key custodian |
| PKCS#11 PIN | Owner-only PIN file only | Token ceremony | Key custodian |
| Guomi client signing + encryption private keys | Reference paths in TrustConfig; mounted read-only | §6.2 | Platform security owner |
| TLCP gateway signing/encryption/readiness keys | Non-exportable provider boundary; `file` references rejected in production profiles | §6.3 generation rotation | Platform security owner |
| Temporary qualification publisher key | `<work-dir>/publisher.key`, mode `0600`, trap-guaranteed deletion | Per run; ephemeral only | Qualification operator |

### 13.2 Trust roots (public but integrity-critical)

| Trust root | Distribution channel | Update mechanism |
| --- | --- | --- |
| Canonical TrustConfig CBOR (chain/group/genesis/checkpoint, contract binding, validator set, CA hashes) | Operator trust process; recorded `trust_config_digest` and `chain_context_id` | `trust-config create` for a new binding; `trust-config advance` for checkpoint only (§7) |
| Verifier-local client/server/registry public descriptors (+ historical server keys) | Operator trust process | New descriptor publication; old descriptors retained for historical evidence |
| Verifier-local CA roots (TLS/Guomi) | Operator trust process | §6 rotation procedure |
| Deployment record (`deployment-record.template.json`, signed) | Deployment evidence repository | Change-control reissue |

### 13.3 Artifacts and retention

| Artifact | Producer | Minimum retention |
| --- | --- | --- |
| `.sproof` evidence files | SDK export / qualification gate | Life of the records they evidence + verifier checkpoint cadence |
| `.tdbackup` archives + create/verify/restore reports | `trustdb backup` | Cover the slowest verifier checkpoint cadence; per organizational policy |
| CI qualification artifact set | Qualification workflow | 14 days (gate default) |
| `trust-config advance` JSON reports | Operator | Permanent audit log |
| Deployment evidence (pinned commits/digests, node identities, drill outputs) | Operator | Life of the deployment |
| SDF recovery bundle | Provider export | Per key-custody policy; independent of `.tdbackup` |
| Local artifact cache (`--cache-dir`) | `verify-artifacts` | Hash-verified bytes only; re-verifiable at any time |

### 13.4 Roles

| Role | Responsibility |
| --- | --- |
| Qualification operator | Runs smoke/qualification gates; owns ephemeral work directories and their cleanup |
| Key custodian | HSM/SDF/PKCS#11 ceremonies, publisher rotation, provider recovery artifacts |
| Contract governance owner | Administrator key, publisher authorization/revocation, contract redeployment |
| Platform security owner | Certificates, CA, TLCP gateway generations, endpoint inventory |
| Evidence verifier owner | Offline verification, trust-root sidecars, checkpoint advancement review |
| Backup operator | Backup cadence, verification, restore drills |
| Compliance owner | MLPS/密评/certification liaison; enforces the claim boundaries at the top of this document |
