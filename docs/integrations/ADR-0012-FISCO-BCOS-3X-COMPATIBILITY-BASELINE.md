# ADR-0012: FISCO BCOS 3.x compatibility baseline

- Status: Accepted; native Air runtime profiles admitted for Linux/amd64 and Darwin/arm64, with no TrustDB anchor implementation implied
- Date: 2026-07-24
- Issue: [#461](https://github.com/wowtrust/trustdb/issues/461)
- Machine-readable contract: [`configs/compatibility/fisco-bcos-v3.16.3.json`](../../configs/compatibility/fisco-bcos-v3.16.3.json)

## Decision

TrustDB pins FISCO BCOS `v3.16.3`, Go SDK `v3.0.2`, the Go SDK's exact C SDK module commit `a278b4749e34`, C SDK native release `v3.6.0`, and FISCO's Solidity compiler `v0.8.11` as one indivisible candidate baseline. Version-number similarity is not compatibility evidence.

The default compatibility gate requires `runtime_status=verified`. Native Air standard and Guomi are admitted only for the exact Linux/amd64 and Darwin/arm64 rows backed by committed compiler-driven four-node evidence. Linux/arm64 remains unverified. Pro and Max remain unsupported because the `v3.16.3` release does not contain the service archives that its pinned BcosBuilder code requests. Container execution cannot enter validation because the `v3.16.3` image is absent and has no digest. Runtime compatibility does not by itself implement or admit a TrustDB BCOS anchor provider; that semantic work begins in #462.

This decision is intentionally narrower than “FISCO BCOS 3.x support.” Later work in #462–#471 may promote an exact row only by committing complete smoke evidence for that row; it must not broaden the version range or copy evidence across deployment, crypto, OS, or CPU boundaries.

## Evidence language

Compatibility reports and CI use three distinct levels:

| Level | Meaning | What it does not mean |
| --- | --- | --- |
| `documented` | An official FISCO source describes the feature or topology. | The pinned artifacts exist or work together. |
| `artifact` | Every native artifact needed by the row has an exact SHA-256 and passed byte/size verification. | A node network or SDK operation succeeded. |
| `runtime` | The exact row completed all required operations and produced reviewable evidence. | Other rows, patches, architectures, or release tags are compatible. |

The validator defaults to `runtime`. A partial smoke is recorded as `partial`, never `verified`.
Changing a matrix row to `runtime_status=verified` is insufficient by itself:
the validator requires a committed repository-relative evidence file whose component
pins, complete artifact digest set, negotiated crypto mode, transaction/proof/event
results, block roots, PBFT signatures and node identities, and stale `blockLimit`
rejection all match that exact row. Compiler-independent raw-EVM diagnostics can
never satisfy runtime admission.

## Exact pins and provenance

| Component | Pin | Commit | Provenance and qualification |
| --- | --- | --- | --- |
| Node | `v3.16.3` | `274f864e7725fef5b8ed4c6b7a3363ee5396f104` | [Latest non-prerelease GitHub release](https://github.com/FISCO-BCOS/FISCO-BCOS/releases/tag/v3.16.3). The newer `v3.16.4` release is marked prerelease and is excluded. GitHub supplies SHA-256 digests for all four node archives. |
| Go SDK | `v3.0.2` | `a9dbab29132d9e6a1cd5919dd993e4186c0703ff` | [Official Go SDK release](https://github.com/FISCO-BCOS/go-sdk/releases/tag/v3.0.2). Its README requires Go 1.21+, FISCO BCOS 3.2+, cgo, C SDK, and solc 0.8.11. |
| Go SDK C dependency | pseudo-version `v0.0.0-20240726021820-a278b4749e34` | `a278b4749e342d2b111d736045db9ed98a63224d` | Pinned by the Go SDK's [exact `v3/go.mod`](https://github.com/FISCO-BCOS/go-sdk/blob/a9dbab29132d9e6a1cd5919dd993e4186c0703ff/v3/go.mod). This post-release source commit is not assumed byte-equivalent to the native `v3.6.0` assets. |
| C SDK native library | `v3.6.0` | `53240138c396c10cb0e1a2b7b4d5c0cdaa0ac539` | [Official C SDK release](https://github.com/FISCO-BCOS/bcos-c-sdk/releases/tag/v3.6.0), which is the native library release named by the Go SDK README. GitHub did not expose asset digests; TrustDB downloaded and SHA-256 hashed every published asset on 2026-07-24. |
| Solidity/compiler | `v0.8.11` | `415673533ae8ae4e9da5af544822499d04f69a52` | [FISCO Solidity release](https://github.com/FISCO-BCOS/solidity/releases/tag/v0.8.11). Standard and GM variants are independently pinned; one must never substitute for the other. |
| TASSL certificate tool | `V_1.4` / `1.1.1b` | `fe885b939c13c715633e4c05df8811a1ea7ca079` | [Official TASSL release](https://github.com/FISCO-BCOS/TASSL/releases/tag/V_1.4). The pinned `build_chain.sh` invokes this tool for standard and GM certificate/key generation, so every platform archive is independently hashed. |
| Official docs | `release-3` | `3e6b003778e076d0cdd5c5a99497299aebf0c89d` | Documentation claims are linked to this exact commit, not the moving Read the Docs `latest` alias. |

The JSON file is authoritative for artifact names, URLs, byte sizes, and SHA-256 values. `scripts/fisco-bcos/compatibility.py verify-artifacts` re-downloads or checks a cache and rejects any byte mismatch.

## Deployment, crypto, and architecture matrix

The official docs describe [Air, Pro, and Max](https://github.com/FISCO-BCOS/FISCO-BCOS-DOC/blob/3e6b003778e076d0cdd5c5a99497299aebf0c89d/3.x/zh_CN/docs/introduction/key_feature.md): Air is all-in-one, Pro separates access and node services, and Max adds executor horizontal scaling, TiKV, and failover. The hardware guide documents [x86_64 and aarch64 CPUs](https://github.com/FISCO-BCOS/FISCO-BCOS-DOC/blob/3e6b003778e076d0cdd5c5a99497299aebf0c89d/3.x/zh_CN/docs/quick_start/hardware_requirements.md). The feature overview documents both [national cryptography algorithms and GM TLS](https://github.com/FISCO-BCOS/FISCO-BCOS-DOC/blob/3e6b003778e076d0cdd5c5a99497299aebf0c89d/3.x/zh_CN/docs/introduction/function_overview.md). These are documented capabilities, not results for the pinned baseline.

| Deployment | Standard amd64/arm64 | Guomi amd64/arm64 | Admission decision |
| --- | --- | --- | --- |
| Air | Linux/amd64 and Darwin/arm64 completed compiler-backed four-node runtime validation. Linux/arm64 remains artifact-verified but unexecuted. | Standard and Guomi are separate rows with independent compiler, certificate, negotiated-mode, transaction, proof-field, event, PBFT and teardown evidence. | Only the four exact Linux/amd64 and Darwin/arm64 rows are admitted. No evidence is copied to another OS or CPU. |
| Pro | The pinned BcosBuilder requests `BcosRpcService`, `BcosGatewayService`, and `BcosNodeService` archives, but the `v3.16.3` release returns 404 for them. | Same artifact gap, before any GM test can start. | Unsupported and fail closed. Building locally would define a different, separately attestable baseline. |
| Max | The release also lacks `BcosMaxNodeService` and `BcosExecutorService`; TiKV/Tars was not provisioned. | Same artifact gap plus no GM Max execution. | Unsupported and fail closed. |

Darwin/arm64 is a supported development/runtime-validation row, not a production-deployment claim. Windows has C SDK, standard/GM compiler and TASSL assets but no `v3.16.3` node release, so it is deliberately a developer-toolchain gate rather than a node runtime row. The Windows CI executes both compilers against `CompatibilityProbe.sol`, executes TASSL, verifies the exact C SDK DLL/import library, links the Go SDK smoke client through cgo, compiles every TrustDB package, and runs the established Windows-safe crypto, WAL, anchor-system and SDK tests. Tests that assert POSIX file-mode behavior remain outside that Windows gate rather than being reported as Windows product support. The official node Docker workflow targets only `linux/amd64`; both `v3.16.3` image runs were [cancelled](https://github.com/FISCO-BCOS/FISCO-BCOS/actions/runs/19784679576), and `docker.io/fiscoorg/fiscobcos:v3.16.3` returned `manifest unknown` on 2026-07-24. A mutable or older image tag is not an allowed substitute.

## Required API surface and current Go SDK gaps

Source inspection at the exact Go SDK commit establishes API presence. It does not establish runtime correctness.

| Requirement | Exact Go SDK surface | Baseline state |
| --- | --- | --- |
| Transaction submission | `SendTransaction`, `SendEncodedTransaction`, async variants | Present. All four admitted compiler-backed rows submitted successful deployment and ABI call transactions. |
| Receipt and transaction proof retrieval | `GetTransactionReceipt(..., true)` yields `txReceiptProof`; `GetTransactionByHash(..., true)` yields `txProof` | Present. All admitted rows returned non-empty arrays, but retrieval is not independent proof verification. The official JSON-RPC docs describe [`getTransactionReceipt` with proof](https://github.com/FISCO-BCOS/FISCO-BCOS-DOC/blob/3e6b003778e076d0cdd5c5a99497299aebf0c89d/3.x/zh_CN/docs/develop/api.md#L441-L487). |
| Blocks and PBFT metadata | `GetBlockByNumber`, `GetBlockHashByNumber`, `GetPBFTView`, `GetConsensusStatus`, `GetSealerList` | Present. Each admitted run bound the event transaction to a block response with transaction/receipt roots, three signatures, four connected sealers, quorum 3, and one tolerated fault. |
| Events | `SubscribeEventLogs` / `UnSubscribeEventLogs` | Present. Each admitted run matched the compiled `Anchored` ABI event topics and transaction hash to the submitted call. The official Go SDK docs describe [asynchronous event push](https://github.com/FISCO-BCOS/FISCO-BCOS-DOC/blob/3e6b003778e076d0cdd5c5a99497299aebf0c89d/3.x/zh_CN/docs/sdk/go_sdk/event_sub.md). |
| Certificates | Standard CA/key/cert and GM CA/signing/encryption key/cert fields in `client.Config` | Present. The standard leaf and both GM signing/encryption leaves verified against their generated CAs; the Go client reported the expected negotiated mode. |
| `blockLimit` | Explicit input to `CreateEncodedTransactionDataV1`; receipt status `10001` is `BlockLimitCheckFail` | Present but no convenience getter in the main Go client. All admitted runs accepted `height+600` and rejected a deliberately stale limit with `BlockLimitCheckFail`. Official C SDK docs state [current height + 600](https://github.com/FISCO-BCOS/FISCO-BCOS-DOC/blob/3e6b003778e076d0cdd5c5a99497299aebf0c89d/3.x/zh_CN/docs/sdk/c_sdk/transaction_data_struct.md#L74-L80). |
| Offline proof verification | No verifier for `txProof` or `txReceiptProof` | Missing. Retrieval is not verification. TrustDB must implement proof decoding, hashing, and binding to the exact finalized block `transactionsRoot`/`receiptsRoot`; accepting SDK booleans or strings would violate the fail-closed proof model. |

PBFT consensus metadata is supporting evidence, not finality by itself. The later anchor implementation must bind the exact transaction and receipt roots to a finalized block and then independently validate the TrustDB payload. BCOS inclusion, PBFT finality, TrustDB proof validity, and exact anchor binding remain separate gates.

## C SDK adapter and sidecar decision

The Go SDK is already a cgo wrapper over `bcos-c-sdk`; adding another in-process C binding would duplicate ABI, memory-lifetime, and native-library risk without adding an isolation boundary. It is rejected.

The approved fallback for a future Go SDK gap is a narrow, supervised C SDK sidecar with these constraints:

1. It is compiled from the pinned C SDK source dependency and loads only a SHA-256-pinned native library for the exact platform.
2. Its protocol is versioned and exposes only the missing operation, request/response bytes, node/group identity, negotiated crypto mode, and native SDK protocol version. It never returns “verified”; it only returns raw BCOS evidence plus transport status.
3. Private transaction keys and GM TLS material are passed by reference or mounted with least privilege. They are not serialized into TrustDB proof objects or logs.
4. Startup fails if the library digest, SDK protocol, group, crypto mode, or certificate set differs from configuration. Crash/restart is supervised and bounded; no fallback to the Go path or a different native library occurs silently.
5. TrustDB performs proof and finality verification in Go after the sidecar returns raw bytes.

No sidecar is introduced by #461 because all required retrieval/submission operations have a Go SDK API. The known missing operation—offline proof verification—must not be delegated to either SDK.

## Reproducible validation

Static and artifact gates:

```bash
python3 scripts/fisco-bcos/compatibility.py validate
python3 scripts/fisco-bcos/test_compatibility.py

# Downloads the exact Linux/amd64 node, C SDK, and both compiler variants,
# then verifies size and SHA-256.
python3 scripts/fisco-bcos/compatibility.py verify-artifacts \
  --platform linux/amd64 \
  --cache-dir .cache/fisco-bcos-compat

# Artifact admission succeeds for the Air candidate.
python3 scripts/fisco-bcos/compatibility.py check \
  --deployment air --crypto standard --platform linux/amd64 --level artifact

# Runtime admission succeeds only for the exact committed Linux/amd64 row.
python3 scripts/fisco-bcos/compatibility.py check \
  --deployment air --crypto standard --platform linux/amd64

# Linux/arm64 remains fail closed because no native run evidence is committed.
python3 scripts/fisco-bcos/compatibility.py check \
  --deployment air --crypto standard --platform linux/arm64

# These also intentionally fail: missing Pro artifacts and missing image digest.
python3 scripts/fisco-bcos/compatibility.py check \
  --deployment pro --crypto guomi --platform linux/arm64 --level artifact
python3 scripts/fisco-bcos/compatibility.py check \
  --deployment air --crypto standard --platform linux/amd64 \
  --level documented --distribution container
```

The pinned Air smoke runner is `scripts/fisco-bcos/smoke-air.sh`. It generates an isolated four-node network with the tag-pinned `build_chain.sh`, explicit version and admin address, validates certificate material, creates an ephemeral in-memory transaction key, and requires the Go SDK smoke client to emit an evidence JSON. Standard and Guomi are separate, sequential invocations; generated networks, certificates, keys, or results are never reused across modes. The runner owns each exact node PID and starts nodes sequentially because the generated upstream scripts identify all four nodes by one shared executable path and their parallel startup exposed a gateway crash on a high-core Linux host. It rejects Linux listener ranges that overlap the kernel ephemeral range, fails closed if another same-platform smoke owns its host lock, and requires every node log to report a four-member group view within a bounded timeout before entering the native SDK. It emits evidence only after clean SDK shutdown, clean node shutdown, listener release and host-lock release. An external `--cache-dir` may reuse only hash-verified release bytes.

The path-scoped workflow `.github/workflows/fisco-bcos-compat.yml` continuously exercises the complete standard and Guomi Air smoke on GitHub's native macOS/arm64 runner. Its Windows/amd64 job does not pretend a node runtime exists: it verifies and executes the exact developer toolchain and Go/C SDK link path described above.

The default path compiles `CompatibilityProbe.sol` with the exact standard or GM compiler and fails if the compiler cannot execute. `--raw-evm-fixture` is a deliberately weaker diagnostic: it deploys fixed creation bytecode whose runtime emits `LOG0`, allowing node/SDK/TLS/proof/event/blockLimit investigation when the compiler is blocked. Evidence from that flag can never by itself promote a row to `runtime_status=verified`.

```bash
scripts/fisco-bcos/smoke-air.sh \
  --mode standard --work-dir /tmp/fisco-standard
scripts/fisco-bcos/smoke-air.sh \
  --mode guomi --work-dir /tmp/fisco-guomi

# Diagnostic only; never sufficient for admission.
scripts/fisco-bcos/smoke-air.sh \
  --mode standard --raw-evm-fixture --work-dir /tmp/fisco-standard-raw
```

## Evidence obtained on 2026-07-24

Compiler-backed runtime validation completed on native Ubuntu 24.04 Linux/amd64 for both [standard Air](evidence/fisco-bcos/2026-07-24-linux-amd64-standard-runtime.json) and [Guomi Air](evidence/fisco-bcos/2026-07-24-linux-amd64-guomi-runtime.json), and on macOS 26.1 arm64 for both [standard Air](evidence/fisco-bcos/2026-07-24-darwin-arm64-standard-runtime.json) and [Guomi Air](evidence/fisco-bcos/2026-07-24-darwin-arm64-guomi-runtime.json). The earlier [standard raw-EVM diagnostic](evidence/fisco-bcos/2026-07-24-darwin-arm64-standard-diagnostic.json) and [Guomi raw-EVM diagnostic](evidence/fisco-bcos/2026-07-24-darwin-arm64-guomi-diagnostic.json) remain historical, non-admitting records.

The pinned standard and GM compiler executables are native arm64 Mach-O binaries. Both link to `/opt/homebrew/opt/z3/lib/libz3.dylib` plus the macOS C++ and system libraries. Installing the normal Homebrew `z3` 4.16.0 development dependency satisfied that absolute install name without modifying either pinned compiler. The standard compiler reported `0.8.11+commit.0bbcc642`; the GM compiler reported `0.8.11+commit.1c3fd7c1.mod`. The evidence records the executable architecture, dependency set and hashes, as well as the pinned release archive hashes.

Each final run verified the exact node, C SDK, compiler archive and TASSL hashes; reported node version 3.16.3 / commit `274f864e...`; generated an independent four-node network; verified the relevant certificate chains; negotiated the expected standard or GM mode; compiled `CompatibilityProbe.sol`; submitted deployment and event transactions; retrieved transaction and receipt proof arrays; matched the ABI event to the submitted transaction; fetched its block roots and three PBFT signatures; observed four sealers with quorum 3; and rejected a stale `blockLimit`. All four commands emitted one valid JSON document, left client stderr empty, closed the native SDK cleanly, stopped all nodes, released all listeners and removed the host lock. Generated private keys, certificates and node directories remain outside the repository and are not part of the evidence.

The first native Linux run used the generated parallel `start_all.sh`; node3 segfaulted in an I/O service thread while the other nodes continued. Starting the same four exact binaries sequentially under PID ownership remained stable and both final modes passed. A separate Guomi attempt selected P2P base port `33300`, which overlapped the host's Linux ephemeral range; an outgoing peer connection consumed a later node's intended listener port. The runner now rejects such ranges before downloading or building anything.

The first compiler-backed Guomi attempt exposed a readiness race: TLS and websocket handshakes completed, but the four nodes had observed group sizes of only 1/3/3/3, so `bcos_sdk_start` eventually reported a websocket connection handshake timeout. A fresh network passed. The runner previously treated process liveness plus a fixed delay as readiness; it now fails closed unless every node observes `connectedNodeSize=4` before native SDK creation. This avoids entering the upstream SDK's opaque connection timeout with a partial group. The admitted Guomi evidence includes the redacted failed-attempt diagnosis and the final successful run.

Earlier standard diagnostics also identified a native `bcos_sdk_destroy` crash after immediate close. The smoke client now explicitly unsubscribes, gives native callback work a one-second bounded drain, closes the client, and emits evidence only after clean teardown. The final compiler-backed standard and Guomi runs completed that path with empty client stderr. Proof arrays were retrieved and bound to the containing block roots, but were not independently decoded and cryptographically recomputed.

Runtime evidence must include exact commands, host/CPU, every artifact digest, node `--version`, four node identities, certificate mode, submitted transaction hash, receipt and transaction proof arrays, containing block roots/signatures/sealer list, event payload, successful fresh `blockLimit`, rejected stale `blockLimit`, and raw client output. If any item is absent, the row remains non-admissible.

## Consequences and follow-up boundary

- #462 may consume the verified native Air profiles for Linux/amd64 and Darwin/arm64; other platform and deployment rows retain their independent fail-closed status.
- #463–#471 must consume the JSON gate and add evidence without relaxing it.
- Publishing new upstream assets or an image later does not mutate this ADR. Their hashes and provenance require a reviewed baseline update.
- Pro/Max enablement requires a complete, pinned service artifact set (or a separately attested source build), plus Tars/TiKV deployment evidence. Air results cannot be copied to those architectures.
- Guomi is a ledger, TLS, account/signature, compiler, hash, proof, and certificate mode. Enabling only one layer is a compatibility failure.
