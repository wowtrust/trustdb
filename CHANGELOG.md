# Changelog

This file summarizes user-visible TrustDB changes. Complete pull request lists, downloadable artifacts, and checksums remain on [GitHub Releases](https://github.com/wowtrust/trustdb/releases).

TrustDB follows semantic versioning for stable releases. Proof, backup, storage, and API compatibility notes are called out explicitly when they require operator action.

## [Unreleased]

## [2.0.1] - 2026-07-29

Patch release for an authenticated, audited online client-key control plane.
It lets an approval system update the exact append-only registry used by the
running claim-admission path without restarting TrustDB.

### Added

- Admin API operations to register, inspect, and revoke V2 client keys through
  the existing session, mTLS, or OIDC administrator identities and the
  `key.read` / `key.manage` RBAC permissions.
- Immediate single-process key admission and revocation against the live
  registry, deterministic registration/revocation replay, immutable security
  audit outcomes, and an operator guide for integrating an external approval
  system.
- Constant-time lookup of the persisted revocation event used to answer
  idempotent online retries.

### Fixed

- Admin Web login no longer panics when the optional security-audit writer is
  disabled.
- Claims signed by an inactive or revoked client key now return the typed
  `FAILED_PRECONDITION` response (`HTTP 412`) instead of an internal error.
- New online revocations reject effective times more than five seconds in the
  past. This prevents a control-plane request from retroactively invalidating
  an already accepted claim and making deterministic WAL replay fail after a
  restart; an exact persisted retry remains idempotent at any later time.

### Compatibility and release safety

- V2 wire objects, proofstore schema v5, WAL, `.sproof v2`, and `.tdbackup v5`
  are unchanged from v2.0.0. Existing v2.0.0 data directories remain
  compatible with this patch.
- Go consumers should pin `github.com/wowtrust/trustdb/v2@v2.0.1`. Stable
  containers update the immutable `2.0.1` tag and the `latest` channel.
- Immediate mutation is a single-process guarantee. NATS + TiKV deployments
  must distribute one ordered, authenticated registry event stream to every
  claim-admitting replica before routing traffic to those replicas.

## [2.0.0] - 2026-07-27

First stable V2 release. It promotes the suite-bound V2/V5 generation qualified
by RC.1 and RC.2, including the release-manifest portability fix, and closes the
remaining container configuration and workflow supply-chain findings.

### Added

- `INTL_V1` and `CN_SM_V1` claims, receipts, Merkle trees, STHs, anchor results,
  APIs, key registries, backups, and portable `.sproof v2` evidence.
- SM2/SM3 deterministic vectors, SM4-GCM key and backup envelopes, TLCP
  profiles, SDF/PKCS#11 signer sidecars, and FISCO BCOS 3.x offline anchor
  verification.
- Proofstore schema v5, V2 WAL/checkpoints, encrypted `.tdbackup v5`, durable
  coalesced STH anchoring, and resumable L5 coverage projection.
- Cross-platform Server/CLI and desktop packages, multi-architecture OCI
  images, a signed release manifest, SHA-256 and SM3 checksum sets, SPDX SBOM,
  vulnerability results, production-input inventory, container digests, and
  downloadable Sigstore provenance.

### Fixed

- The Docker entrypoint no longer forces the service configuration onto
  informational commands such as `version` or `release verify`.
- `configs/docker.yaml` now declares the development/evaluation profile it
  actually implements. Production deployments continue to use
  `configs/production.yaml` with a dedicated audit signer and synchronized
  time evidence.
- Release-manifest media types are derived from deterministic artifact names,
  so packaged Linux, macOS, and Windows verifiers enforce the same exact file
  set and dual hashes.
- Every external GitHub Action used by the repository is pinned to an
  immutable commit, with a repository-hygiene gate preventing mutable refs from
  returning.

### Compatibility and release safety

- The Go module is `github.com/wowtrust/trustdb/v2`; consumers should pin
  `v2.0.0`.
- This is an intentional breaking generation. V2 does not read, migrate, or
  fall back to v1 storage, schema v4, backups, WAL, API objects, or `.sproof`
  files. Preserve the old audit environment and deploy V2 with a new namespace,
  LogID, and empty V5 data directory.
- The stable container updates the immutable `2.0.0` tag and the `latest`
  channel. The prerelease `beta` channel remains bound to RC.2.
- Desktop packages remain self-signed and can trigger Gatekeeper or SmartScreen
  warnings. Verify the signed manifest and both checksum sets before install.
- Generic packages verify FISCO BCOS evidence offline. Real network publication
  requires the separately qualified provider-enabled source build.

## [2.0.0-rc.2] - 2026-07-26

Corrected V2 release candidate. It preserves the V2/V5 formats and proof
semantics introduced by RC.1 while replacing the affected release verifier and
documentation with reproducible, release-first paths.

### Container note

The immutable RC.2 image contains the correct TrustDB binary, but its bundled
`config/docker.yaml` declares `single_node_production` without the required
security-audit configuration. Use `--entrypoint /usr/local/bin/trustdb` for
informational commands. For an RC.2 container evaluation, explicitly set
`TRUSTDB_RUN_PROFILE=development`; do not represent that override as a
production deployment.

### Fixed

- Release-manifest media types are now derived from deterministic artifact
  names instead of the host MIME database. Packaged macOS, Linux, and Windows
  verifiers therefore enforce the same exact manifest on every platform.
- Website quick starts, SDK setup, server deployment, NATS ingress, downloads,
  and supply-chain guides consume versioned release archives, Go modules, and
  digest-pinned container images. Only the dedicated source-build guide builds
  TrustDB from source.

### Compatibility and release safety

- Proofstore schema v5, V2 WAL/checkpoints, V2 API objects, `.sproof v2`, and
  encrypted `.tdbackup v5` are unchanged from RC.1.
- RC.1 remains immutable for audit and reproducibility. RC.2 uses a new tag,
  release assets, Go module version, container version, and `beta` image while
  leaving the stable `latest` container tag unchanged.
- The breaking v1-to-v2 cutover remains in force: deploy with a new namespace,
  LogID, and empty V5 data directory; do not feed v1 storage, backups, API
  objects, or evidence files to V2.

## [2.0.0-rc.1] - 2026-07-26

First V2 release candidate. This is an intentional breaking generation and is
not an in-place upgrade from v1.0.0.

### Added

- `INTL_V1` and `CN_SM_V1` suite-bound claims, receipts, Merkle trees, STHs,
  anchor results, backups, APIs, key registries, and `.sproof v2` evidence.
- SM2/SM3 interoperability vectors, deterministic encoding rules, provider
  contracts, TLCP deployment profiles, SDF/PKCS#11 signer sidecars, and
  FISCO BCOS 3.x anchor evidence with offline receipt/finality verification.
- Encrypted `.tdbackup v5` with authenticated SM4-GCM frames, provider-wrapped
  DEKs, suite-selected entry digests, resumable restore, and source/target
  namespace binding.
- A signed release manifest, SHA-256 and SM3 checksum sets, SPDX SBOM,
  vulnerability results, production-input inventory, immutable container
  digest inventory, and downloadable Sigstore provenance bundles.
- Isolated, build-tagged PKCS#11 signer sidecar with non-exportable key-policy
  enforcement, explicit Ed25519/SM2 mechanisms, certificate/public-key
  binding, sanitized provider errors, rotation guards, and a SoftHSM
  interoperability gate.
- Versioned authenticated SM4-GCM envelopes for software-managed private keys,
  including a provider-neutral KEK interface, development PBKDF2-HMAC-SM3
  passphrase provider, and atomic `key rewrap` operation.

### Changed

- The public Go module is now `github.com/wowtrust/trustdb/v2`; consumers must
  import `/v2` and pin `v2.0.0-rc.1`.
- Proofstore schema v5, V2 WAL/checkpoints, V2 wire objects, `.sproof v2`, and
  `.tdbackup v5` replace the v1 generations. Old storage, backups, API objects,
  and proof files are rejected without dual-read, migration, or fallback.
- Release-candidate container images update immutable `2.0.0-rc.1` and `beta`
  tags while leaving `latest` unchanged.
- `trustdb key generate` now defaults to `sm4-envelope-v1` and requires
  exactly one direct or owner-only file passphrase source;
  `plaintext-dev-v1` remains an explicit development-only compatibility
  option.

### Security and correctness

- Envelope parsing and opening fail closed for non-canonical data, wrong KEKs,
  tampering, truncation, metadata/KDF downgrade, unsafe permissions, symlinks,
  and unregistered providers. Software envelopes are not represented as HSM or
  certified production key custody.
- Rewrap now holds an adjacent OS lock across read, authentication, and atomic
  replacement, preventing concurrent or stale writers from overwriting a
  winning rotation. Windows software-envelope persistence fails closed pending
  continuously runtime-qualified owner-only DACL handling.
- The release workflow refuses a source other than current `main`, an existing
  Git tag or container version, a lightweight tag, or any source/manifest/
  provenance mismatch.

### Known limitations

- Desktop packages use release-specific self-signed certificates and may
  trigger Gatekeeper or SmartScreen warnings.
- Generic release packages verify FISCO BCOS evidence offline. Real network
  publication requires a source build with the pinned C SDK v3.6.0, Go SDK
  v3.0.2, and `fiscobcos_sdk` build tag.
- This release candidate must use a new namespace, LogID, and empty data
  directory. Keep a v1 environment available when historical v1 evidence must
  still be verified.

## [1.0.0] - 2026-07-22

First stable release.

### Added

- Portable `.sproof` v1 evidence containing L3 proofs and optional L4/L5 evidence for offline verification.
- Signed client claims, server acceptance receipts, batch Merkle proofs, and a persistent Global Transparency Log.
- Optional Signed Tree Head anchoring through file, noop, and OpenTimestamps sinks.
- WAL-backed ingest with configurable fsync modes, replay, checkpoints, and graceful shutdown.
- File, Pebble, and TiKV proofstore backends, including storage-compute separation for correctly isolated TiKV namespaces.
- Logical `.tdbackup` creation, verification, and resumable restore.
- HTTP and gRPC transports plus a Go SDK for submission, proof export, and local verification.
- Linux, macOS, and Windows Server/CLI packages; macOS and Windows desktop packages; multi-architecture Docker images.
- Optional Admin Web, Prometheus metrics, production configuration profiles, and performance reports.

### Changed

- Established `github.com/wowtrust/trustdb` as the stable Go module and repository identity.
- Established storage schema v4 and the current logical-backup format.
- Coalesced STH anchoring into durable bounded scheduling state with resumable L5 coverage projection.

### Security and correctness

- Offline verification recomputes content hashes, signatures, Merkle paths, STH bindings, and supported anchor evidence using caller-supplied trust roots.
- Network response bodies, admin sessions, filesystem paths, proof parsing, WAL recovery, and restore checkpoints include explicit bounds and failure handling.
- Release archives include a unified `SHA256SUMS` file. Desktop packages are self-signed and do not establish Apple or Microsoft platform trust.

### Known limitations

- TrustDB does not by itself bind a cryptographic key to a real-world identity or make blanket legal-validity claims.
- Business HTTP and gRPC endpoints require deployment-level TLS, authentication, authorization, and network controls.
- A TiKV proofstore namespace supports one logical `(node_id, log_id)` writer stream; same-namespace active-active writers are not supported.
- Desktop packages may trigger Gatekeeper or SmartScreen warnings because the release certificates are self-signed.

[1.0.0]: https://github.com/wowtrust/trustdb/releases/tag/v1.0.0
[2.0.1]: https://github.com/wowtrust/trustdb/releases/tag/v2.0.1
[2.0.0]: https://github.com/wowtrust/trustdb/releases/tag/v2.0.0
[2.0.0-rc.2]: https://github.com/wowtrust/trustdb/releases/tag/v2.0.0-rc.2
[2.0.0-rc.1]: https://github.com/wowtrust/trustdb/releases/tag/v2.0.0-rc.1
