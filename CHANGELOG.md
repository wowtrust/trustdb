# Changelog

This file summarizes user-visible TrustDB changes. Complete pull request lists, downloadable artifacts, and checksums remain on [GitHub Releases](https://github.com/wowtrust/trustdb/releases).

TrustDB follows semantic versioning for stable releases. Proof, backup, storage, and API compatibility notes are called out explicitly when they require operator action.

## [Unreleased]

No user-visible changes after the v2.0.0-rc.1 release candidate.

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
[2.0.0-rc.1]: https://github.com/wowtrust/trustdb/releases/tag/v2.0.0-rc.1
