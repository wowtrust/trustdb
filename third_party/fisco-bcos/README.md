# Pinned FISCO BCOS native boundary

TrustDB carries narrow source snapshots of:

- `github.com/FISCO-BCOS/go-sdk/v3` v3.0.2,
  upstream commit `a9dbab29132d9e6a1cd5919dd993e4186c0703ff`;
- `github.com/FISCO-BCOS/bcos-c-sdk`
  `v0.0.0-20240726021820-a278b4749e34`,
  upstream commit `a278b4749e342d2b111d736045db9ed98a63224d`.

The upstream Apache-2.0 license is retained in each snapshot. These are local,
reviewable forks rather than complete upstream source archives. They retain
only the transitive packages and C headers used by TrustDB:

- Go SDK: `abi`, `abi/bind`, `client`, `smcrypto`, `smcrypto/sm3`, and `types`;
- C SDK Go binding: `bindings/go/csdk` plus the eight headers included by its
  cgo preamble;
- each module's `LICENSE`, `go.mod`, and `go.sum`.

Samples, command-line tools, unrelated language bindings, build systems,
upstream tests, and prebuilt DLLs/libraries are deliberately excluded. Runtime
libraries are downloaded and digest-verified by the compatibility workflow;
they are never committed here.

The top-level module replaces only these exact pins so TrustDB can enforce
security properties missing from the released Go bindings:

1. finite native message timeouts and context-aware response waiting;
2. raw callback size checks before `C.GoBytes` and bounded native errors;
3. cancellation-safe, expiring opaque callback tokens with no blocking
   goroutine or borrowed C-string lifetime;
4. observation of the loaded C SDK version and shared-library path, including
   Unicode-safe Windows paths.

Production files outside `client/connection.go`,
`bindings/go/csdk/csdk_wrapper.go`, and the three `library_path_*.go` files are
source-identical to the commits above. The Go SDK module has one local
`replace` directive so its conformance test exercises the patched C binding.
Files ending in `_trustdb_test.go` are TrustDB-owned boundary tests.
`abi/bind/template.go` also has whitespace-only fixes required by TrustDB's
repository-wide `git diff --check` gate.

TrustDB additionally verifies the loaded v3.6.0 native artifact against source
provenance commit `53240138c396c10cb0e1a2b7b4d5c0cdaa0ac539` and the
platform-specific filename, byte length, and SHA-256 pins in
`configs/compatibility/fisco-bcos-v3.16.3.json` before opening a driver. The
official Linux/amd64 library reports embedded commit `0`, and the official
Windows/amd64 DLL reports `73a3f93b2b88bd4af93e1df9c8f8c4f0be57a8ae`;
those platform build values are accepted only for their exact pinned artifact
and never replace the release source provenance.
