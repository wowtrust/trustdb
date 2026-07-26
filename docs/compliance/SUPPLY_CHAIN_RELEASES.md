# Release supply chain, offline verification, and domestic mirrors

This runbook defines how TrustDB release inputs are admitted, how release
evidence is generated, and how an operator verifies and imports a release when
the target environment has no network access.

It applies to `v2.0.0-rc.1` and later releases produced by the gated workflow.
The historical `v1.0.0` release predates this bundle and contains only
`SHA256SUMS`.

## What a gated release contains

| File | Purpose | Trust decision |
| --- | --- | --- |
| `TRUSTDB_RELEASE_MANIFEST.json` | Exact source commit, policy digest, required documents, file sizes, SHA-256, and SM3 for every asset | Verify its Sigstore bundle before trusting any contained digest |
| `trustdb-release-attestation.sigstore.json` | GitHub Actions build-provenance attestation for the manifest | Verify with a separately retained trusted root |
| `SHA256SUMS` / `SM3SUMS` | Dual checksums for the manifest and every manifested asset | Both must exactly match the signed manifest |
| `trustdb-release.spdx.json` | SPDX JSON dependency and license inventory | Must be manifested; review `NOASSERTION` or policy exceptions before admission |
| `TRUSTDB_PRODUCTION_INPUTS.json` | Exact native SDK, contract, toolchain lock, image, license, and architecture inventory | Must match the policy digest in the manifest |
| `TRUSTDB_VULNERABILITY_REPORT.json` | Retained npm and `govulncheck` output from the fail-on-high gate | Must identify the same source commit |
| `TRUSTDB_CONTAINER_DIGESTS.json` | Multi-architecture OCI digest and registry references | Import and mirror by digest, never by a channel tag |
| `trustdb-container-attestation.sigstore.json` | Provenance for the exact OCI digest | Verify with the same independently retained root |

The release workflow fails before publication when:

- a production GitHub Action uses a floating tag instead of a full commit SHA;
- a Docker base image is not selected through a policy-controlled
  `name@sha256:digest` reference;
- a required FISCO BCOS, contract, PKCS#11, SDF, TLCP, Go, npm, desktop, or
  website input is missing, has changed bytes, has unresolved license evidence,
  or lacks an architecture declaration;
- `go mod verify`, an npm high-severity audit, or `govulncheck` fails;
- the SPDX SBOM, vulnerability report, production-input inventory, container
  digest inventory, dual checksums, or provenance bundle cannot be produced;
- an artifact is missing from the manifest or an unexpected file appears in
  the offline bundle.

## Trust roots are provisioned separately

Never treat a trusted-root file found beside a release as authoritative. That
would let an attacker replace the artifact, signature, and claimed root
together.

Before the maintenance window, acquire the GitHub/Sigstore trusted-root
snapshot through an independently approved channel and record its SHA-256 in
the organization's trust-root register:

```bash
gh attestation trusted-root > github-public-good-trusted-root.json
sha256sum github-public-good-trusted-root.json
```

Retain the approved GitHub CLI binary, trusted-root file, expected repository
identity (`wowtrust/trustdb`), and expected release version on read-only media
or an authenticated internal repository. Root rotation is a separate security
change and must not happen implicitly during a TrustDB upgrade.

## Connected staging verification

Download every release asset into one otherwise empty directory. Put the
trusted root outside that directory:

```bash
mkdir trustdb-release
gh release download vX.Y.Z \
  --repo wowtrust/trustdb \
  --dir trustdb-release

APPROVED_COMMIT=replace-with-approved-40-character-commit
gh attestation verify \
  trustdb-release/TRUSTDB_RELEASE_MANIFEST.json \
  --repo wowtrust/trustdb \
  --signer-workflow wowtrust/trustdb/.github/workflows/release.yml \
  --source-digest "$APPROVED_COMMIT" \
  --deny-self-hosted-runners \
  --bundle trustdb-release/trustdb-release-attestation.sigstore.json \
  --custom-trusted-root /secure/trust-roots/github-public-good-trusted-root.json
```

`APPROVED_COMMIT` comes from the signed release approval record or another
independent repository channel, not from the still-untrusted manifest. Now use
a previously admitted TrustDB verifier to enforce exact coverage and both
hashes:

```bash
trustdb release verify --dir trustdb-release
```

The command rejects path traversal, symlinks, nested or extra files, missing
required documents, duplicate checksum rows, changed sizes, and any SHA-256 or
SM3 mismatch. Do not use the not-yet-verified binary from the same release as
the only verifier. If no previous verifier exists, independently validate
`SHA256SUMS` and `SM3SUMS`, extract the now hash-admitted binary, and run the
TrustDB verifier as a second check.

Inspect retained policy and security results before approval:

```bash
jq . trustdb-release/TRUSTDB_PRODUCTION_INPUTS.json
jq . trustdb-release/TRUSTDB_VULNERABILITY_REPORT.json
jq . trustdb-release/TRUSTDB_CONTAINER_DIGESTS.json
```

## Air-gapped transfer and import

Create an operator transfer inventory over the already verified directory and
the separately approved trust root:

```bash
find trustdb-release -maxdepth 1 -type f -print0 \
  | sort -z \
  | xargs -0 sha256sum > transfer-media.sha256
sha256sum /secure/trust-roots/github-public-good-trusted-root.json \
  >> transfer-media.sha256
```

Write the release, trusted verifier, trusted root, and `transfer-media.sha256`
to controlled media. At the offline boundary:

1. verify the media inventory;
2. copy the release into an empty directory;
3. repeat `gh attestation verify` with `--bundle` and
   `--custom-trusted-root`;
4. repeat `trustdb release verify`;
5. compare the source commit, version, policy digest, and planned platform;
6. extract only the matching operating-system and architecture package;
7. run `trustdb version`, `trustdb config validate`, and `trustdb doctor`;
8. start an isolated canary, export `.sproof v2`, disconnect the service, and
   verify the proof with independently retained evidence trust roots.

Store the release manifest, both attestation bundles, both checksum files,
production-input inventory, SBOM, vulnerability report, approval record, and
media inventory for at least the evidence-retention lifetime.

## OCI export, domestic mirror, and offline import

Read the immutable digest from `TRUSTDB_CONTAINER_DIGESTS.json`; do not export
`latest` or another channel tag:

```bash
DIGEST="$(jq -r .digest trustdb-release/TRUSTDB_CONTAINER_DIGESTS.json)"
skopeo copy --all \
  "docker://ghcr.io/wowtrust/trustdb@${DIGEST}" \
  oci-archive:trustdb-X.Y.Z.oci.tar
skopeo inspect --format '{{.Digest}}' \
  oci-archive:trustdb-X.Y.Z.oci.tar
```

The inspected digest must exactly equal `DIGEST`. Add the OCI archive digest
to the transfer-media inventory. On the offline host:

```bash
skopeo inspect --format '{{.Digest}}' \
  oci-archive:trustdb-X.Y.Z.oci.tar
skopeo copy --all \
  oci-archive:trustdb-X.Y.Z.oci.tar \
  docker-daemon:trustdb:X.Y.Z
```

To populate a domestic registry, copy the exact manifest list and verify that
the destination keeps the same digest:

```bash
skopeo copy --all \
  "docker://ghcr.io/wowtrust/trustdb@${DIGEST}" \
  "docker://registry.example.cn/wowtrust/trustdb@${DIGEST}"
skopeo inspect --format '{{.Digest}}' \
  "docker://registry.example.cn/wowtrust/trustdb@${DIGEST}"
```

For source builds, copy
`supply-chain/domestic-mirrors.env.example`, configure approved Go and npm
mirrors, and mirror the three base images without rewriting their OCI
manifests. Pass the mirrored digest references as `NODE_IMAGE`, `GO_IMAGE`, and
`RUNTIME_IMAGE`. Mirrors change acquisition routes; they never weaken `go.sum`,
npm integrity, policy digests, or OCI digest checks.

## Native and contract admission matrix

`supply-chain/production-inputs.json` is the machine-enforced matrix. Every
entry records:

- exact release, commit, ABI, compiler, or lockfile generation;
- canonical file or directory SHA-256;
- license expression and repository evidence path;
- admitted operating-system and architecture set.

It covers the vendored FISCO BCOS C SDK and Go SDK, standard/Guomi contract
source and compiled artifacts, PKCS#11 integration, the versioned SDF adapter
ABI, reproducible TLCP gateway baseline, server/desktop Go graphs, all npm
graphs, and all Docker base images. Vendor-specific SDF libraries, HSM
firmware, deployed BCOS contracts, and operator certificates remain
deployment inputs: record their version, hash, license, architecture,
qualification result, and custody evidence in the deployment dossier.

## Updating a production input

Do not hand-edit only the digest. In one reviewable pull request:

1. update the source, lock, SDK, compiler, contract, or image;
2. review its license and architecture support;
3. generate the new canonical value with
   `trustdb release digest-input --path <repository-relative-path>`;
4. update `supply-chain/production-inputs.json`;
5. run `trustdb release verify-policy`;
6. run unit, race, platform, vulnerability, contract, and relevant hardware
   qualification gates;
7. reproduce the package twice from the same commit and commit timestamp;
8. record the approved exception and expiry if a gate cannot yet pass.

No gate may silently downgrade to a tag, an unsigned artifact, an unknown
license, or a previous binary after failure.

## Clean-room drill

Quarterly, use a host with no TrustDB cache and no network:

- provision only the registered verifier, trusted root, release bundle, OCI
  archive, and deployment secrets;
- verify provenance and every hash;
- import the package and image;
- restore a test backup into a new namespace;
- produce and verify a canary `.sproof v2`;
- tamper with one package byte, one manifest digest, the attestation bundle,
  the trusted root, the OCI digest, and one SBOM/policy file and require every
  case to fail at the expected stage.

Record duration, operators, tool versions, root digest, source commit,
platform, failed stage, and remediation. A release is not air-gap ready until
this drill succeeds.
