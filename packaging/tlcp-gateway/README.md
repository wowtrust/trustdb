# Reproducible TLCP gateway image

The gateway terminates TLCP mutual authentication with Tengine 2.3.4 and
Tongsuo 8.4.0, then forwards plaintext only over loopback to the TrustDB
process in the same restricted network namespace.

All source archives, source licenses, container inputs, Debian snapshot
packages, build arguments, the Buildx release, the multi-architecture BuildKit
image digest, and the Syft scanner are pinned in `baseline.json`.
The build uses `SOURCE_DATE_EPOCH`, rewrites OCI layer timestamps, disables
embedded provenance attestations, and compares two complete OCI archives.
Both passes use `--no-cache`, so the second pass recompiles Tengine, Tongsuo,
and the embedded Go profile/readiness tools instead of replaying the first
pass's cached layers. The embedded tools build from
`validator-go.mod`/`validator-go.sum`, which contain only their required
runtime-validation modules rather than downloading TrustDB's unrelated server
dependencies.
Those modules are fetched serially with bounded retries and verified against
the committed sums before compilation.
The runtime package layer removes apt/dpkg logs and the regenerated ldconfig
auxiliary cache because they contain execution-time state and are not required
to load the pinned runtime library.
The first solve also exports the identical BuildKit result through the Docker
exporter for local runtime checks. The retained deliverable remains the
independently verified OCI archive; it is not passed to `docker image load`,
whose input contract is a Docker image archive. Both exporters rewrite layer
timestamps to the reviewed `SOURCE_DATE_EPOCH` and use OCI media types. The
build requires the
loaded image identity to match either the retained OCI manifest digest
(containerd image store) or its config digest (classic image store).

Build and independently verify one architecture with Buildx `v0.35.0` and the
reviewed `docker-container` builder from `baseline.json`. The build fails
before compilation if either active tool differs:

- Buildx: [`v0.35.0`](https://github.com/docker/buildx/releases/tag/v0.35.0)
- BuildKit: [`v0.31.2`](https://github.com/moby/buildkit/releases/tag/v0.31.2),
  selected through its reviewed multi-architecture registry digest

```sh
PLATFORM=linux/amd64 packaging/tlcp-gateway/build.sh
PLATFORM=linux/arm64 packaging/tlcp-gateway/build.sh
```

Each run produces an OCI archive, a canonical SPDX 2.3 SBOM, an immutable
build record, and the build-record SHA-256 under `dist/tlcp-gateway`. The
record binds the archive digest, image manifest digest, SBOM digest, baseline
digest, source archives, license checksums, base images, frontend image,
Buildx release, BuildKit image, and Syft image.

The build fails unless both rebuilds are byte-identical and the loaded image:

- runs as UID/GID `10001`;
- contains the exact Tengine and Tongsuo binaries and source licenses;
- contains the pinned strict profile validator and credentialed readiness
  executable;
- exposes only a writable runtime directory, not a writable configuration
  directory; and
- refuses to start without the complete validated gateway environment.

Deployment, dual-certificate input, readiness, CRL, atomic rotation, and
failure-recovery procedures are documented in
[`docs/integrations/TLCP_GATEWAY.md`](../../docs/integrations/TLCP_GATEWAY.md).
The complete strict profile format is
[`formats/TLCP_GATEWAY_PROFILE_V1.md`](../../formats/TLCP_GATEWAY_PROFILE_V1.md).

Re-run the standalone verifier before promotion:

```sh
go run ./cmd/trustdb-tlcp-build-record verify \
  --baseline packaging/tlcp-gateway/baseline.json \
  --oci-archive dist/tlcp-gateway/gateway-linux-amd64.oci.tar \
  --platform linux/amd64 \
  --record dist/tlcp-gateway/gateway-linux-amd64.build-record.json \
  --record-sha256 dist/tlcp-gateway/gateway-linux-amd64.build-record.json.sha256 \
  --sbom dist/tlcp-gateway/gateway-linux-amd64.sbom.spdx.json
```
