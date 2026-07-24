# Reproducible TLCP gateway image

The gateway terminates TLCP mutual authentication with Tengine 2.3.4 and
Tongsuo 8.4.0, then forwards plaintext only over loopback to the TrustDB
process in the same restricted network namespace.

All source archives, source licenses, container inputs, Debian snapshot
packages, build arguments, and the Syft scanner are pinned in `baseline.json`.
The build uses `SOURCE_DATE_EPOCH`, rewrites OCI layer timestamps, disables
embedded provenance attestations, and compares two complete OCI archives.

Build and independently verify one architecture:

```sh
PLATFORM=linux/amd64 packaging/tlcp-gateway/build.sh
PLATFORM=linux/arm64 packaging/tlcp-gateway/build.sh
```

Each run produces an OCI archive, a canonical SPDX 2.3 SBOM, an immutable
build record, and the build-record SHA-256 under `dist/tlcp-gateway`. The
record binds the archive digest, image manifest digest, SBOM digest, baseline
digest, source archives, license checksums, base images, frontend image, and
Syft image.

The build fails unless both rebuilds are byte-identical and the loaded image:

- runs as UID/GID `10001`;
- contains the exact Tengine and Tongsuo binaries and source licenses;
- exposes only a writable runtime directory, not a writable configuration
  directory; and
- refuses to start without the complete validated gateway environment.

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
