# TLCP and Guomi certificate gateway

TrustDB can expose HTTP and gRPC through a pinned Tengine/Tongsuo gateway using
TLCP mutual authentication, SM2/SM3 dual certificates, SM4-GCM, CRLs, and
HTTP/2. The gateway is a transport boundary only: it does not sign TrustDB
receipts, build Merkle trees, anchor an STH, or supply an offline proof trust
root.

The supported reference implementation is:

- Tengine `2.3.4`, commit
  `698e1798e8d691c55b5405ca1526c3dca4759d47`;
- Tongsuo `8.4.0`, commit
  `a8ae0925d26de3b449f7a21767910cd41291bcd8`;
- protocol `NTLSv1.1`;
- cipher suite `ECDHE-SM2-SM4-GCM-SM3`;
- ALPN `h2` and `http/1.1`;
- separate SM2 signing and encryption certificates and private keys;
- mandatory client certificates and fail-closed CRL checking.

The complete machine-readable contract is
[`formats/TLCP_GATEWAY_PROFILE_V1.md`](../../formats/TLCP_GATEWAY_PROFILE_V1.md).
Validate every deployment profile before starting or rotating the gateway:

```sh
go run ./cmd/trustdb-tlcp-profile validate \
  --profile /etc/trustdb/tlcp/profile.json
```

Every production profile must contain the exact reference and canonical public
key SHA-256 of every active TrustDB proof signer in `proof_signing_keys`.
Validation fails when this inventory is empty or overlaps either gateway key.
The optional `--forbid-*` flags add rollout-time identities; they do not replace
the mandatory production inventory.

## Deployment boundary

Run TrustDB and the gateway in one restricted network namespace:

```text
TLCP client ── SM2/SM3/SM4 mTLS ──> TLCP gateway
                                           │
                                  loopback HTTP/gRPC
                                           │
                                        TrustDB
```

Only the gateway ports are published. Bind TrustDB HTTP and gRPC to
`127.0.0.1`; do not publish ports `8080` or `9090`, use host networking, or
attach a debug container to the namespace. During rotation, exactly one
short-lived `tlcp-gateway-candidate` may join on the canary ports and must be
removed after promotion or failure. The reference container runs as
UID/GID `10001`, drops every Linux capability, uses a read-only root
filesystem, and needs writable tmpfs mounts only for:

- `/run/tlcp-gateway`;
- `/var/cache/tlcp-gateway`.

Mount certificates, CA bundles, CRLs, and provider configuration read-only.
TrustDB must not receive either gateway private-key mount.

## Required gateway inputs

| Environment variable | Meaning |
| --- | --- |
| `TLCP_PROFILE_FILE` | Absolute path to the strict profile; all runtime paths, providers, binds, proof-key identities, and timeouts come from this file. |
| `TLCP_EXPECTED_GATEWAY_IMAGE_DIGEST` | Exact deployed OCI manifest digest; must equal the profile. |
| `TLCP_READINESS_SIGNING_CHAIN_FILE` | Dedicated probe client signing chain. |
| `TLCP_READINESS_SIGNING_KEY_REFERENCE` | Dedicated probe signing key reference. |
| `TLCP_READINESS_ENCRYPTION_CHAIN_FILE` | Dedicated probe client encryption chain. |
| `TLCP_READINESS_ENCRYPTION_KEY_REFERENCE` | Dedicated probe encryption key reference. |

Production private keys must be generated in, and remain inside, the selected
HSM/SDF/PKCS#11 boundary. `file` gateway-key references are deliberately
rejected when the profile uses `environment=production`. The readiness identity
is a separate least-privilege client identity and is never a proof signer.

Tengine uses one `ssl_ciphers` directive while constructing both its ordinary
TLS and NTLS contexts. The generated configuration therefore contains an RSA
suite as an ordinary-TLS initialization sentinel. It does not configure an
ordinary TLS server certificate, so standard TLS cannot complete a handshake.
The NTLS listener can negotiate only `ECDHE-SM2-SM4-GCM-SM3`; integration tests
require every other NTLS cipher and standard TLS to fail.

## Readiness

Do not use a listener-only TCP check. A gateway becomes ready only after a
credentialed probe has completed all of the following within the profile's
`startup` and `canary` bounds:

1. revalidate the profile, its exact image digest, generated configuration,
   runtime-manifest digest bindings, certificate roles/chains/SAN/current
   validity, CRL files and exact runtime bundle, provider references, mandatory
   proof-key separation, and public-key fingerprints;
2. complete TLCP mutual authentication and require `NTLSv1.1`;
3. require `ECDHE-SM2-SM4-GCM-SM3`;
4. call TrustDB's HTTP `/healthz` through the gateway;
5. call `grpc.health.v1.Health/Check` through HTTP/2 and require `SERVING`.

Failure of any step keeps the deployment unready. The probe credential is a
dedicated least-privilege client dual certificate; it is not a TrustDB
proof-signing key. The image declares
`/usr/local/bin/trustdb-tlcp-readiness` as its Docker health check. Configure
the same executable as the Kubernetes `readinessProbe.exec` command because
Kubernetes does not consume Docker image health checks.

Startup writes `/run/tlcp-gateway/runtime-manifest.json` and
`/run/tlcp-gateway/nginx.conf` with mode `0600`. The runtime manifest contains
only profile hashes, public fingerprints, expiry bounds, and build identity; it
never contains private material.

## Runtime resource bounds

The generated gateway configuration fixes the following public-edge limits:

- 10-second header and 30-second body/send timeouts;
- 5-second upstream connect and 30-second HTTP/gRPC upstream timeouts;
- 16 MiB maximum request body, matching TrustDB's batch transport bound;
- 15-second keepalive with at most 100 requests;
- at most 64 concurrent HTTP/2 streams and 32 connections per client address;
- 2,048 connections per worker and a 16,384 descriptor ceiling.

Set container CPU, memory, PID, and file-descriptor limits explicitly. Start
with `--cpus=2 --memory=1g --pids-limit=256 --ulimit nofile=16384:16384`, then
qualify different values with the concurrent handshake, HTTP/gRPC, slow-header,
and sustained-load gates for the target machine. Put a connection-aware L4
load balancer in front of an Internet-facing listener; per-address limits do
not stop a distributed handshake flood.

## Certificate and CRL rotation

Treat signing certificate/key, encryption certificate/key, server/client CA
files, every individually validated CRL, and the exact runtime CRL bundle as
one immutable generation. Never replace these files individually in the active
directory.

1. Enroll distinct non-exportable signing and encryption keys and issue both
   certificates with the same subject and SAN identity.
2. Write a new generation directory beside the active generation. Flush every
   file and the parent directory before it can be selected.
3. Validate the new generation's concrete, non-symlinked profile.
4. Start a candidate gateway on separate canary ports and run both readiness
   probes. The active gateway continues serving the previous generation.
5. Atomically replace the `active` relative symlink with the candidate
   generation using a sibling link plus `rename(2)`.
6. run `/usr/local/bin/tlcp-gateway-prepare-runtime` inside the active
   container; it stages the new runtime files, revalidates all public inputs,
   runs Tengine's full configuration/private-key check, and promotes the files
   only after that check succeeds;
7. send `SIGHUP` to the Tengine master and require the new server public-key
   fingerprint to appear within the profile's `reload` timeout;
8. repeat both live probes through the production ports, then retire the
   candidate and retain the previous generation for bounded rollback.

If validation or a candidate canary fails, do not change `active`. If reload or
post-switch canaries fail, atomically restore the previous link, regenerate the
previous runtime manifest/configuration with
`tlcp-gateway-prepare-runtime`, and reload it before declaring the incident
contained. A validation or Tengine configuration failure does not replace
either active runtime file. Never delete the previous generation until the
rollback window and active-connection lifetime have elapsed.

For emergency client revocation, build and sign a complete replacement CRL
bundle, stage it in a new generation, and follow the same process. A revoked
client may keep an already-established connection until that connection
closes; it must fail every new HTTP and gRPC handshake.

## Build and verification

Build either supported Linux gateway architecture with the reproducibility
gate:

```sh
PLATFORM=linux/amd64 packaging/tlcp-gateway/build.sh
PLATFORM=linux/arm64 packaging/tlcp-gateway/build.sh
```

Each build performs two clean builds and requires byte-identical OCI archives.
It also emits and verifies a canonical SPDX SBOM and a build record that binds
the source, base image, frontend, image, manifest, layers, and scanner.

Run the real gateway test on a Linux or Docker Desktop host:

```sh
go test -count=1 -mod=readonly -tags="integration tlcp" \
  -run TestTLCPGatewayHTTPAndGRPCMutualAuthentication \
  ./internal/tlcpe2e
```

The test executes real HTTP and HTTP/2 gRPC through Tengine/Tongsuo and covers
missing client credentials, wrong CA, wrong cipher, standard TLS, mismatched or
missing encryption material, expiry, CRL revocation, failed candidate
retention, dual canaries, atomic certificate/CA/CRL generation switch,
post-switch rollback, credentialed readiness, concurrent HTTP/gRPC, slow-header
termination, and bounded reload.
Windows and macOS remain supported developer platforms for the profile
validator and test compilation; the production gateway runtime is Linux.

Passing these engineering checks demonstrates the stated interoperability and
fail-closed controls. Product qualification, key ceremonies, deployment
assessment, and regulatory conclusions remain tied to the exact deployed
gateway, provider, CA, and operating environment.
