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
  --profile /etc/trustdb/tlcp/profile.json \
  --forbid-key-ref /etc/trustdb/keys/server.json \
  --forbid-public-key-sha256 "$TRUSTDB_PROOF_KEY_SHA256"
```

The two `--forbid-*` checks make accidental reuse of a TrustDB proof-signing
key fail closed. Repeat them for every active proof-signing key.

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
attach a debug container to the namespace. The reference container runs as
UID/GID `10001`, drops every Linux capability, uses a read-only root
filesystem, and needs writable tmpfs mounts only for:

- `/run/tlcp-gateway`;
- `/var/cache/tlcp-gateway`.

Mount certificates, CA bundles, CRLs, and provider configuration read-only.
TrustDB must not receive either gateway private-key mount.

## Required gateway inputs

| Environment variable | Meaning |
| --- | --- |
| `TLCP_ENVIRONMENT` | `production` or `test`; software key files are test-only. |
| `TLCP_SERVER_NAME` | Exact server DNS name present in both certificate SAN sets. |
| `TLCP_SERVER_SIGNING_CHAIN_FILE` | Leaf-first SM2/SM3 signing chain. |
| `TLCP_SERVER_ENCRYPTION_CHAIN_FILE` | Leaf-first SM2/SM3 encryption chain. |
| `TLCP_CLIENT_CA_FILE` | Client trust anchors. |
| `TLCP_CRL_BUNDLE_FILE` | Current CRL for every required issuer. |
| `TLCP_SIGNING_KEY_PROVIDER` | `engine`, `pkcs11`, or `sdf` in production; `file` in tests. |
| `TLCP_SIGNING_KEY_REFERENCE` | Opaque `engine:<id>:<key-id>` production reference. |
| `TLCP_SIGNING_PUBLIC_KEY_SHA256` | Canonical DER public-key SHA-256 matching the signing certificate. |
| `TLCP_ENCRYPTION_KEY_PROVIDER` | Provider for the distinct encryption key. |
| `TLCP_ENCRYPTION_KEY_REFERENCE` | Distinct opaque production reference. |
| `TLCP_ENCRYPTION_PUBLIC_KEY_SHA256` | Canonical DER public-key SHA-256 matching the encryption certificate. |
| `TLCP_GATEWAY_HTTP_BIND` | External HTTP listener, normally `0.0.0.0:8443`. |
| `TLCP_GATEWAY_GRPC_BIND` | External gRPC listener, normally `0.0.0.0:9443`. |
| `TLCP_TRUSTDB_HTTP_UPSTREAM` | Loopback-only TrustDB HTTP listener. |
| `TLCP_TRUSTDB_GRPC_UPSTREAM` | Loopback-only TrustDB gRPC listener. |

Production private keys must be generated in, and remain inside, the selected
HSM/SDF/PKCS#11 boundary. `file` is deliberately rejected when
`TLCP_ENVIRONMENT=production`.

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

1. validate the profile, certificate roles, chains, current validity, CRLs,
   provider references, and public-key fingerprints;
2. complete TLCP mutual authentication and require `NTLSv1.1`;
3. require `ECDHE-SM2-SM4-GCM-SM3`;
4. call TrustDB's HTTP `/health` through the gateway;
5. call `grpc.health.v1.Health/Check` through HTTP/2 and require `SERVING`.

Failure of any step keeps the deployment unready. The probe credential is a
dedicated least-privilege client dual certificate; it is not a TrustDB
proof-signing key.

## Certificate and CRL rotation

Treat signing certificate/key, encryption certificate/key, CA bundles, and
CRLs as one immutable generation. Never replace these files individually in
the active directory.

1. Enroll distinct non-exportable signing and encryption keys and issue both
   certificates with the same subject and SAN identity.
2. Write a new generation directory beside the active generation. Flush every
   file and the parent directory before it can be selected.
3. Validate the new generation's concrete, non-symlinked profile.
4. Start a candidate gateway on separate canary ports and run both readiness
   probes. The active gateway continues serving the previous generation.
5. Atomically replace the `active` relative symlink with the candidate
   generation using a sibling link plus `rename(2)`.
6. send `SIGHUP` to the Tengine master and require the new server public-key
   fingerprint to appear within the profile's `reload` timeout;
7. repeat both live probes through the production ports, then retire the
   candidate and retain the previous generation for bounded rollback.

If validation or a candidate canary fails, do not change `active`. If reload or
post-switch canaries fail, atomically restore the previous link and reload it
before declaring the incident contained. Never delete the previous generation
until the rollback window and active-connection lifetime have elapsed.

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
retention, dual canaries, atomic generation switch, and bounded reload.
Windows and macOS remain supported developer platforms for the profile
validator and test compilation; the production gateway runtime is Linux.

Passing these engineering checks demonstrates the stated interoperability and
fail-closed controls. Product qualification, key ceremonies, deployment
assessment, and regulatory conclusions remain tied to the exact deployed
gateway, provider, CA, and operating environment.
