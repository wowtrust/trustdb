# TLCP gateway profile v1

`trustdb.tlcp-gateway-profile.v1` is a versioned deployment contract for a
qualified external TLCP gateway. It is not a TrustDB proof format, a private-key
container, or a claim that an unqualified SM implementation satisfies a
regulatory requirement.

The reference profile pins Tengine `2.3.4` at commit
`698e1798e8d691c55b5405ca1526c3dca4759d47` and Tongsuo `8.4.0` at commit
`a8ae0925d26de3b449f7a21767910cd41291bcd8`. Source archives, builder and
runtime base images, build arguments, the produced gateway image, SBOM, and
build record are all independently SHA-256 pinned.

The exact production build inputs are recorded in
[`packaging/tlcp-gateway/baseline.json`](../packaging/tlcp-gateway/baseline.json).
The Tengine archive SHA-256 is
`9a8d1e83ec7664f799255b0dec5baebde2d12b6578b29cfadf92316b3d3e221c`;
the Tongsuo archive SHA-256 is
`57c2741750a699bfbdaa1bbe44a5733e9c8fc65d086c210151cfbc2bbd6fc975`.
Both Tengine stages use the exact Debian manifest-list digest recorded in that
baseline. The embedded runtime validator/readiness tools use the separately
pinned Go builder image, a minimal checksummed module graph, and deterministic
CGO-disabled flags. The
`gateway_image_digest`, `sbom_sha256`, and
`build_record_sha256` fields identify outputs of a particular reproducible
build and therefore are not hard-coded global constants.

## Trust boundary

The gateway terminates TLCP mutual authentication and forwards HTTP and gRPC
inside one restricted network namespace. TrustDB binds only loopback upstreams.
Only the gateway binds externally. The namespace admits `trustdb`, one active
`tlcp-gateway`, and at most one short-lived `tlcp-gateway-candidate` during a
bounded rotation. It does not use host networking and never admits a debug or
general-purpose utility container. The candidate is removed after promotion or
failure.

Gateway signing and encryption private keys are gateway inputs. Production
profiles use opaque `engine`, `pkcs11`, or `sdf` references. `file` references
are accepted only when `environment=test`; the reference validator never opens
them. The gateway entrypoint may read test-only software keys to perform
certificate/key matching. TrustDB does not mount or read either gateway private
key.

Every production reference uses `engine:<id>:<key-id>`. For the `pkcs11` and
`sdf` providers, `<id>` must respectively be `pkcs11` or `sdf`; `<key-id>` is
an opaque provider identifier, not a filesystem path or private-key value.

Proof-signing keys remain under TrustDB's existing `keys.*` and
`crypto.signer_plugins.*` configuration. Every production profile contains a
non-empty `proof_key_descriptor_files` array naming the canonical public
verifier descriptors selected by the same generation as the active TrustDB
configuration. The gateway reads those real CBOR descriptors, requires
`trustdb.key-descriptor.v1`, `kind=verifier`, and `provider=public`, rejects
every private provider union, and computes normalized SPKI fingerprints itself.
The runtime manifest binds both canonical descriptor bytes and computed public
keys. Production validation fails when the array is absent, duplicated,
malformed, changed, or overlaps either gateway key. Optional `--forbid-*` flags
can add rollout-time identities but do not replace the mandatory files.
Gateway certificates, CAs, CRLs, keys, and readiness results never become
proof trust roots. Proof, WAL, proofstore, backup, and offline verification
bytes are unchanged.

## Strict JSON envelope

The profile is UTF-8 JSON with a maximum encoded size of 128 KiB. Unknown
fields, duplicate object keys, trailing values, excessive nesting, oversized
collections, empty strings, surrounding whitespace in scalar values, control
characters, dirty paths, relative paths, symlinked files, and files that change
while being read are rejected.

The complete field shape is represented by
[`test/vectors/tlcp-gateway-profile-v1.json`](../test/vectors/tlcp-gateway-profile-v1.json).
`${FIXTURE_DIR}` is a test-only placeholder replaced with an absolute temporary
directory by the golden tests. Repeated-digit artifact digests in that
test-environment vector exercise schema shape only; they are not production
pins or published build outputs.

The following values are exact:

- `schema_version`: `trustdb.tlcp-gateway-profile.v1`
- `mode`: `tlcp_mtls`
- `crypto_mode`: `guomi`
- `cipher_suites`: `[ECDHE-SM2-SM4-GCM-SM3]`
- `alpn_protocols`: `[h2, http/1.1]`, in that order
- `revocation.mode`: `crl`
- `revocation.gateway_crl_bundle_file`: one runtime PEM bundle containing
  exactly the CRLs named by `revocation.crl_files`

The reference v1 rejects `ocsp` rather than treating a generic network check as
verified revocation. A later qualified gateway adapter may define a new
versioned mode only if it verifies responder identity, response signature,
certificate binding, status, `thisUpdate`/`nextUpdate`, maximum age, replay,
timeout, and unavailable-responder behavior. It must fail closed and retain the
last known-good gateway generation on refresh failure.

## Dual-certificate rules

All parsing and verification use the pinned `emmansun/gmsm/smx509` SM-aware
implementation. The validator does not ask Go's standard `crypto/x509` package
to infer SM2 semantics.

The server signing and encryption inputs are separate, strict, leaf-first PEM
chains. Their leaf certificates:

- use `sm2p256v1` public keys and `SM2-with-SM3` signatures;
- are different certificates with different public keys;
- have byte-identical DER subjects;
- have identical normalized DNS, IP, email, and URI SAN sets;
- both cover `server_name`;
- are end-entity certificates with exactly the `serverAuth` EKU and no unknown
  EKU;
- use distinct roles:
  - signing requires `digitalSignature` and forbids encipherment, key agreement,
    CA signing, and CRL signing;
  - encryption requires at least one encipherment/agreement usage and forbids
    digital/content commitment, CA signing, and CRL signing.

Every intermediate is a current SM2/SM3 CA, has a subject key identifier,
appears in issue order, and signs the preceding certificate. Every child
certificate has an authority key identifier that exactly matches its issuer.
The final certificate in each explicit chain links directly to exactly one
configured trust anchor. Trust anchors are supplied separately in
`server_ca_file` and `client_ca_file`; each is a current, self-signed SM2/SM3
CA authorized for both certificate and CRL signing and has a subject key
identifier.

## CRL rules

Every distinct server issuing CA (including an intermediate) and client trust
anchor has exactly one configured CRL. Client certificates in the v1 profile
are issued directly by a configured client trust anchor. Each CRL:

- is one strict `X509 CRL` PEM block within the 4 MiB bound;
- is signed with SM2/SM3 by the matching configured CA;
- has an unambiguous issuer and a mandatory matching authority key identifier;
- has `thisUpdate <= now < nextUpdate`;
- is no older than `max_staleness`, which cannot exceed 168 hours;
- contains only positive, unique certificate serial numbers;
- does not revoke either configured server certificate.

The gateway bundle contains the exact same CRL DER objects as the individually
validated files; missing, extra, duplicate, or substituted CRLs fail before
startup. The gateway applies that validated bundle during every new TLCP
handshake.

## Network and readiness

`trustdb_http_upstream` and `trustdb_grpc_upstream` are distinct loopback IP
address/port pairs using exactly `127.0.0.1`. `gateway_http_bind` and
`gateway_grpc_bind` are distinct non-loopback IP address/port pairs. All four
addresses are explicit and use non-zero ports. All four ports are different
because the two processes share one network namespace and an unspecified
gateway bind must not overlap a TrustDB loopback listener.

The container entrypoint requires `TLCP_PROFILE_FILE` and
`TLCP_EXPECTED_GATEWAY_IMAGE_DIGEST`. It validates the profile and current
public trust material, renders Nginx configuration only from that profile, and
writes a canonical `trustdb.tlcp-gateway-runtime-manifest.v1` binding the raw
profile, rendered configuration, deployed image digest, certificate/public-key
fingerprints, CA fingerprints, proof-key separation, CRL bundle, and expiry
bounds. Runtime preparation and `nginx -t` run through the entrypoint's
`startup` deadline. Any validation failure or timeout exits before Tengine
starts.

The shipped readiness executable revalidates that manifest and every
referenced public input on each probe, then performs, within the configured
canary timeout:

1. a real TLCP mutual-authentication handshake;
2. an exact `NTLSv1.1` and cipher check;
3. a proxied HTTP `/healthz` request;
4. a proxied gRPC HTTP/2 health RPC.

It uses a dedicated least-privilege client dual certificate supplied through
the four `TLCP_READINESS_*` variables. Missing credentials, profile/path
drift, expiry, revocation, an unavailable upstream, or a protocol/cipher
mismatch keeps the container unhealthy. Kubernetes and similar systems must
configure `/usr/local/bin/trustdb-tlcp-readiness` as the readiness command
instead of using a TCP probe and set the outer `timeoutSeconds` to the
whole-second ceiling of `timeouts.canary`. The executable enforces the exact
duration itself. Rotation invokes `tlcp-gateway-prepare-runtime reload`, whose
outer controller deadline comes from `timeouts.reload`.

The generated runtime sets explicit 10-second header, 30-second body/send and
upstream bounds, a tested 16 MiB request ceiling, 15-second/100-request
keepalive limits, configured ceilings of 64 HTTP/2 streams and 32 connections
per client address, and 2,048 connections per worker. The request-body gate
accepts exactly 16 MiB and rejects the next byte. Effective stream and
connection admission remains deployment-qualified because it depends on the
exact Tengine build, client reuse, and L4 topology. Deployment CPU, memory,
PID, file-descriptor, and restart limits remain mandatory.

## Rotation

Signing certificate/reference, encryption certificate/reference, server and
client CA files, readiness signing/encryption identities, authoritative public
proof descriptors, every CRL, and the exact gateway CRL bundle form one
generation. Operators stage a complete generation, run profile validation and
both live canaries in the one admitted candidate, atomically switch the
generation, invoke the image's `tlcp-gateway-prepare-runtime` helper, and
request a bounded reload with `tlcp-gateway-prepare-runtime reload`. The helper
stages the new manifest/configuration,
performs Tengine's private-key and configuration check, and promotes both files
only after that check succeeds. If regeneration, reload, or either post-switch
canary fails, the controller restores the prior generation, prepares its
manifest/configuration, and reloads it. Existing workers retain the last loaded
generation until a valid replacement is ready.

Private-key enrollment, generation, backup, deletion, and audit are provider
responsibilities. Enrollment issues separate signing and encryption CSRs from
separate non-exportable keys and gives both certificates the same subject and
SAN identity with the exact roles above.
