# PKCS#11 signing provider

TrustDB can keep receipt, registry, STH, and other signing keys inside a
PKCS#11 token. The production adapter is the standalone
`trustdb-signer-pkcs11` process. TrustDB core never links the vendor module,
receives a private key, reads a private-key attribute, or falls back to a
software signer.

```text
TrustDB core
  -> authenticated signer-plugin v1 over loopback gRPC
    -> trustdb-signer-pkcs11
      -> vendor PKCS#11 module
        -> non-exportable private key
```

The core builds the final suite-bound message, selects the exact descriptor,
and verifies every returned signature locally against the descriptor's pinned
public key before evidence can be persisted. The sidecar performs only token
discovery, login, exact key lookup, public material retrieval, and signing.

## Build

The native adapter requires CGO and the explicit `pkcs11` build tag:

```bash
CGO_ENABLED=1 go build -trimpath -tags=pkcs11 \
  -o trustdb-signer-pkcs11 ./cmd/trustdb-signer-pkcs11
```

An ordinary `go build ./...` does not link the Cryptoki wrapper or a vendor
library into the TrustDB server. A build without the tag produces only a
diagnostic sidecar stub.

The repository's PKCS11 Provider workflow builds the Linux amd64 sidecar and
runs the complete supervised path against SoftHSM 2.6.1 on Ubuntu 24.04. The
portable contract and non-native stub are also tested on macOS and Windows;
macOS additionally compiles the native adapter. A production Windows or macOS
deployment still needs the selected vendor's DLL or dylib and its supported
CGO toolchain.

Mechanism constants and behavior are interpreted according to the
[OASIS PKCS#11 v3.1 specification](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html).

## Token and key preparation

Generate or import the private key through the token's controlled ceremony.
Do not use TrustDB to export, copy, back up, or destroy it. Give the related
private key, public key, and optional X.509 certificate the same `CKA_ID`.

Create a canonical signer descriptor whose provider is `pkcs11`. The URI
must identify one private object and may use both an object label and binary
ID:

```text
pkcs11:id=%01;object=receipt-key;serial=0123456789ABCDEF;token=trustdb;type=private
```

Attributes are lower-case and sorted. `type`, when present, must be `private`.
The descriptor validator and sidecar both reject duplicate attributes, query
parameters, fragments, `pin-value`, and `pin-source`.

The descriptor's public key and optional certificate chain are immutable
verification material. They are not discovered and trusted on demand. During
resolution the sidecar reads the related public object and certificate, checks
that they agree, and returns only the public key. TrustDB then compares it
byte-for-byte with the descriptor.

## Sidecar configuration

The sidecar accepts no command-line configuration. All variables must be
listed explicitly in `crypto.signer_plugins.pkcs11.inherit_env`, because the
supervisor removes the ambient environment:

```yaml
crypto:
  signer_plugins:
    pkcs11:
      command: "/usr/local/libexec/trustdb-signer-pkcs11"
      args: []
      inherit_env:
        - "TRUSTDB_PKCS11_MODULE"
        - "TRUSTDB_PKCS11_TOKEN_URI"
        - "TRUSTDB_PKCS11_PIN_FILE"
        - "TRUSTDB_PKCS11_PLUGIN_ID"
        - "TRUSTDB_PKCS11_ALGORITHMS"
        - "TRUSTDB_PKCS11_MAX_CONCURRENCY"
        - "TRUSTDB_PKCS11_EDDSA_MECHANISM"
        - "TRUSTDB_PKCS11_SM2_MECHANISM"
        - "TRUSTDB_PKCS11_SM2_SIGNATURE_FORMAT"
        - "TRUSTDB_PKCS11_SM2_PARAMETER_HEX"
      start_timeout: "10s"
      rpc_timeout: "30s"
      max_concurrency: 16
```

| Variable | Meaning |
| --- | --- |
| `TRUSTDB_PKCS11_MODULE` | Absolute or loader-supported path to the selected PKCS#11 module. |
| `TRUSTDB_PKCS11_TOKEN_URI` | Canonical token-only URI. It must contain `token` or `serial` and cannot select an object. |
| `TRUSTDB_PKCS11_PIN_FILE` | Owner-only regular file containing the user PIN. |
| `TRUSTDB_PKCS11_PLUGIN_ID` | Optional stable process identity; default `trustdb.pkcs11.v1`. |
| `TRUSTDB_PKCS11_ALGORITHMS` | Explicit comma-separated `INTL_V1`, `CN_SM_V1`, or both. |
| `TRUSTDB_PKCS11_MAX_CONCURRENCY` | Token-side concurrency limit, 1–1024; default 16. |
| `TRUSTDB_PKCS11_EDDSA_MECHANISM` | Optional numeric EdDSA mechanism; default standard `CKM_EDDSA` (`0x1057`). |
| `TRUSTDB_PKCS11_SM2_MECHANISM` | Required numeric vendor mechanism when `CN_SM_V1` is enabled. |
| `TRUSTDB_PKCS11_SM2_SIGNATURE_FORMAT` | Required `raw` (`r || s`) or canonical `der`. |
| `TRUSTDB_PKCS11_SM2_PARAMETER_HEX` | Optional, bounded, exact vendor mechanism parameter bytes. |

`TRUSTDB_PKCS11_PIN_FILE` is the only supported PIN source. The file must be
regular, not a symlink, and must not grant group or other permissions on Unix.
The PIN is read immediately before login and cleared from mutable Go buffers
after the Cryptoki call. The C/Go wrapper may create short-lived runtime copies,
so the sidecar process and PIN file still require OS-level protection. There is
deliberately no inline PIN environment variable, URI attribute, YAML field, or
command argument.

The child receives no ambient environment. If a module such as SoftHSM needs
an additional non-secret configuration variable, add that exact variable name
to `inherit_env`; never expose the entire parent environment.

Windows PIN-file loading currently fails closed until TrustDB continuously
runtime-qualifies an owner-only DACL policy. This is why release packages do
not yet bundle the native Windows sidecar; the portable provider contract and
diagnostic stub are still built and tested on Windows.

Do not add module paths, token URIs, object URIs, PIN file paths, PIN values, or
provider handles to application logs. The adapter maps native failures to
fixed retryable or permanent signer-plugin errors and never forwards raw CKR
diagnostics.

## Algorithm profiles

### INTL_V1

The default interoperability profile uses PKCS#11 v3 `CKM_EDDSA` (`0x1057`)
with an Ed25519 key. The token receives the exact final TrustDB message and
must return a 64-byte RFC 8032 signature. Mechanism parameters are forbidden.

The automated interoperability target is:

- Ubuntu 24.04;
- [SoftHSM 2.6.1](https://github.com/softhsm/SoftHSMv2/releases/tag/2.6.1);
- OpenSC `pkcs11-tool`;
- an Ed25519 key generated as `EC:edwards25519`;
- `CKM_EDDSA`.

This target verifies adapter interoperability; SoftHSM is a software test
token and is not a production HSM or a Chinese commercial-cryptography
certification claim.

### CN_SM_V1

PKCS#11 does not provide one portable SM2 mechanism contract across deployed
vendor modules. TrustDB therefore refuses to infer SM2 support from an EC key,
mechanism name, signature length, public key, or module endpoint.

Enabling `CN_SM_V1` requires an explicit vendor mechanism number and output
format. The configured mechanism must:

1. accept the complete TrustDB message bytes;
2. perform SM2 with SM3 and the fixed user ID `1234567812345678`;
3. avoid adding another TrustDB application domain or prehash;
4. return either 64-byte `r || s` or strict ASN.1 DER as configured.

At startup the adapter discovers exactly one configured token and requires
every configured mechanism to advertise `CKF_SIGN`. Missing SM support fails
startup before evidence generation. A vendor profile that ignores the fixed
user ID, expects a digest, applies a second hash, or returns a different
signature format will also fail the core's mandatory local SM2 verification.

Before production use, record the module version, mechanism values and
parameters, token firmware, key attributes, concurrency limit, restart
behavior, PIN policy, certificate mapping, SM2 user-ID behavior, known CKR
codes, and a signed interoperability result for the exact purchased product.

## Sessions, failure, and rotation

- Every public-key or signing operation opens an isolated serial session,
  logs in, resolves exactly one private object, and closes the session.
- Token removal, device/session loss, and unavailable modules are retryable
  for a later host operation. `Sign` itself is never replayed automatically,
  because a timeout or session failure may happen after a randomized external
  signature was produced.
- Bad PIN, locked/expired PIN, missing key, unsupported mechanism, ambiguous
  object selection, permission denial, and identity drift are permanent for
  the current configuration.
- Token identity is captured at startup and checked again for every operation.
  Replacing a token behind a weak selector fails closed.
- A public key accepted for one object URI cannot change during the process
  lifetime. Reusing the URI for a different key is rejected before signing.
- Rotate by provisioning a new token object with a new `CKA_ID` or label,
  publishing a new canonical descriptor/key-registry event, updating the
  intended role, and restarting the resolver. Historical evidence continues
  to verify with its historical public descriptor.

Linux sends SIGTERM during normal service/container shutdown. The sidecar
handles SIGTERM and SIGINT, stops gRPC, closes sessions, and finalizes the
module. Windows supports the supervisor's bounded force-termination path, so
vendor modules must also tolerate abrupt process exit.

## Qualification checklist

Before using a hardware token for production evidence:

- verify the exact module, firmware, operating system, CPU architecture, and
  mechanism profile;
- confirm the signing key is private, sensitive, always sensitive,
  non-extractable, never extractable, and restricted to signing; the adapter
  checks these standard attributes before every use;
- run concurrent signing at the configured cap and test session exhaustion;
- remove and reinsert the token, restart the sidecar, and confirm public-key
  rebind behavior;
- exercise wrong, expired, and locked PINs without disclosing their values;
- rotate to a new object URI and confirm the old URI cannot silently change;
- retain the device certificate, key ceremony, configuration checksum,
  interoperability output, and operator approvals as deployment evidence.

Offline proof verification never loads this sidecar, the vendor module, or a
token. It uses only evidence bytes and verifier-local trust roots.
