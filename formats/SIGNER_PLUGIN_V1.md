# TrustDB Signer Plugin v1

Status: implemented; tracked by [#552](https://github.com/wowtrust/trustdb/issues/552).

`trustdb.signer-plugin.v1` is the subprocess boundary for non-exportable
private-key operations. It lets a deployment adapt an existing `remote`,
`pkcs11`, or `sdf` key descriptor without linking vendor code into TrustDB.

The plugin is not a cryptographic-suite extension point. TrustDB remains the
sole authority for suite availability, hashing, canonical encoding, domain
separation, signature input, Merkle profiles, signature encoding validation,
and public verification. A plugin receives only final message bytes and may
return only a signature made by the descriptor-bound key.

## Process and transport

- Plugins are independent executables supervised by the TrustDB process.
- The host creates a random 32-byte cookie and passes the protocol version and
  cookie through dedicated environment variables.
- The child inherits no ambient application environment by default. Operators
  may explicitly allow individual variable names; protocol and cookie
  variables are reserved case-insensitively and cannot be overridden. Go adds
  the platform-required `SYSTEMROOT` bootstrap variable on Windows.
- The plugin listens on a random loopback TCP address and writes exactly one
  bounded JSON handshake line to stdout. All plugin diagnostics use stderr.
- RPC uses gRPC with canonical CBOR, strict unknown-field rejection, bounded
  messages, per-call deadlines, and cookie authentication on every request.
- A non-loopback address, malformed or oversized handshake, wrong cookie,
  incompatible protocol, or early process exit fails startup.

The RPC surface is deliberately narrow:

| RPC | Purpose |
| --- | --- |
| `GetInfo` | Bind protocol, stable plugin ID, provider kind, capabilities, immutable algorithm profiles, and concurrency limit. |
| `Health` | Confirm that the configured provider is ready before key use. |
| `GetPublicKey` | Resolve one existing provider reference and return its public key. |
| `Sign` | Sign final host-generated message bytes with the selected existing key. |

There is no generate, import, export, delete, hash, prehash, verify, framing,
or suite-registration RPC.

## Exact binding

Every `GetPublicKey` and `Sign` request carries a `Key` containing an exact
binding with these fields:

- protocol version and stable plugin ID;
- provider kind (`remote`, `pkcs11`, or `sdf`);
- crypto suite and signature algorithm;
- public-key and signature encodings;
- key ID and suite-defined SM2 user ID;

The request `Key` also contains the matching non-secret provider reference from
`trustdb.key-descriptor.v1`. The unary response echoes the exact `Binding` and
returns only the public key or signature output; it does not repeat the provider
reference. The response is correlated with the reference by its originating
unary request.

The host derives this binding from a fully validated key descriptor. Empty or
unknown values never select defaults. The plugin may advertise support, but it
cannot choose a suite or algorithm. Startup and every process restart repeat
the identity, capability, health, and public-key checks. Any difference from
the descriptor or the first accepted process identity fails closed.

## Signature acceptance

The plugin response contains signature bytes plus the exact binding. Before a
signature can enter a receipt, key event, Signed Tree Head, WAL-derived result,
or proof, the host:

1. checks the response binding byte-for-byte;
2. validates the suite-defined signature encoding and size;
3. constructs the signature metadata from the fixed descriptor; and
4. verifies the signature with TrustDB's built-in verifier and the public key
   stored in the descriptor.

A correct-length random signature, a signature from another key, a replay for
another message, double hashing, or different domain framing therefore fails
locally. TrustDB never falls back to a software key, another plugin, another
algorithm, or the default suite.

For WAL-bound accepted receipts, the host reserves each exact WAL position in
FIFO order before calling `Sign`. Reservations may prepare concurrently, but
successful records are published only in reservation order. If a predecessor
fails, its successors are canceled and return an explicit retryable
reservation error; TrustDB does not automatically bind or sign them again for
a different position. No unsigned claim or position gap is written to the WAL.
An external device that completes a successor operation before cancellation
may retain an audit entry for a signature that the host discards and never
returns or persists; this is limited to a failure cascade, not normal
concurrent publication.

## Lifecycle and failures

- One configured provider supervisor may serve multiple immutable signer
  adapters of the same provider kind.
- Effective signing concurrency is the lower non-zero value of the host limit
  and the plugin-advertised limit. Waiting for capacity obeys cancellation.
- Each RPC has an internal deadline even when the caller uses a background
  context.
- A failed `Sign` call is not automatically retried. A transient transport or
  child-process failure invalidates the child; a later call may start a new
  child and must repeat all bindings.
- Permanent provider errors, identity drift, public-key drift, or an invalid
  signature do not trigger fallback.
- Resolver shutdown closes the gRPC connection and then terminates the child.
  Where `os.Interrupt` is supported, the host sends it and waits for a bounded
  shutdown interval (two seconds by default); a signaling failure or timeout
  causes a force kill. Protocol v1 has no shutdown RPC. On Windows,
  `os.Interrupt` is not implemented by Go, so the current host force-terminates
  the child immediately. Plugins should handle interrupt by canceling their
  `Serve` context where the platform supports it, and provider operations must
  remain safe under abrupt termination. Commands and the long-running server
  own the resolver for its complete lifetime.

Plugin errors exposed by the host are classified and sanitized. Private key
material is never sent across the protocol. Provider URIs, endpoints, handles,
credential references, cookies, and message bytes must not be copied into
errors or structured logs.

The executable is part of the deployment trusted computing base and runs with
the TrustDB process's OS privileges. This protocol isolates lifecycle and
language/runtime dependencies; it is not a filesystem, network, or syscall
sandbox. Credentials must not be passed in command-line arguments, which may
be visible in process listings.

## Compatibility

The protocol reuses the provider union already defined by
`trustdb.key-descriptor.v1`; it does not add `provider=plugin` or alter the
descriptor schema. Evidence, API, WAL, proofstore, backup, and `.sproof`
formats are unchanged. Offline verification never starts a signer plugin and
requires only the existing public trust material.

The repository's production PKCS#11 implementation of this protocol is
documented in
[`docs/integrations/PKCS11_SIGNER.md`](../docs/integrations/PKCS11_SIGNER.md).
Its native Cryptoki dependency is confined to a build-tagged standalone
sidecar and is not linked into TrustDB core.
