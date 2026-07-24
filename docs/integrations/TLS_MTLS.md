# TLS and mutual TLS transport security

TrustDB supports TLS 1.2 and TLS 1.3 on the HTTP and gRPC listeners. The same
listener policy is used by both protocols, including mutual TLS, CA pinning,
certificate reload, and revocation checks.

Transport trust is a separate trust boundary from proof trust:

- `server.transport.*`, `sdk.TLSConfig`, and desktop TLS settings authenticate
  network peers.
- `keys.server_*`, the client key registry, `sdk.TrustedKeys`, and proof-format
  suite markers authenticate claims, receipts, and evidence.
- A TLS certificate must never be substituted for a proof-signing key, and a
  proof-signing public key must never be loaded into a TLS CA pool.

## Server configuration

```yaml
run_profile: single_node_production
server:
  listen: "0.0.0.0:8080"
  grpc_listen: "0.0.0.0:9090"
  transport:
    mode: "mtls"                 # plaintext | tls | mtls
    allow_local_plaintext: false
    cert_file: "/etc/trustdb/tls/server.crt"
    key_file: "/etc/trustdb/tls/server.key"
    client_ca_file: "/etc/trustdb/tls/client-ca.crt"
    client_ca_pins_sha256: []    # SHA-256 of CA certificate DER
    min_version: "1.2"           # 1.2 or 1.3
    max_version: ""              # empty allows the latest supported version
    reload_interval: "1m"
    revocation:
      mode: "serial_denylist"    # off | serial_denylist
      serial_file: "/etc/trustdb/tls/revoked-client-serials.txt"
```

`tls` authenticates the server to clients. `mtls` additionally requires each
client to chain to `client_ca_file`. Optional CA pins constrain accepted
verified chains to the exact configured CA certificate fingerprints.

The production profile refuses a plaintext listener. A narrowly scoped
single-host deployment may set `allow_local_plaintext: true`, but every active
HTTP and gRPC listener must then be an explicit loopback TCP address such as
`127.0.0.1:8080` or `[::1]:9090`. Wildcard, private-network, public, and
unparseable addresses remain rejected. The general default is `false`, so
changing only `run_profile` never silently enables the exception.

## Rotation and revocation

TrustDB loads the certificate/key pair, CA pool, CA pins, and serial denylist as
one immutable snapshot. Every new TLS handshake receives the latest snapshot.
An invalid, mismatched, not-yet-valid, or expired replacement fails reload and
the last known-good snapshot remains active. Established HTTP keep-alives,
gRPC connections, durable ingest, and evidence verification are not restarted.

Endpoint certificate files must contain an ordered PEM chain: the end-entity
certificate followed by every issuing intermediate through at least one CA
trust anchor. Every certificate and CA is parsed strictly, checked for current
validity, CA constraints, key usage, and chain linkage before publication.
Malformed or trailing PEM data is rejected. A self-signed root may be included
for validation and is omitted automatically from the TLS wire chain.

Replace files atomically (write a sibling file, `fsync`, then rename). They are
checked at `reload_interval`. Close idle HTTP connections, or recycle a gRPC
connection, when a new certificate must take effect immediately instead of
waiting for ordinary connection turnover.

The built-in denylist contains one hexadecimal certificate serial number per
line; blank lines and `#` comments are ignored. Reload is fail-closed: when the
configured denylist cannot be parsed, the active policy is not replaced.
`transporttls.CertificateRevocationChecker` is the hook for deployment-specific
OCSP, CRL, or equivalent policy after normal chain and hostname verification.

## Go SDK

```go
client, err := sdk.NewClient("https://trustdb.example:8080",
    sdk.WithTLSConfig(sdk.TLSConfig{
        CAFile:         "/etc/myapp/trustdb-ca.crt",
        CAPinsSHA256:   []string{"0123...64 hex characters..."},
        CertFile:       "/etc/myapp/client.crt", // omit both for server-only TLS
        KeyFile:        "/etc/myapp/client.key",
        ServerName:     "trustdb.example",       // optional verifier override
        MinVersion:     "1.2",
        ReloadInterval: "1m",
    }),
)
```

Use `sdk.WithGRPCTLSConfig` with the same `sdk.TLSConfig` for gRPC. Remote gRPC
targets and loopback targets both default to system-root TLS 1.2+. A local
plaintext development endpoint must be selected explicitly with
`sdk.WithGRPCLocalPlaintext`, which rejects non-loopback targets. Plain HTTP SDK
URLs are accepted only for loopback hosts.

Reloadable HTTP TLS configuration rejects HTTP and HTTPS proxies. Go performs
the target TLS handshake after an HTTP proxy `CONNECT` outside the custom
reloadable dialer, so accepting a proxy would bypass CA pins, mTLS credentials,
revocation, and certificate reload policy. Use a direct connection or a
policy-aware transport supplied by the application instead.

`CheckHealth` traverses the configured TLS/mTLS connection and reports
`TransportSecurity`, `TLSVersion`, and whether the server authenticated a
client certificate. A successful health result therefore also proves that CA,
hostname, protocol-version, client-certificate, pin, and revocation policy
accepted the connection.

## Identity input for RBAC and audit

For an authenticated client certificate, HTTP middleware and gRPC interceptors
place `transporttls.PeerIdentity` in the request context. Future RBAC and audit
layers can read it with `transporttls.PeerIdentityFromContext`. It includes the
verified subject, common name, serial, certificate SHA-256 fingerprint, SANs,
and TLS version. This does not grant permissions or equate certificate identity
with the tenant/client identity signed inside a claim.

## Container health checks

The container profile is mTLS by default and expects `/etc/trustdb/tls` to be a
read-only secret mount. Its health check uses a dedicated least-privilege client
certificate and the server CA. Set `TRUSTDB_HEALTH_SERVER_NAME` to a DNS SAN in
the server certificate (the image default is `trustdb`).
