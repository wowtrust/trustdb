# Online client-key lifecycle

TrustDB can admit a newly approved client signing key without restarting a
single-node `trustdb serve` process. The API mutates the same signed,
append-only Key Registry V2 instance used by claim admission. It does not add a
second cache or accept a trusted key on an ingest request.

## Security boundary

The endpoints are mounted below `admin.base_path` and use the existing Admin
Web authentication mechanisms:

- signed local-password session cookie;
- directly bound mTLS administrator identity; or
- OIDC identity asserted by a pinned mTLS gateway.

Registration and revocation require `key.manage`; inspection requires
`key.read`. The built-in `key-operator` role has both permissions. A
`security-admin` manages policy but does not implicitly receive key custody.
Authentication, authorization, request path, method and outcome are written to
the immutable security audit pipeline. When required audit writes fail,
requests fail closed.

Do not expose the admin subtree as a public ingest endpoint. Use TLS or mTLS
outside an explicitly local development profile.

## Configuration

Online mutation is available only when the active client trust anchor is a V2
key registry and its signing descriptor is configured:

```yaml
paths:
  key_registry: /var/lib/trustdb/keys/clients.tdkeys

registry:
  key_id: registry-key

keys:
  client_public: ""
  registry_private: /run/secrets/registry.key
  registry_public: /etc/trustdb/keys/registry.pub

admin:
  enabled: true
  base_path: /admin
  policy_path: /etc/trustdb/admin-policy.json
  session_secret: ${TRUSTDB_ADMIN_SESSION_SECRET}
```

The registry signer descriptor and trusted public descriptor must identify the
same suite, key ID, algorithm, encoding and public bytes. A mismatch prevents
startup. Omitting `keys.registry_private` preserves read-only registry
operation: claim admission and historical lookup continue, while mutation
returns `503`.

Static `keys.client_public` deployments are unchanged and do not expose a
writable registry.

## Authenticate

For local-password automation, create a dedicated `key-operator` account and
establish a cookie jar:

```bash
curl --fail-with-body \
  --cookie-jar trustdb-admin.cookies \
  --header 'Content-Type: application/json' \
  --data '{"username":"proof-mesh-key-operator","password":"..."}' \
  https://trustdb.example/admin/api/session
```

Production integrations should prefer a directly bound mTLS account or the
pinned OIDC gateway. Passwords and session cookies must come from a secret
manager and must not be written to configuration, command history or logs.

## Register a key

`POST /admin/api/keys`

```json
{
  "tenant_id": "tenant-a",
  "client_id": "chrome-extension:proof-mesh",
  "descriptor": {
    "schema_version": "trustdb.key-descriptor.v1",
    "kind": "verifier",
    "provider": "public",
    "crypto_suite": "CN_SM_V1",
    "key_id": "browser-key-2026-07",
    "algorithm": "sm2-sm3",
    "sm2_user_id": "1234567812345678",
    "public_key": {
      "encoding": "sec1-uncompressed-65-byte-sm2p256v1",
      "bytes": "<base64>"
    }
  },
  "valid_from": "2026-07-29T08:00:00Z"
}
```

Only a public verifier descriptor is accepted. Private material, remote signer
credentials and provider handles are rejected at this boundary. `valid_until`
is optional and uses RFC 3339 when supplied.

An identical replay returns the original sequence and event hash without
appending another event. Different descriptor material or validity under the
same tenant/client/key identity returns `409`.

## Inspect a key

`GET /admin/api/keys/{tenant_id}/{client_id}/{key_id}?at=<RFC3339>`

`at` defaults to the current server time. A historical time before a later
revocation remains queryable. A time at or after revocation returns `409`
because the key is no longer valid at that admission instant.

## Revoke a key

`POST /admin/api/keys/{tenant_id}/{client_id}/{key_id}/revoke`

```json
{
  "revoked_at": "2026-07-29T09:00:00Z",
  "reason": "tenant administrator revoked browser key"
}
```

The effective time is part of the signed registry event. An identical replay
is idempotent even when retried much later. A new online revocation may take
effect at the server's current time or in the future; more than five seconds of
past skew is rejected so an integration cannot retroactively invalidate a
claim that TrustDB already accepted. Claims received at or after the effective
instant are rejected; records accepted before it remain verifiable and
restart-safe against historical registry state.

## Multi-replica constraint

The online API updates the registry instance in the process that serves the
request. It is immediately correct for a single binary or a single TrustDB
Compose service.

Do not use node-local online mutation as an HA distribution mechanism. Every
claim-admitting replica in a NATS + TiKV deployment must observe one ordered,
authenticated registry event stream before traffic can be routed to it.
Until a deployment provides that control plane, use an operator-controlled
registry rollout and restart/readiness barrier across all replicas. A load
balancer must not send key-management requests to arbitrary replicas.
