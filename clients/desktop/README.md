# TrustDB Desktop

TrustDB Desktop is the Wails + Vue client for creating portable TrustDB
evidence, managing local signing identities, and verifying evidence without
contacting a TrustDB server.

## Capabilities

- create or import encrypted software identities for `INTL_V1`
  (Ed25519/SHA-256) and `CN_SM_V1` (SM2/SM3);
- reference non-exportable PKCS#11, SDF, or remote keys through the signer
  provider protocol;
- submit files over HTTP or gRPC and keep a searchable local Pebble index;
- export the recommended `.sproof` evidence file, plus the advanced split
  `.tdproof`, `.tdgproof`, and `.tdanchor-result` artifacts;
- verify content, client claims, receipts, batch paths, Global Log proofs,
  signed tree heads, identity lifecycle evidence, certificate status, and
  supported L5 anchors locally.

## Offline trust model

The primary evidence format is deterministic CBOR `.sproof v2`, documented in
[`formats/SPROOF_V2.md`](../../formats/SPROOF_V2.md). The retired v1 format is
not read, migrated, or used as a fallback.

Verification is performed by the in-process SDK verifier. It does not launch
an anchor-plugin subprocess and does not access HTTP, gRPC, DNS, certificate
services, anchor providers, or blockchain RPC endpoints. Remote verification
mode may download the selected proof first; cryptographic verification of the
downloaded file is still local.

Trust comes only from verifier-local inputs:

- client and server V2 verifier descriptors, including exact historical
  `key_id` values used by the evidence;
- a local Key Registry V2 verifier descriptor when lifecycle evidence is
  required;
- local client and server CA roots when certificate chains are used;
- the built-in, offline-verifiable anchor formats implemented by the SDK.

Descriptors, certificates, CRLs, validator sets, or checkpoints embedded in
the evidence file never become trust roots by carrying themselves. Missing or
mismatched local trust fails closed. The desktop client has no configurable
anchor policy or provider trust-root input: custom/provider-backed anchors and
the local-only `file`/`noop` sinks fail the anchor stage and cannot receive L5.
Selecting “skip anchor” explicitly limits verification to the available L1-L4
evidence instead.

## Development

```powershell
go test ./...
cd frontend
npm run build
```

Build the frontend and a desktop package with Wails:

```powershell
cd frontend
npm ci
npm run build
cd ..
wails build
```
