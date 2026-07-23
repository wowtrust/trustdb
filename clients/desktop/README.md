# TrustDB Desktop

TrustDB Desktop is the Wails + Vue client for local file attestation and proof management.

Current capabilities:

- local identity setup and server configuration;
- file attestation against a TrustDB HTTP server;
- local records stored in a Pebble-backed indexed store;
- record list search, filters, pagination, details, deletion, and proof refresh;
- primary `.sproof` export plus advanced `.tdproof`, `.tdgproof`, and `.tdanchor-result` exports;
- local proof verification with optional GlobalLogProof and STHAnchorResult;
- configured subprocess gRPC verifier support for custom L5 anchor sinks.

`.sproof` uses the repository-level v1 format documented in `formats/SPROOF_V1.md`.

Development:

```powershell
go test ./...
cd frontend
npm run build
```

Build a desktop package with Wails:

```powershell
wails build
```
