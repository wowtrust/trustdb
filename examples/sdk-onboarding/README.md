# Go SDK onboarding

This checked example submits a file, waits for a portable proof with Global Log evidence (L4 or stronger), writes and reads a `.sproof`, then verifies the original file locally with explicit trusted public keys.

## Prerequisites

- Run all commands from the TrustDB repository root with the Go version declared in `go.mod`.
- Use a fresh working directory. `keygen` writes the named key files; do not overwrite keys used by an existing server.
- The server must use the public half of `client.key`, and Global Log must be enabled. The default configuration enables Global Log. No anchor is required for this L4 walkthrough.

Build the CLI and generate separate client and server Ed25519 key pairs:

```sh
mkdir -p ./bin .trustdb-onboarding
go build -o ./bin/trustdb ./cmd/trustdb
./bin/trustdb keygen --out .trustdb-onboarding --prefix client
./bin/trustdb keygen --out .trustdb-onboarding --prefix server
```

In terminal 1, start a local server. The short batch delay keeps the tutorial wait brief:

```sh
./bin/trustdb serve \
  --server-private-key .trustdb-onboarding/server.key \
  --client-public-key .trustdb-onboarding/client.pub \
  --wal .trustdb-onboarding/data/wal \
  --proof-dir .trustdb-onboarding/data/proofs \
  --metastore pebble \
  --metastore-path .trustdb-onboarding/data/pebble \
  --batch-max-delay 100ms \
  --listen 127.0.0.1:8080
```

In terminal 2, create a file and run the example:

```sh
printf 'hello TrustDB\n' > .trustdb-onboarding/example.txt
go run ./examples/sdk-onboarding \
  --server http://127.0.0.1:8080 \
  --file .trustdb-onboarding/example.txt \
  --client-private-key .trustdb-onboarding/client.key \
  --client-public-key .trustdb-onboarding/client.pub \
  --server-public-key .trustdb-onboarding/server.pub \
  --output .trustdb-onboarding/example.sproof
```

The final line reports the locally verified record and proof level:

```text
verified record_id=tr1... proof_level=L4 output=.trustdb-onboarding/example.sproof
```

The program uses a fresh SDK-generated idempotency key, checks server health, and polls only until the bounded `--timeout` (default `30s`). It reloads the written proof and reopens the original file before verification, so verification does not depend on the server or network. The keys inside evidence are never treated as trust roots; verification uses the public-key files supplied on the command line.

To demonstrate the same offline property with the CLI, stop the server and run:

```sh
./bin/trustdb verify \
  --file .trustdb-onboarding/example.txt \
  --sproof .trustdb-onboarding/example.sproof \
  --client-public-key .trustdb-onboarding/client.pub \
  --server-public-key .trustdb-onboarding/server.pub
```

An explicitly configured anchor can raise a later export to L5. This walkthrough deliberately stops at Global Log inclusion (L4) and does not require an external timestamp provider.
