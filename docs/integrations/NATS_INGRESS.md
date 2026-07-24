# Optional NATS / JetStream ingress

[简体中文](NATS_INGRESS.zh-CN.md)

TrustDB can accept signed claims through NATS JetStream when producers need a
durable buffer, many-to-one fan-in, or broker-controlled flow distribution in
front of the normal TrustDB submission pipeline. The transport is optional and
disabled by default. HTTP and gRPC remain available whether NATS is enabled or
not.

NATS changes how a signed claim reaches TrustDB; it does not change the claim,
WAL, batch, proof, Global Log, anchor, or offline-verification semantics.

## What the acknowledgement means

There are two separate durable boundaries:

1. A JetStream publish acknowledgement means the NATS ingress stream stored the
   request. It does **not** mean TrustDB accepted the claim.
2. An accepted result means TrustDB validated the claim and crossed the normal
   WAL acceptance boundary. That result reports L2 and contains the same server
   record and accepted receipt returned by HTTP or gRPC.

The server stores the result before acknowledging the ingress delivery. A
caller can therefore recover the immutable result after a timeout, connection
loss, or caller restart as long as the result remains inside the configured
result retention window.

```text
producer
   |
   | publish SignedClaim request
   v
TRUSTDB_INGRESS (work-queue stream)
   |
   | durable pull consumer, bounded MaxAckPending
   v
TrustDB shared submission service -> signature/key checks -> WAL acceptance
   |                                      |
   | accepted or terminal failure         | malformed broker delivery
   v                                      v
TRUSTDB_INGRESS_RESULTS                 TRUSTDB_INGRESS_DLQ
   |
   | immutable outcome stored first
   v
ACK / terminate original ingress delivery
```

## When to use it

NATS ingress is useful when:

- many producers must feed one TrustDB service through a shared durable buffer;
- producers and TrustDB cannot stay connected for the whole acceptance wait;
- a broker must absorb bounded bursts while TrustDB applies downstream
  backpressure;
- broker accounts, subjects, and stream limits are part of the deployment's
  routing and isolation model.

It is not required for a single application that can call HTTP or gRPC
directly. The public `NATSIngressClient` is write-oriented; use the normal
`sdk.Client` over HTTP or gRPC for records, proof export, Global Log evidence,
and anchor reads.

## Default-off boundary

The generated configuration contains a complete `nats` section with:

```yaml
nats:
  enabled: false
```

While `enabled` is `false`, `trustdb serve` does not connect to NATS, create or
inspect JetStream resources, start NATS workers, or change HTTP/gRPC behavior.
Setting unrelated NATS fields has no runtime effect until the section is
enabled.

## Local evaluation

The following broker is suitable for a disposable local walkthrough. It is not
a hardened broker configuration:

```bash
docker volume create trustdb-nats-data
docker run --rm --name trustdb-nats \
  -p 127.0.0.1:4222:4222 \
  -v trustdb-nats-data:/data \
  nats:2 -js -sd /data
```

Create a TrustDB config if the deployment does not already have one:

```bash
./bin/trustdb config init --out ./trustdb.yaml
```

Keep the existing runnable server, key, WAL, and proofstore settings, then set
the generated NATS block to at least:

```yaml
nats:
  enabled: true
  urls: ["nats://127.0.0.1:4222"]
  provision: true
```

Validate the merged configuration before starting the service:

```bash
./bin/trustdb --config ./trustdb.yaml config validate
./bin/trustdb --config ./trustdb.yaml serve
```

On startup, TrustDB logs the ingress stream, durable consumer, result stream,
dead-letter stream, resolved worker count, and per-worker fetch batch. Startup
fails closed if the broker is unavailable or an existing resource does not
match the configured topology.

## Topology and provisioning

The default topology contains three distinct streams and one durable consumer:

| Resource | Default | Required behavior |
| --- | --- | --- |
| Ingress stream | `TRUSTDB_INGRESS` | Work-queue retention on the concrete `trustdb.ingress.v1.claims` subject, `DiscardNew`, bounded bytes/message size, configured duplicate window. |
| Durable consumer | `trustdb-ingress` | Explicit ACK, instant replay, exact subject filter, configured `AckWait`, `MaxDeliver`, `MaxAckPending`, request batch, and request expiry. |
| Result stream | `TRUSTDB_INGRESS_RESULTS` | Limits retention on `trustdb.ingress.v1.results.*`, one immutable message per result subject, `DiscardNewPerSubject`. |
| Dead-letter stream | `TRUSTDB_INGRESS_DLQ` | Limits retention on `trustdb.ingress.v1.dlq.*`, one immutable message per rejection subject, `DiscardNewPerSubject`. |

With `nats.provision: true`, TrustDB creates missing resources. It never
silently rewrites an existing stream or consumer: every relevant field is
validated and an incompatible topology stops startup.

With `nats.provision: false`, all four resources must already exist with the
exact configured semantics. This mode is appropriate when broker topology is
owned by a separate operations or infrastructure workflow.

The Go SDK never creates, updates, or deletes broker resources. It only opens
and validates the configured ingress and result streams.

## Configuration reference

Generate the current complete schema with `trustdb config init`. The fields are
grouped below by operational purpose.

### Connection, authentication, and TLS

| Field | Meaning |
| --- | --- |
| `enabled` | Enables the optional transport. Default `false`. |
| `urls` | One or more `nats://`, `tls://`, `ws://`, or `wss://` endpoints. URL credentials and query-string secrets are rejected. |
| `connect_timeout` | Bounds initial connection establishment. |
| `reconnect_wait` | Delay between reconnect attempts. |
| `max_reconnects` | Maximum reconnect attempts; `-1` means unlimited. |
| `drain_timeout` | Bounds connection drain during shutdown. |
| `credentials_file` | NATS credentials file. Mutually exclusive with username/password and token authentication. |
| `username`, `password` | Username/password pair. Both must be set together and are mutually exclusive with other auth modes. |
| `token` | Token authentication, mutually exclusive with the other auth modes. |
| `tls.enabled` | Forces a TLS connection configuration. TLS is also configured when any TLS file or name is set. |
| `tls.ca_file` | Additional PEM CA bundle. |
| `tls.cert_file`, `tls.key_file` | Client certificate and key for mTLS; both must be set together. |
| `tls.server_name` | Expected certificate server name. |
| `tls.insecure_skip_verify` | Explicitly disables certificate verification. Keep `false` outside isolated tests. |

Use environment variables for deployment secrets, for example
`TRUSTDB_NATS_CREDENTIALS_FILE`, `TRUSTDB_NATS_USERNAME`,
`TRUSTDB_NATS_PASSWORD`, or `TRUSTDB_NATS_TOKEN`. Authentication modes are
mutually exclusive. Do not put credentials in `nats.urls` or commit them to a
configuration file.

### Stream capacity and retention

| Field | Meaning |
| --- | --- |
| `stream`, `subject`, `durable` | Ingress stream, exact publish subject, and durable consumer identity. |
| `provision` | Creates missing topology when true; validates only when false. |
| `stream_storage` | `file` for restart-persistent broker storage or `memory` for intentionally volatile storage. |
| `stream_replicas` | JetStream replica count, from 1 through 5; the cluster must support the selected count. |
| `stream_max_bytes`, `stream_max_age` | Ingress backlog limits. `0s` disables age expiry, but the byte limit still applies. |
| `result_stream`, `result_subject` | Immutable per-request result stream and subject pattern ending in `.*`. |
| `result_max_bytes`, `result_max_age` | Result recovery limits. The default age is `24h`; expired results can no longer be recovered by `WaitResult`. |
| `dlq_stream`, `dlq_subject` | Immutable malformed-delivery stream and subject pattern ending in `.*`. |
| `dlq_max_bytes`, `dlq_max_age` | Dead-letter retention limits. |
| `duplicate_window` | JetStream publish de-duplication window. TrustDB also verifies an already-stored immutable outcome, so a lost outcome publish acknowledgement remains safe to retry after this window. |

All three streams use `DiscardNew`. When the ingress stream reaches a boundary,
the producer publish fails and must be treated as backpressure. When a result
or DLQ stream reaches a boundary, TrustDB cannot durably store the outcome, so
it does not ACK the ingress delivery and keeps retrying the outcome write. No
path silently deletes an older immutable outcome or grows memory/disk usage
without the configured limits.

### Workers, flow control, and retry

| Field | Meaning |
| --- | --- |
| `workers` | Pull-loop count. `0` resolves automatically to a value bounded by `GOMAXPROCS`, `fetch_batch`, and `max_ack_pending`. Explicit values are bounded by `max_ack_pending`. |
| `fetch_batch` | Maximum configured pull request batch. Each worker receives a smaller share when necessary so combined client buffers remain bounded. |
| `fetch_wait` | Pull expiry and maximum idle wait; at least `1s`. |
| `ack_wait` | Broker acknowledgement deadline. TrustDB sends progress heartbeats while a delivery is being processed. |
| `max_ack_pending` | Upper bound on unacknowledged deliveries held by the durable consumer. |
| `nak_delay` | Delay before redelivery after a retryable submission failure. |
| `max_deliver` | Maximum delivery count before a valid request receives an immutable terminal failure result. |
| `outcome_retry_wait` | Delay while retrying result or dead-letter persistence. The ingress delivery is not acknowledged until that persistence succeeds. |

The worker adds no second in-process message queue. JetStream's durable
consumer and `MaxAckPending` bound delivery fan-out, while the shared TrustDB
submission service applies the same blocking queue backpressure used by HTTP
and gRPC.

## Go SDK workflow

Pin a release or commit that contains `NATSIngressClient`. While evaluating the
current unreleased tree, use:

```bash
go get github.com/wowtrust/trustdb@main
```

Applications normally produce a `sdk.SignedClaim` through their existing
signing path, then use one of two submission styles.

### Synchronous publish and wait

```go
cfg := sdk.DefaultNATSIngressConfig()
cfg.URLs = []string{"tls://nats.internal.example:4222"}
cfg.ConnectionOptions = []nats.Option{
    nats.UserCredentials("/run/secrets/trustdb-nats.creds"),
    nats.RootCAs("/etc/trust/nats-ca.pem"),
}

client, err := sdk.NewNATSIngressClient(ctx, cfg)
if err != nil {
    return err
}
defer client.Close()

result, err := client.SubmitSignedClaim(ctx, signed)
if err != nil {
    return err
}
fmt.Printf("record=%s level=%s\n", result.RecordID, result.ProofLevel)
```

### Publish now, recover later

```go
submission, err := client.PublishSignedClaim(ctx, signed)
if err != nil {
    return err
}

// Persist both submission.MessageID and submission.SignedClaim in the
// application's durable state before returning control to its caller.

result, err := client.WaitResult(ctx, submission)
```

`WaitResult` validates that the handle still identifies the exact signed
claim. It subscribes to the exact result subject before looking up the durable
snapshot, covering both a result that already exists and one committed during
the lookup without polling. The SDK rejects mismatched subjects, headers,
schemas, message IDs, bodies, and mutable result stream configurations.

`NATSSubmission` is a Go value, not a new TrustDB evidence format. If recovery
must survive process restart, store both fields in application-owned durable
state and protect them from modification. Do not reconstruct a handle from an
untrusted message ID alone.

Server rejections are returned as `*sdk.Error`; inspect them with
`errors.As`. Cancellation and deadlines are honored by connection, publish,
lookup, and wait operations. `Close` is idempotent and performs a bounded NATS
drain.

Checked public API examples live in [`sdk/example_test.go`](../../sdk/example_test.go),
and the complete embedded JetStream lifecycle tests live in
[`sdk/nats_ingress_test.go`](../../sdk/nats_ingress_test.go).

## Retry, duplicate, and failure behavior

- Publishing the same exact signed claim produces the same deterministic
  request ID. JetStream de-duplication may report the publish as a duplicate;
  the caller can still recover the same immutable result.
- A malformed subject, header, schema, message ID, or CBOR body is copied to
  the immutable dead-letter stream before the original delivery is terminated.
- A valid request with a retryable TrustDB failure is negatively acknowledged
  with `nak_delay`. After `max_deliver`, TrustDB stores a terminal error result.
- Invalid arguments, duplicates that conflict with TrustDB state, and data-loss
  classifications are terminal rather than retried indefinitely.
- TrustDB never ACKs a successful or terminal delivery before the exact result
  is durable. Result-store failure keeps retrying and leaves the ingress
  delivery unacknowledged.
- If shutdown interrupts processing, unfinished deliveries remain
  unacknowledged and are available to the same durable consumer after restart.

## Broker authorization

Use separate broker identities for the TrustDB server and producer SDKs.

The TrustDB server needs permission to inspect the configured topology,
consume and ACK the durable ingress consumer, and publish immutable result and
dead-letter subjects. When `provision` is true it also needs permission to
create the three streams and durable consumer.

An SDK producer needs permission to inspect the ingress and result streams,
publish only the concrete ingress subject, subscribe to the exact per-request
result subjects it owns, read the last message for those subjects through the
JetStream API, and use NATS inbox subjects for request/reply acknowledgements.
It does not need consumer-management, stream-update, stream-delete, or DLQ
access.

Exact NATS permission syntax depends on the broker account and deployment.
Validate the final account with both a publish-and-wait test and a stored-result
recovery test before admitting traffic.

## Operations and troubleshooting

Monitor both TrustDB and JetStream:

- TrustDB startup logs must contain `optional NATS ingress started` with the
  intended stream, consumer, result stream, DLQ stream, and worker sizing.
- Broker stream state shows pending ingress bytes/messages and result/DLQ
  retention pressure.
- Durable consumer state shows pending, redelivered, and unacknowledged
  deliveries.
- Repeated `NATS ingress worker delivery error` logs require investigation;
  they may indicate submission failures, broker interruption, or outcome-store
  pressure.
- An unexpected worker exit is fatal to `trustdb serve`; restart only after the
  broker or topology cause is understood.

TrustDB exports process-local NATS ingress metrics through the existing
`/metrics` endpoint. Every label is a fixed enumeration; no message ID,
subject, client identity, or error text is exposed.

| Metric | Interpretation |
| --- | --- |
| `trustdb_nats_ingress_in_flight` | Deliveries currently executing the worker state machine; broker backlog is not included. |
| `trustdb_nats_ingress_deliveries_total{action}` | Successful broker actions: `ack`, `nak`, `term_result`, or `term_rejection`. |
| `trustdb_nats_ingress_outcome_store_retries_total{kind}` | Failed durable result or rejection writes that will retry before the original delivery is acknowledged. |
| `trustdb_nats_ingress_errors_total{stage}` | Worker errors from `consume`, `process`, or `ack_progress`. |

A rising `nak` rate indicates downstream transient pressure. Rising outcome
store retries with stable broker health points at result/DLQ capacity or
storage availability. A non-zero error rate requires logs and JetStream state
to identify the exact cause.

Common startup failures:

| Symptom | Action |
| --- | --- |
| Broker connection refused | Verify endpoints, listener binding, network policy, credentials, and TLS server name. Enabled NATS fails closed. |
| Missing stream/consumer with `provision=false` | Create the exact topology through the broker-owned workflow or enable provisioning for an authorized bootstrap. |
| Incompatible resource configuration | Compare every reported mismatch. TrustDB intentionally does not mutate an existing resource. |
| Publisher can publish but cannot wait | Grant result stream info/read access, exact result-subject subscribe access, and required inbox replies. |
| Results disappear before a delayed caller returns | Increase `result_max_age` and/or `result_max_bytes`, then create a compatible topology during a planned change; existing mismatched resources are rejected. |
| Ingress publish fails at capacity | Treat it as backpressure, reduce producer rate or increase the deliberately bounded stream capacity. Do not switch to unbounded retention. |

## Evidence and backup boundaries

JetStream ingress messages, NATS results, and dead letters are transport state,
not `.sproof` evidence and not part of TrustDB logical `.tdbackup` files. Once a
claim is accepted, all L2-L5 processing and proof export use the normal TrustDB
stores. Preserve and back up broker state separately according to the selected
JetStream storage and replication policy.
