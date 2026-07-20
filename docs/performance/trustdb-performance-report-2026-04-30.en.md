# TrustDB High-Write Private-IP CVM Retest Report

![TrustDB high-write retest overview](assets/perf-highwrite-ai-overview.png)

Report date: 2026-04-30

Run ID: `perf-semantic-20260430T071902Z`

Scope: semantic performance switches, high-write profile, HTTP/gRPC private-IP transport, legacy payload matrix, and 100k high-concurrency matrix.

Goal: validate single-server TrustDB submit capacity and L3 proof materialization capacity using two CVMs connected through the private VPC network, without recording passwords, keys, or other secrets.

This report replaces the previous `perf-v3` report. The previous report focused on the safer L4 proof-ready profile. This report explicitly uses a performance-first profile with L4/L5 disabled and L3 as the highest proof level, so it should not be mixed with default-safe or L4/L5 benchmark results.

## Executive Summary

The effective drain-aware workload covered 850,000 records:

- 100k high-concurrency matrix: 300,000 HTTP records and 300,000 gRPC records.
- Legacy payload matrix: 185,000 HTTP records and 65,000 gRPC records.
- Every effective case completed with `failed=0`, `batch_errors=0`, `proof_timeouts=0`, and `post_proof_query_failed=0`.

| Metric | HTTP | gRPC | Combined / Range |
| --- | ---: | ---: | ---: |
| Effective submitted records | 485,000 | 365,000 | 850,000 |
| Submit failures | 0 | 0 | 0 |
| Batch errors | 0 | 0 | 0 |
| Proof timeouts | 0 | 0 | 0 |
| Post-proof query failures | 0 | 0 | 0 |
| High-concurrency Submit TPS | 48,186-49,150/s | 46,497-51,409/s | 46k-51k/s |
| Legacy-case Submit TPS | 17,471-53,366/s | 26,282-50,767/s | 17k-53k/s |
| L3 materialized TPS | 2,958-5,754/s | 1,247-3,856/s | 1.2k-5.8k/s |

Main interpretation: the accepted-submit path is strong, and the current bottleneck is asynchronous L3 proof materialization plus Pebble proof artifact persistence. TrustDB can return L2 accepted receipts quickly; if the product target is full proof readiness throughput, the artifact materialization path remains the next optimization target.

![Submit and L3 materialization throughput](assets/perf-highwrite-submit-proof.png)

## Test Environment

| Item | Value |
| --- | --- |
| Machines | Two CVMs: one server, one client |
| Server | 32 vCPU / 64 GiB, TencentOS Server 4 |
| Client | 32 vCPU / 64 GiB, TencentOS Server 4 |
| Network | Same VPC and subnet; client used the server private IP |
| Server listeners | HTTP `10.206.0.9:8080`, gRPC `10.206.0.9:9090` |
| Client private IP | `10.206.0.4` |
| Data disk | `/mnt/datadisk0`, ext4, about 70 GiB |
| Run directory | `/mnt/datadisk0/trustdb-perf-semantic-20260430T071902Z` |
| Binary | Current branch cross-compiled for linux/amd64 |
| Go version | `go1.26.2` |

The report intentionally omits server passwords, private keys, client private keys, and other sensitive credentials.

## High-Write Profile

| Setting | Value | Semantic impact |
| --- | --- | --- |
| `wal.fsync_mode` | `batch` | Unsafe high-throughput mode; records already returned as accepted may be lost during machine crash or power-loss windows. |
| `batch.proof_mode` | `async` | L2 submit response is decoupled from L3 proof materialization. |
| `proofstore.record_index_mode` | `time_only` | Writes only base and time indexes to reduce write amplification; richer queries may become slower. |
| `proofstore.artifact_sync_mode` | `batch` | Artifacts rely on manifest plus WAL recovery to fill gaps, reducing per-chunk sync pressure. |
| `global_log.enabled` | `false` | L4 global log is disabled; highest proof level is L3. |
| `anchor-sink` | `off` | L5 anchoring is disabled. |
| `batch_queue_size` | `1,048,576` | Prevents batch queue saturation during 100k burst submissions. |
| `batch_max_records` | `8,192` | Reduces batch count and proofstore write batches. |

This profile is intended for high-write benchmarking. It is not the default production-safe profile. Use `wal.fsync_mode=group` to bound the asynchronous loss window, or `strict` when every accepted record must wait for its WAL file fsync before acknowledgement. End-to-end crash durability also depends on the filesystem and storage guarantees.

## Measurement Semantics

| Metric | Meaning |
| --- | --- |
| Submit TPS | Measures only signed-claim submission and accepted receipt return on the L2 path. It does not wait for proof readiness. |
| L3 materialized TPS | After each case finishes submitting, the runner waits until WAL checkpoint advances by the full case count and queue depths return to zero. |
| Immediate query failure | A `GetRecord` miss immediately after submit. This measures asynchronous visibility delay, not submit failure. |
| Post-proof query failure | A `GetRecord` failure after proof readiness. This is the stronger correctness signal for the asynchronous proof pipeline. |
| Proof timeout | Timeout while waiting for the configured proof target; this run used L3. |

## 100k High-Concurrency Matrix

Each case submitted 100,000 records with 1 KiB payloads. This matrix shows the gap between fast accepted submission and full L3 materialization.

| Transport | Concurrency | Records | Submit TPS | Submit p95 | L3 materialized TPS | Drain seconds | Failures | Batch errors | Proof timeouts | Post-proof query failures |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| HTTP | 64 | 100,000 | 48,186/s | 5 ms | 3,880/s | 25.8 | 0 | 0 | 0 | 0 |
| HTTP | 128 | 100,000 | 49,150/s | 5 ms | 3,357/s | 29.8 | 0 | 0 | 0 | 0 |
| HTTP | 256 | 100,000 | 48,616/s | 10 ms | 3,459/s | 28.9 | 0 | 0 | 0 | 0 |
| gRPC | 64 | 100,000 | 46,497/s | 5 ms | 3,444/s | 29.0 | 0 | 0 | 0 | 0 |
| gRPC | 128 | 100,000 | 51,122/s | 5 ms | 2,723/s | 36.7 | 0 | 0 | 0 | 0 |
| gRPC | 256 | 100,000 | 51,409/s | 10 ms | 2,128/s | 47.0 | 0 | 0 | 0 | 0 |

## Legacy Payload Matrix Retest

`p1k-c32` means a 1 KiB payload at concurrency 32. This matrix reuses the case names from the previous report, but runs them under the new high-write profile.

![Legacy payload matrix retest](assets/perf-highwrite-legacy-cases.png)

### HTTP

| Case | Records | Concurrency | Payload | Submit TPS | Submit p95 | L3 materialized TPS | Failures | Batch errors | Proof timeouts | Post-proof query failures | Immediate query failures |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `p1k-c8` | 10,000 | 8 | 1 KiB | 17,471/s | 1 ms | 5,133/s | 0 | 0 | 0 | 0 | 0 |
| `p1k-c16` | 20,000 | 16 | 1 KiB | 28,584/s | 1 ms | 3,067/s | 0 | 0 | 0 | 0 | 0 |
| `p1k-c32` | 30,000 | 32 | 1 KiB | 41,568/s | 2 ms | 3,441/s | 0 | 0 | 0 | 0 | 0 |
| `p1k-c64` | 30,000 | 64 | 1 KiB | 44,506/s | 5 ms | 3,053/s | 0 | 0 | 0 | 0 | 0 |
| `p1k-c128` | 30,000 | 128 | 1 KiB | 53,366/s | 5 ms | 4,688/s | 0 | 0 | 0 | 0 | 0 |
| `p4k-c32` | 20,000 | 32 | 4 KiB | 39,895/s | 2 ms | 3,876/s | 0 | 0 | 0 | 0 | 0 |
| `p4k-c64` | 20,000 | 64 | 4 KiB | 46,475/s | 5 ms | 3,049/s | 0 | 0 | 0 | 0 | 0 |
| `p16k-c32` | 10,000 | 32 | 16 KiB | 39,589/s | 2 ms | 3,514/s | 0 | 0 | 0 | 0 | 0 |
| `p16k-c64` | 10,000 | 64 | 16 KiB | 46,792/s | 5 ms | 5,754/s | 0 | 0 | 0 | 0 | 0 |
| `p64k-c32` | 5,000 | 32 | 64 KiB | 36,323/s | 2 ms | 2,958/s | 0 | 0 | 0 | 0 | 1 |

### gRPC

| Case | Records | Concurrency | Payload | Submit TPS | Submit p95 | L3 materialized TPS | Failures | Batch errors | Proof timeouts | Post-proof query failures | Immediate query failures |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `p1k-c16` | 10,000 | 16 | 1 KiB | 26,282/s | 1 ms | 3,255/s | 0 | 0 | 0 | 0 | 0 |
| `p1k-c32` | 20,000 | 32 | 1 KiB | 40,104/s | 2 ms | 3,856/s | 0 | 0 | 0 | 0 | 0 |
| `p1k-c64` | 20,000 | 64 | 1 KiB | 50,767/s | 2 ms | 3,639/s | 0 | 0 | 0 | 0 | 1 |
| `p4k-c32` | 10,000 | 32 | 4 KiB | 38,005/s | 2 ms | 3,500/s | 0 | 0 | 0 | 0 | 0 |
| `p16k-c32` | 5,000 | 32 | 16 KiB | 34,675/s | 2 ms | 1,247/s | 0 | 0 | 0 | 0 | 1 |

## Correctness and Visibility

![Retest correctness signals](assets/perf-highwrite-correctness.png)

Post-proof query failures were zero. That is the more important read-correctness signal for this profile because L3 proof materialization is intentionally asynchronous. A few immediate misses appeared in HTTP `p64k-c32`, gRPC `p1k-c64`, and gRPC `p16k-c32`; those are visibility windows where the record was accepted but its index was not immediately readable. After proof readiness, all sampled records were readable.

## Performance Interpretation

The short version: the submit ingress path is fast, and proof artifact materialization is the next bottleneck.

- For business acceptance throughput, HTTP/gRPC at concurrency 64-256 sustained about 46k-51k accepted submissions per second. The fastest legacy cases were HTTP `p1k-c128` at 53,366/s and gRPC `p1k-c64` at 50,767/s.
- For full proof readiness, L3 materialized throughput mostly stayed around 3k-5k/s, with gRPC `p16k-c32` dropping to 1,247/s. Larger payloads and artifact writes still put pressure on materialization throughput.
- For latency, submit p95 was mostly 1-5 ms. The 100k high-concurrency 256 cases reached 10 ms, still low milliseconds.
- For stability, submit failures, batch errors, proof timeouts, and post-proof query failures were all zero. The earlier standard matrix queue saturation was resolved by increasing the batch queue size.

## Code Fix During Retest

The retest exposed and fixed a real stability issue: when `global_log.enabled=false`, the optional global-log service could be carried into HTTP/gRPC handlers as a typed nil interface, so L4/L5 probing paths could panic. The fix normalizes typed nil services before route registration/server construction. With L4/L5 disabled, HTTP global-log routes are not registered and gRPC returns a clear failed-precondition error instead of panicking.

Fix commit: `f947823 fix: handle disabled global log services`.

## Validation Status

| Check | Result |
| --- | --- |
| Server `/healthz` | `{"ok":true}` |
| Server panic/fatal/segfault scan | None found |
| Final batch queue depth | 0 |
| Final ingest queue depth | 0 |
| Final WAL checkpoint | `1,451,000` |
| `go test -p 1 ./...` | Passed |
| `go test -p 1 -tags=e2e ./cmd/trustdb` | Passed |
| `git diff --check` | Passed |

## Next Optimization Targets

1. Continue optimizing `PutBatchArtifacts`, especially ProofBundle CBOR/snappy encoding, record-index writes, and Pebble batch staging allocations.
2. Run a dedicated proof materializer parallelism pass. L2 submit throughput is now far higher than L3 materialization throughput, so the materializer should use the 32 vCPUs more effectively.
3. Keep a dedicated large-payload profile. `p16k` and `p64k` cases expose artifact-path bottlenecks more clearly.
4. Separate WAL and Pebble storage devices for production-like tests. The current run used the data-disk directory, but WAL, Pebble WAL, SSTs, proof artifacts, and compaction still shared one disk.
5. Retest the default safe profile separately. This report is for the performance-first unsafe profile and does not represent `wal.fsync_mode=group` with L4/L5 enabled.

## Artifacts

```text
.localdeploy/perf-semantic-20260430T071902Z/reports/
.localdeploy/perf-semantic-20260430T071902Z/reports/drain-summary.json
.localdeploy/perf-semantic-20260430T071902Z/reports/legacy-drain-summary.json
```
