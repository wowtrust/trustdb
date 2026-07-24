# CN_SM_V1 Cross-Component Interoperability Corpus

Status: normative test corpus

Issue: [#460](https://github.com/wowtrust/trustdb/issues/460)

Suite: `CN_SM_V1`

## Purpose

The corpus fixes one byte-exact CN_SM_V1 evidence chain that every TrustDB
producer and verifier must interpret identically. It detects accidental
changes to canonical CBOR, SM2 user IDs, DER signatures, SM3 domains, record
IDs, Merkle profiles, Registry V2 events, receipts, Global Log leaves, STHs,
and `.sproof v2` composition.

This gate does not introduce a new proof, storage, backup, or wire format.
Every artifact is generated through the existing V2 production code and is
then preserved as expected bytes.

## Files

- `test/cnsmvectors/cn-sm-v1-interoperability-v1.json` is the reviewed corpus.
- `test/cnsmvectors/cn-sm-v1-interoperability-v1.sha256` detects repository
  corruption and makes corpus updates visible in review. SHA-256 here is a
  source-file checksum, not a TrustDB evidence algorithm.
- `test/cnsmvectors/generate.go` is the deterministic generator.
- `test/cnsmvectors/corpus.go` is the strict embedded loader used by all
  component tests.
- `test/cnsmvectors/openssl_test.go` is the independent OpenSSL 3 oracle.

The JSON includes fixed, test-only private scalars. They are public test
vectors and must never be copied into deployments. Production private keys
remain behind the configured software-envelope, SDF, HSM, PKCS#11, KMS, or
remote provider boundary.

## Covered evidence chain

The generator uses fixed content, clocks, namespace identifiers, and test
identities to produce:

1. three canonical client claims and their SM3 content digests;
2. SM2-SM3 signed claims and stable `tr2...` record IDs;
3. server records and accepted receipts;
4. a two-record batch, its SM3 root, committed receipts, and non-empty
   inclusion paths;
5. a second batch root, so the Global Log also has two leaves;
6. canonical Global Log leaves, an SM3 root, an SM2-SM3 STH, and a non-empty
   Global Log inclusion path;
7. a Registry V2 manifest and signed `KEY_REGISTERED` event;
8. verifier identity evidence containing the complete Registry V2 stream;
9. a portable L4 `.sproof v2` verified without network or external-provider
   access.

For every signed artifact, the corpus stores the exact signature input and
canonical ASN.1 DER signature. For every encoded object, it stores the exact
RFC 8949 deterministic-CBOR bytes.

## Reproducible generation

From the repository root:

```bash
go run ./test/cnsmvectors/cmd/generate -check
```

`-check` generates the complete evidence chain in a new temporary WAL,
proofstore, and key registry. It then compares the generated JSON and checksum
byte for byte with the reviewed files. It does not use the network.

An intentional suite or format change uses:

```bash
go run ./test/cnsmvectors/cmd/generate -write
go test ./test/cnsmvectors
```

The resulting corpus diff requires explicit cryptography and format review.
Updating only expected bytes cannot make a stale generator pass, and updating
only production code makes `-check` fail.

SM2 signatures need a nonce, so the generator uses a documented test-only SM3
counter stream derived from the fixed private scalar and exact signature
input. This makes generation independent of call order and process entropy.
Production signing continues to use its configured provider and secure
randomness; it does not use this test nonce construction.

## Independent implementation

The corpus is generated and verified by TrustDB's pinned Go implementation,
then independently checked by OpenSSL 3:

- `openssl dgst -sm3 -binary` recomputes every content digest.
- OpenSSL EVP verifies claim, accepted receipt, committed receipt, STH, and
  key-event SM2 signatures using
  `distid:1234567812345678`.
- The same signatures must fail with a different SM2 user ID.

OpenSSL is a test oracle only. Offline verification never invokes it or falls
back to it.

## Component consumers

Dedicated tests consume the same embedded bytes through:

- Server, Batch, and Global Log generation;
- CLI local `trustdb verify`;
- Go SDK `VerifySingleProofOffline`;
- Desktop local proof verification;
- the internal offline `.sproof` verifier;
- the provider-neutral signature contract.

The negative matrix rejects:

- `CN_SM_V1`/`INTL_V1` relabeling;
- a non-suite SM2 user ID;
- trailing, raw, or otherwise non-canonical signature encoding;
- embedded identity evidence used as a trust root;
- a different verifier-local key under the expected KeyID;
- an altered STH root or inclusion path.

Desktop verification remains in the existing Windows/macOS/Linux Desktop test
jobs. The dedicated Linux interoperability job runs the generator drift gate,
OpenSSL oracle, and the Server, provider, offline, SDK, and CLI consumers.
