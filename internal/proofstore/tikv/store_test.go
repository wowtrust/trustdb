package tikv

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/golang/snappy"

	"github.com/ryan-wong-coder/trustdb/internal/cborx"
	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/trusterr"
)

func TestNormalizePDAddresses(t *testing.T) {
	t.Parallel()

	got := NormalizePDAddresses([]string{"127.0.0.1:2379, 127.0.0.2:2379", ""}, "127.0.0.3:2379")
	want := []string{"127.0.0.1:2379", "127.0.0.2:2379", "127.0.0.3:2379"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestOpenWithOptionsRequiresPDEndpoints(t *testing.T) {
	t.Parallel()

	if _, err := OpenWithOptions(Options{}); trusterr.CodeOf(err) != trusterr.CodeInvalidArgument {
		t.Fatalf("OpenWithOptions without endpoints error code = %s, want %s", trusterr.CodeOf(err), trusterr.CodeInvalidArgument)
	}
}

func TestNormalizeNamespace(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		namespace string
		want      string
	}{
		{name: "empty defaults", namespace: "", want: "default"},
		{name: "trims whitespace", namespace: " tenant-a/log-a ", want: "tenant-a/log-a"},
		{name: "keeps unicode text", namespace: "租户/日志", want: "租户/日志"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := NormalizeNamespace(tt.namespace); got != tt.want {
				t.Fatalf("NormalizeNamespace(%q) = %q, want %q", tt.namespace, got, tt.want)
			}
		})
	}
}

func TestNamespaceKeyPrefix(t *testing.T) {
	t.Parallel()

	got := namespaceKeyPrefix("tenant-a/log-a")
	wantSuffix := base64.RawURLEncoding.EncodeToString([]byte("tenant-a/log-a")) + "/"
	if !bytes.HasPrefix(got, []byte(namespacePrefix)) {
		t.Fatalf("namespace prefix %q does not start with %q", got, namespacePrefix)
	}
	if !bytes.HasSuffix(got, []byte(wantSuffix)) {
		t.Fatalf("namespace prefix %q does not end with encoded namespace %q", got, wantSuffix)
	}
}

func TestDeferredSetFinishTransfersBuffers(t *testing.T) {
	t.Parallel()

	db := &tikvDB{namespace: namespaceKeyPrefix("test")}
	batch := &tikvBatch{db: db}
	op := batch.SetDeferred(3, 5)
	copy(op.Key, "key")
	copy(op.Value, "value")
	if err := op.Finish(); err != nil {
		t.Fatal(err)
	}
	if len(batch.ops) != 1 {
		t.Fatalf("ops = %d, want 1", len(batch.ops))
	}
	wantKey := append(append([]byte(nil), db.namespace...), "key"...)
	if !bytes.Equal(batch.ops[0].key, wantKey) || !bytes.Equal(batch.ops[0].value, []byte("value")) {
		t.Fatalf("staged op = key %q value %q", batch.ops[0].key, batch.ops[0].value)
	}
	if &batch.ops[0].value[0] != &op.Value[0] {
		t.Fatal("deferred value was copied instead of transferred")
	}
	if &batch.ops[0].key[len(db.namespace)] != &op.Key[0] {
		t.Fatal("deferred logical key was copied instead of embedded in the physical key")
	}

	raw := &tikvBatch{db: db, raw: true}
	rawOp := raw.SetDeferred(3, 5)
	copy(rawOp.Key, "key")
	copy(rawOp.Value, "value")
	if err := rawOp.Finish(); err != nil {
		t.Fatal(err)
	}
	if &raw.ops[0].key[0] != &rawOp.Key[0] || &raw.ops[0].value[0] != &rawOp.Value[0] {
		t.Fatal("raw deferred buffers were copied instead of transferred")
	}
}

func TestEncodeBatchArtifactIntoMatchesWrapper(t *testing.T) {
	t.Parallel()

	bundle := syntheticTiKVProofBundles(1)[0]
	want, err := encodeBatchArtifact(bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer want.release()
	var got encodedBatchArtifact
	if err := encodeBatchArtifactInto(&got, &bundle); err != nil {
		t.Fatal(err)
	}
	defer got.release()
	if got.recordID != want.recordID || !bytes.Equal(got.bundleValue, want.bundleValue) {
		t.Fatal("direct batch artifact bundle differs from wrapper")
	}
	if got.index.idx.RecordID != want.index.idx.RecordID || !bytes.Equal(got.index.value, want.index.value) {
		t.Fatal("direct batch artifact record index differs from wrapper")
	}
}

func TestDecodeStoredProofBundleRejectsInvalidEnvelopePayloads(t *testing.T) {
	t.Parallel()

	oversized := make([]byte, binary.MaxVarintLen64)
	oversized = oversized[:binary.PutUvarint(oversized, uint64(maxStoredObjectBytes+1))]
	tests := []struct {
		name     string
		envelope storedProofBundleEnvelope
	}{
		{name: "unsupported codec", envelope: storedProofBundleEnvelope{SchemaVersion: schemaStoredProofBundleV2, Codec: "unknown"}},
		{name: "corrupt snappy", envelope: storedProofBundleEnvelope{SchemaVersion: schemaStoredProofBundleV2, Codec: storedBundleCodecSnappy, Data: []byte{0xff}}},
		{name: "oversized decoded payload", envelope: storedProofBundleEnvelope{SchemaVersion: schemaStoredProofBundleV2, Codec: storedBundleCodecSnappy, Data: oversized}},
		{name: "malformed decoded cbor", envelope: storedProofBundleEnvelope{SchemaVersion: schemaStoredProofBundleV2, Codec: storedBundleCodecSnappy, Data: snappy.Encode(nil, []byte{0xff})}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := cborx.Marshal(tt.envelope)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeStoredProofBundle(data); err == nil {
				t.Fatal("decodeStoredProofBundle error = nil")
			}
		})
	}
}

func BenchmarkTiKVEncodeBatchArtifacts1024(b *testing.B) {
	bundles := syntheticTiKVProofBundles(1024)
	b.ReportAllocs()
	for b.Loop() {
		artifacts, err := encodeBatchArtifacts(context.Background(), bundles)
		if err != nil {
			b.Fatal(err)
		}
		releaseBatchArtifacts(artifacts)
	}
}

func BenchmarkTiKVStageDeferredSets1024(b *testing.B) {
	db := &tikvDB{namespace: namespaceKeyPrefix("bench")}
	key := []byte("bundle-v2/tr1-bench-record")
	value := bytes.Repeat([]byte{1}, 1024)
	b.ReportAllocs()
	for b.Loop() {
		batch := &tikvBatch{db: db}
		for range 1024 {
			if err := stageSet(batch, key, value); err != nil {
				b.Fatal(err)
			}
		}
		_ = batch.Close()
	}
}

func BenchmarkTiKVDecodeStoredProofBundleV2(b *testing.B) {
	bundle := syntheticTiKVProofBundles(1)[0]
	for i := range 256 {
		bundle.BatchProof.AuditPath = append(bundle.BatchProof.AuditPath, bytes.Repeat([]byte{byte(i % 8)}, 32))
	}
	data, buf, err := encodeStoredProofBundle(&bundle)
	if err != nil {
		b.Fatal(err)
	}
	defer putArtifactBuffer(buf)
	var envelope storedProofBundleEnvelope
	if err := cborx.UnmarshalLimit(data, &envelope, maxStoredObjectBytes); err != nil {
		b.Fatal(err)
	}
	if envelope.Codec != storedBundleCodecSnappy {
		b.Fatalf("codec = %q, want %q", envelope.Codec, storedBundleCodecSnappy)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		got, err := decodeStoredProofBundle(data)
		if err != nil {
			b.Fatal(err)
		}
		if got.RecordID != bundle.RecordID {
			b.Fatalf("record_id = %q, want %q", got.RecordID, bundle.RecordID)
		}
	}
}

func syntheticTiKVProofBundles(n int) []model.ProofBundle {
	bundles := make([]model.ProofBundle, n)
	for i := range bundles {
		recordID := fmt.Sprintf("bench-record-%04d", i)
		bundles[i] = model.ProofBundle{
			SchemaVersion: model.SchemaProofBundle,
			RecordID:      recordID,
			SignedClaim: model.SignedClaim{
				SchemaVersion: model.SchemaSignedClaim,
				Claim: model.ClientClaim{
					SchemaVersion: model.SchemaClientClaim,
					TenantID:      "bench-tenant",
					ClientID:      "bench-client",
					KeyID:         "bench-key",
					Content: model.Content{
						HashAlg:       model.DefaultHashAlg,
						ContentHash:   bytes.Repeat([]byte{byte(i % 251)}, 32),
						ContentLength: 1024,
						StorageURI:    "bench://" + recordID,
					},
					Metadata: model.Metadata{EventType: "bench.synthetic"},
				},
			},
			ServerRecord: model.ServerRecord{
				SchemaVersion:   model.SchemaServerRecord,
				RecordID:        recordID,
				TenantID:        "bench-tenant",
				ClientID:        "bench-client",
				KeyID:           "bench-key",
				ReceivedAtUnixN: int64(1_000 + i),
				WAL:             model.WALPosition{SegmentID: 1, Offset: int64(i * 512), Sequence: uint64(i + 1)},
			},
			CommittedReceipt: model.CommittedReceipt{
				SchemaVersion: model.SchemaCommittedReceipt,
				RecordID:      recordID,
				BatchID:       "bench-batch",
				LeafIndex:     uint64(i),
				BatchRoot:     bytes.Repeat([]byte{1}, 32),
				ClosedAtUnixN: 1_000,
			},
			BatchProof: model.BatchProof{
				TreeAlg:   model.DefaultMerkleTreeAlg,
				LeafIndex: uint64(i),
				TreeSize:  uint64(n),
				AuditPath: [][]byte{bytes.Repeat([]byte{byte((i + 1) % 251)}, 32)},
			},
		}
	}
	return bundles
}
