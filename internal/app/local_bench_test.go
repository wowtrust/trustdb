package app

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/trustcrypto"
)

func BenchmarkCommitBatchSynthetic1024(b *testing.B) {
	_, serverPriv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		b.Fatal(err)
	}
	engine := LocalEngine{
		ServerID:         "bench-server",
		ServerKeyID:      "bench-server-key",
		ServerPrivateKey: serverPriv,
	}
	signed, records, accepted := syntheticCommitBatchInputs(1024)
	closedAt := time.Unix(200, 0)

	b.ReportAllocs()
	for b.Loop() {
		bundles, err := engine.CommitBatch("bench-batch", closedAt, signed, records, accepted)
		if err != nil {
			b.Fatal(err)
		}
		if len(bundles) != len(records) {
			b.Fatalf("bundles = %d, want %d", len(bundles), len(records))
		}
	}
}

func BenchmarkCommitBatchIndexesSynthetic1024(b *testing.B) {
	_, serverPriv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		b.Fatal(err)
	}
	engine := LocalEngine{ServerID: "bench-server", ServerKeyID: "bench-server-key", ServerPrivateKey: serverPriv}
	signed, records, accepted := syntheticCommitBatchInputs(1024)
	closedAt := time.Unix(200, 0)
	b.ReportAllocs()
	for b.Loop() {
		root, indexes, err := engine.CommitBatchIndexes("bench-batch", closedAt, signed, records, accepted)
		if err != nil {
			b.Fatal(err)
		}
		if root.TreeSize != uint64(len(records)) || len(indexes) != len(records) {
			b.Fatalf("root/indexes mismatch")
		}
	}
}

func syntheticCommitBatchInputs(n int) ([]model.SignedClaim, []model.ServerRecord, []model.AcceptedReceipt) {
	signed := make([]model.SignedClaim, n)
	records := make([]model.ServerRecord, n)
	accepted := make([]model.AcceptedReceipt, n)
	for i := range records {
		recordID := fmt.Sprintf("bench-record-%04d", i)
		contentHash := bytes.Repeat([]byte{byte(i % 251)}, 32)
		claimHash := bytes.Repeat([]byte{byte((i + 1) % 251)}, 32)
		signed[i] = model.SignedClaim{
			SchemaVersion: model.SchemaSignedClaim,
			Claim: model.ClientClaim{
				SchemaVersion:   model.SchemaClientClaim,
				TenantID:        "bench-tenant",
				ClientID:        "bench-client",
				KeyID:           "bench-client-key",
				ProducedAtUnixN: int64(100 + i),
				Nonce:           []byte{byte(i), byte(i >> 8)},
				IdempotencyKey:  recordID,
				Content: model.Content{
					HashAlg:       model.DefaultHashAlg,
					ContentHash:   contentHash,
					ContentLength: 1024,
					StorageURI:    "bench://" + recordID,
				},
				Metadata: model.Metadata{EventType: "bench.synthetic"},
			},
			Signature: model.Signature{
				Alg:       model.DefaultSignatureAlg,
				KeyID:     "bench-client-key",
				Signature: bytes.Repeat([]byte{byte((i + 2) % 251)}, 64),
			},
		}
		records[i] = model.ServerRecord{
			SchemaVersion:       model.SchemaServerRecord,
			RecordID:            recordID,
			TenantID:            "bench-tenant",
			ClientID:            "bench-client",
			KeyID:               "bench-client-key",
			ClaimHash:           claimHash,
			ClientSignatureHash: bytes.Repeat([]byte{byte((i + 3) % 251)}, 32),
			ReceivedAtUnixN:     int64(200 + i),
			WAL:                 model.WALPosition{SegmentID: 1, Offset: int64(i * 512), Sequence: uint64(i + 1)},
			Validation: model.Validation{
				PolicyVersion:       model.DefaultValidationPolicy,
				HashAlgAllowed:      true,
				SignatureAlgAllowed: true,
				KeyStatus:           model.KeyStatusValid,
			},
		}
		accepted[i] = model.AcceptedReceipt{
			SchemaVersion:   model.SchemaAcceptedReceipt,
			RecordID:        recordID,
			Status:          "accepted",
			ServerID:        "bench-server",
			ReceivedAtUnixN: int64(200 + i),
			WAL:             records[i].WAL,
			ServerSig: model.Signature{
				Alg:       model.DefaultSignatureAlg,
				KeyID:     "bench-server-key",
				Signature: bytes.Repeat([]byte{byte((i + 4) % 251)}, 64),
			},
		}
	}
	return signed, records, accepted
}
