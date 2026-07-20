package batch

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"testing"
	"time"

	"github.com/ryan-wong-coder/trustdb/internal/app"
	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/trusterr"
)

func BenchmarkBatchProofModeInline1024(b *testing.B) {
	engine := benchmarkLocalEngine(b)
	items := benchmarkBatchItems(1024)
	closedAt := time.Unix(1_900, 0).UTC()
	svc := New(engine, benchmarkBatchStore{}, Options{ProofMode: ProofModeInline}, nil)
	defer svc.Shutdown(context.Background())

	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		if err := svc.persistBatch(context.Background(), fmt.Sprintf("bench-inline-%d", i), closedAt, items); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBatchProofModeAsync1024(b *testing.B) {
	engine := benchmarkLocalEngine(b)
	items := benchmarkBatchItems(1024)
	signed, records, accepted := splitBenchmarkBatchItems(items)
	closedAt := time.Unix(1_900, 0).UTC()
	svc := New(engine, benchmarkBatchStore{}, Options{ProofMode: ProofModeAsync}, nil)
	defer svc.Shutdown(context.Background())

	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		batchID := fmt.Sprintf("bench-async-%d", i)
		commit, err := svc.computeBatch(context.Background(), batchID, closedAt, signed, records, accepted, model.BatchComputeOptions{Mode: model.BatchComputePlanOnly, IncludeTree: true})
		if err != nil {
			b.Fatal(err)
		}
		if err := svc.writeIndexesAndRoot(context.Background(), commit.Indexes, commit.Root); err != nil {
			b.Fatal(err)
		}
		if err := svc.writeBatchTree(context.Background(), commit.Tree); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkLocalEngine(b *testing.B) app.LocalEngine {
	b.Helper()
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		b.Fatal(err)
	}
	return app.LocalEngine{
		ServerID:         "bench-server",
		ServerKeyID:      "bench-server-key",
		ServerPrivateKey: private,
		Now: func() time.Time {
			return time.Unix(1_900, 0).UTC()
		},
	}
}

func benchmarkBatchItems(n int) []Accepted {
	items := make([]Accepted, n)
	for i := range items {
		recordID := fmt.Sprintf("bench-batch-record-%04d", i)
		items[i] = Accepted{
			Signed: model.SignedClaim{
				SchemaVersion: model.SchemaSignedClaim,
				Claim: model.ClientClaim{
					SchemaVersion:  model.SchemaClientClaim,
					TenantID:       "bench-tenant",
					ClientID:       "bench-client",
					KeyID:          "bench-key",
					IdempotencyKey: recordID,
					Content: model.Content{
						HashAlg:       model.DefaultHashAlg,
						ContentHash:   []byte(recordID),
						ContentLength: 1024,
						StorageURI:    "bench://" + recordID,
					},
				},
			},
			Record: model.ServerRecord{
				SchemaVersion:   model.SchemaServerRecord,
				RecordID:        recordID,
				TenantID:        "bench-tenant",
				ClientID:        "bench-client",
				KeyID:           "bench-key",
				ReceivedAtUnixN: int64(1_000 + i),
				WAL: model.WALPosition{
					SegmentID: 1,
					Offset:    int64(i) * 1024,
					Sequence:  uint64(i + 1),
				},
			},
			Accepted: model.AcceptedReceipt{
				SchemaVersion: model.SchemaAcceptedReceipt,
				RecordID:      recordID,
				Status:        "accepted",
				WAL: model.WALPosition{
					SegmentID: 1,
					Offset:    int64(i) * 1024,
					Sequence:  uint64(i + 1),
				},
			},
		}
	}
	return items
}

func splitBenchmarkBatchItems(items []Accepted) ([]model.SignedClaim, []model.ServerRecord, []model.AcceptedReceipt) {
	signed := make([]model.SignedClaim, len(items))
	records := make([]model.ServerRecord, len(items))
	accepted := make([]model.AcceptedReceipt, len(items))
	for i := range items {
		signed[i] = items[i].Signed
		records[i] = items[i].Record
		accepted[i] = items[i].Accepted
	}
	return signed, records, accepted
}

type benchmarkBatchStore struct{}

func (benchmarkBatchStore) WALCheckpointPruneSafe() bool { return true }

func (benchmarkBatchStore) PutBundle(context.Context, model.ProofBundle) error { return nil }

func (benchmarkBatchStore) GetBundle(context.Context, string) (model.ProofBundle, error) {
	return model.ProofBundle{}, trusterr.New(trusterr.CodeNotFound, "proof bundle not found")
}

func (benchmarkBatchStore) PutRecordIndex(context.Context, model.RecordIndex) error { return nil }

func (benchmarkBatchStore) GetRecordIndex(context.Context, string) (model.RecordIndex, bool, error) {
	return model.RecordIndex{}, false, nil
}

func (benchmarkBatchStore) ListRecordIndexes(context.Context, model.RecordListOptions) ([]model.RecordIndex, error) {
	return nil, nil
}

func (benchmarkBatchStore) PutRoot(context.Context, model.BatchRoot) error { return nil }

func (benchmarkBatchStore) ListRoots(context.Context, int) ([]model.BatchRoot, error) {
	return nil, nil
}

func (benchmarkBatchStore) ListRootsAfter(context.Context, int64, int) ([]model.BatchRoot, error) {
	return nil, nil
}

func (benchmarkBatchStore) ListRootsPage(context.Context, model.RootListOptions) ([]model.BatchRoot, error) {
	return nil, nil
}

func (benchmarkBatchStore) LatestRoot(context.Context) (model.BatchRoot, error) {
	return model.BatchRoot{}, trusterr.New(trusterr.CodeNotFound, "batch root not found")
}

func (benchmarkBatchStore) PutBatchTreeArtifacts(context.Context, []model.BatchTreeLeaf, []model.BatchTreeNode) error {
	return nil
}

func (benchmarkBatchStore) PutBatchTreeSnapshot(context.Context, model.BatchTreeSnapshot) error {
	return nil
}

func (benchmarkBatchStore) ListBatchTreeLeaves(context.Context, model.BatchTreeLeafListOptions) ([]model.BatchTreeLeaf, error) {
	return nil, nil
}

func (benchmarkBatchStore) ListBatchTreeNodes(context.Context, model.BatchTreeNodeListOptions) ([]model.BatchTreeNode, error) {
	return nil, nil
}

func (benchmarkBatchStore) PutManifest(context.Context, model.BatchManifest) error { return nil }

func (benchmarkBatchStore) GetManifest(context.Context, string) (model.BatchManifest, error) {
	return model.BatchManifest{}, trusterr.New(trusterr.CodeNotFound, "batch manifest not found")
}

func (benchmarkBatchStore) ListManifests(context.Context) ([]model.BatchManifest, error) {
	return nil, nil
}

func (benchmarkBatchStore) PutCheckpoint(context.Context, model.WALCheckpoint) error { return nil }

func (benchmarkBatchStore) GetCheckpoint(context.Context) (model.WALCheckpoint, bool, error) {
	return model.WALCheckpoint{}, false, nil
}

func (benchmarkBatchStore) PutBatchArtifacts(context.Context, []model.ProofBundle, model.BatchRoot) error {
	return nil
}

func (benchmarkBatchStore) PutBatchIndexesAndRoot(context.Context, []model.RecordIndex, model.BatchRoot) error {
	return nil
}
