package proofstore

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ryan-wong-coder/trustdb/internal/cborx"
	"github.com/ryan-wong-coder/trustdb/internal/model"
)

func BenchmarkLocalStoreLatestRoot4096(b *testing.B) {
	store := LocalStore{Root: b.TempDir()}
	if err := os.MkdirAll(store.rootDir(), 0o755); err != nil {
		b.Fatal(err)
	}
	for i := range 4095 {
		name := fmt.Sprintf("%020d_batch-%04d.tdroot", i+1, i+1)
		if err := os.WriteFile(filepath.Join(store.rootDir(), name), nil, 0o600); err != nil {
			b.Fatal(err)
		}
	}
	latest := model.BatchRoot{
		SchemaVersion: model.SchemaBatchRoot,
		BatchID:       "batch-4096",
		BatchRoot:     make([]byte, 32),
		TreeSize:      1,
		ClosedAtUnixN: 4096,
	}
	if err := store.PutRoot(context.Background(), latest); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		got, err := store.LatestRoot(context.Background())
		if err != nil {
			b.Fatal(err)
		}
		if got.BatchID != latest.BatchID {
			b.Fatalf("latest root = %q, want %q", got.BatchID, latest.BatchID)
		}
	}
}

func BenchmarkLocalStoreGlobalLeafFirstPage4096(b *testing.B) {
	store := LocalStore{Root: b.TempDir()}
	if err := os.MkdirAll(store.globalLeafDir(), 0o755); err != nil {
		b.Fatal(err)
	}
	for i := range 4096 {
		leaf := model.GlobalLogLeaf{
			SchemaVersion: model.SchemaGlobalLogLeaf,
			LeafIndex:     uint64(i),
			BatchID:       fmt.Sprintf("batch-%04d", i),
			BatchRoot:     make([]byte, 32),
		}
		data, err := cborx.Marshal(leaf)
		if err != nil {
			b.Fatal(err)
		}
		if err := os.WriteFile(store.globalLeafPath(leaf.LeafIndex), data, 0o600); err != nil {
			b.Fatal(err)
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		got, err := store.ListGlobalLeavesPage(context.Background(), model.GlobalLeafListOptions{Limit: 100})
		if err != nil {
			b.Fatal(err)
		}
		if len(got) != 100 || got[0].LeafIndex != 4095 || got[99].LeafIndex != 3996 {
			b.Fatalf("unexpected page bounds: len=%d first=%d last=%d", len(got), got[0].LeafIndex, got[len(got)-1].LeafIndex)
		}
	}
}

func BenchmarkLocalStoreRecordFirstPage4096(b *testing.B) {
	store := LocalStore{Root: b.TempDir()}
	if err := os.MkdirAll(store.recordByTimeDir(), 0o755); err != nil {
		b.Fatal(err)
	}
	for i := range 4096 {
		idx := model.RecordIndex{
			SchemaVersion:   model.SchemaRecordIndex,
			RecordID:        fmt.Sprintf("tr1record-%04d", i),
			ReceivedAtUnixN: int64(i + 1),
			BatchID:         "batch-benchmark",
			TenantID:        "tenant-benchmark",
			ClientID:        "client-benchmark",
			ProofLevel:      "L3",
		}
		data, err := cborx.Marshal(idx)
		if err != nil {
			b.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(store.recordByTimeDir(), store.recordIndexName(idx)), data, 0o600); err != nil {
			b.Fatal(err)
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		got, err := store.ListRecordIndexes(context.Background(), model.RecordListOptions{Limit: 100})
		if err != nil {
			b.Fatal(err)
		}
		if len(got) != 100 || got[0].ReceivedAtUnixN != 4096 || got[99].ReceivedAtUnixN != 3997 {
			b.Fatalf("unexpected page bounds: len=%d first=%d last=%d", len(got), got[0].ReceivedAtUnixN, got[len(got)-1].ReceivedAtUnixN)
		}
	}
}
