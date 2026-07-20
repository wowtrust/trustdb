package proofstore

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

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
