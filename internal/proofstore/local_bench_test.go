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

func BenchmarkLocalStoreRootFirstPage4096(b *testing.B) {
	store := localRootBenchStore(b, 4096)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		got, err := store.ListRootsPage(context.Background(), model.RootListOptions{Limit: 100, Direction: model.RecordListDirectionDesc})
		if err != nil {
			b.Fatal(err)
		}
		if len(got) != 100 || got[0].ClosedAtUnixN != 4096 || got[99].ClosedAtUnixN != 3997 {
			b.Fatalf("unexpected page bounds: len=%d first=%d last=%d", len(got), got[0].ClosedAtUnixN, got[len(got)-1].ClosedAtUnixN)
		}
	}
}

func BenchmarkLocalStoreRootsAfterLateCursor4096(b *testing.B) {
	store := localRootBenchStore(b, 4096)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		got, err := store.ListRootsAfter(context.Background(), 3996, 100)
		if err != nil {
			b.Fatal(err)
		}
		if len(got) != 100 || got[0].ClosedAtUnixN != 3997 || got[99].ClosedAtUnixN != 4096 {
			b.Fatalf("unexpected page bounds: len=%d first=%d last=%d", len(got), got[0].ClosedAtUnixN, got[len(got)-1].ClosedAtUnixN)
		}
	}
}

func localRootBenchStore(b *testing.B, count int) LocalStore {
	b.Helper()
	store := LocalStore{Root: b.TempDir()}
	if err := os.MkdirAll(store.rootDir(), 0o755); err != nil {
		b.Fatal(err)
	}
	for i := range count {
		root := model.BatchRoot{
			SchemaVersion: model.SchemaBatchRoot,
			BatchID:       fmt.Sprintf("batch-%04d", i),
			BatchRoot:     make([]byte, 32),
			TreeSize:      1,
			ClosedAtUnixN: int64(i + 1),
		}
		data, err := cborx.Marshal(root)
		if err != nil {
			b.Fatal(err)
		}
		name := fmt.Sprintf("%020d_%s.tdroot", root.ClosedAtUnixN, safeFileName(root.BatchID))
		if err := os.WriteFile(filepath.Join(store.rootDir(), name), data, 0o600); err != nil {
			b.Fatal(err)
		}
	}
	return store
}

func BenchmarkLocalStoreManifestsAfterLateCursor4096(b *testing.B) {
	store := LocalStore{Root: b.TempDir()}
	if err := os.MkdirAll(store.manifestDir(), 0o755); err != nil {
		b.Fatal(err)
	}
	for i := range 4096 {
		manifest := model.BatchManifest{
			SchemaVersion: model.SchemaBatchManifest,
			BatchID:       fmt.Sprintf("batch-%04d", i),
			State:         model.BatchStateCommitted,
		}
		data, err := cborx.Marshal(manifest)
		if err != nil {
			b.Fatal(err)
		}
		if err := os.WriteFile(store.manifestPath(manifest.BatchID), data, 0o600); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		got, err := store.ListManifestsAfter(context.Background(), "batch-3995", 100)
		if err != nil {
			b.Fatal(err)
		}
		if len(got) != 100 || got[0].BatchID != "batch-3996" || got[99].BatchID != "batch-4095" {
			b.Fatalf("unexpected page: len=%d first=%s last=%s", len(got), got[0].BatchID, got[len(got)-1].BatchID)
		}
	}
}

func BenchmarkLocalStoreGlobalNodesAfterLateCursor4096(b *testing.B) {
	store := LocalStore{Root: b.TempDir()}
	if err := os.MkdirAll(store.globalNodeDir(), 0o755); err != nil {
		b.Fatal(err)
	}
	for i := range 4096 {
		node := model.GlobalLogNode{
			SchemaVersion: model.SchemaGlobalLogNode,
			Level:         0,
			StartIndex:    uint64(i),
			Width:         1,
			Hash:          make([]byte, 32),
		}
		data, err := cborx.Marshal(node)
		if err != nil {
			b.Fatal(err)
		}
		if err := os.WriteFile(store.globalNodePath(node.Level, node.StartIndex), data, 0o600); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		got, err := store.ListGlobalLogNodesAfter(context.Background(), 0, 3995, 100)
		if err != nil {
			b.Fatal(err)
		}
		if len(got) != 100 || got[0].StartIndex != 3996 || got[99].StartIndex != 4095 {
			b.Fatalf("unexpected page: len=%d first=%d last=%d", len(got), got[0].StartIndex, got[len(got)-1].StartIndex)
		}
	}
}

func BenchmarkLocalStorePendingGlobalLogWithPublishedHistory4096(b *testing.B) {
	store := LocalStore{Root: b.TempDir()}
	if err := os.MkdirAll(store.globalOutboxStatusDir(model.AnchorStatePublished), 0o755); err != nil {
		b.Fatal(err)
	}
	for index := range 4096 {
		item := model.GlobalLogOutboxItem{
			SchemaVersion:   model.SchemaGlobalLogOutbox,
			BatchID:         fmt.Sprintf("batch-%08d", index),
			Status:          model.AnchorStatePublished,
			EnqueuedAtUnixN: int64(index + 1),
		}
		data, err := cborx.Marshal(item)
		if err != nil {
			b.Fatal(err)
		}
		if err := os.WriteFile(store.globalOutboxPath(item.Status, item.BatchID), data, 0o600); err != nil {
			b.Fatal(err)
		}
	}
	pending := model.GlobalLogOutboxItem{
		SchemaVersion:   model.SchemaGlobalLogOutbox,
		BatchID:         "batch-pending",
		Status:          model.AnchorStatePending,
		EnqueuedAtUnixN: 4097,
	}
	if err := store.EnqueueGlobalLog(context.Background(), pending); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		items, err := store.ListPendingGlobalLog(context.Background(), 4098, 64)
		if err != nil {
			b.Fatal(err)
		}
		if len(items) != 1 || items[0].BatchID != pending.BatchID {
			b.Fatalf("pending items = %+v", items)
		}
	}
}
