//go:build integration

package tikv_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/ryan-wong-coder/trustdb/internal/globallog"
	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/proofstore"
	"github.com/ryan-wong-coder/trustdb/internal/proofstore/proofstoretest"
	tikvstore "github.com/ryan-wong-coder/trustdb/internal/proofstore/tikv"
	"github.com/ryan-wong-coder/trustdb/internal/trustcrypto"
)

func TestTiKVConformance(t *testing.T) {
	requireTiKVIntegration(t)

	proofstoretest.RunConformance(t, func(t *testing.T) (proofstore.Store, func()) {
		store := openIntegrationStore(t, integrationNamespace(t, "conformance"))
		return store, func() { _ = store.Close() }
	})
}

func TestTiKVSharedNamespaceAcrossStores(t *testing.T) {
	requireTiKVIntegration(t)

	ctx := context.Background()
	namespace := integrationNamespace(t, "shared")
	nodeA := openIntegrationStore(t, namespace)
	defer nodeA.Close()
	nodeB := openIntegrationStore(t, namespace)
	defer nodeB.Close()

	want := model.WALCheckpoint{
		SchemaVersion:   model.SchemaWALCheckpoint,
		SegmentID:       7,
		LastSequence:    42,
		LastOffset:      4096,
		BatchID:         "batch-shared",
		RecordedAtUnixN: time.Now().UTC().UnixNano(),
	}
	if err := nodeA.PutCheckpoint(ctx, want); err != nil {
		t.Fatalf("nodeA PutCheckpoint: %v", err)
	}
	got, ok, err := nodeB.GetCheckpoint(ctx)
	if err != nil || !ok {
		t.Fatalf("nodeB GetCheckpoint ok=%v err=%v", ok, err)
	}
	if got.SegmentID != want.SegmentID || got.LastSequence != want.LastSequence || got.BatchID != want.BatchID {
		t.Fatalf("shared checkpoint = %+v, want %+v", got, want)
	}
}

func TestTiKVNamespaceIsolationAcrossStores(t *testing.T) {
	requireTiKVIntegration(t)

	ctx := context.Background()
	nodeA := openIntegrationStore(t, integrationNamespace(t, "isolation-a"))
	defer nodeA.Close()
	nodeB := openIntegrationStore(t, integrationNamespace(t, "isolation-b"))
	defer nodeB.Close()

	if err := nodeA.PutCheckpoint(ctx, model.WALCheckpoint{
		SchemaVersion:   model.SchemaWALCheckpoint,
		SegmentID:       1,
		LastSequence:    1,
		RecordedAtUnixN: time.Now().UTC().UnixNano(),
	}); err != nil {
		t.Fatalf("nodeA PutCheckpoint: %v", err)
	}
	if _, ok, err := nodeB.GetCheckpoint(ctx); err != nil || ok {
		t.Fatalf("nodeB GetCheckpoint ok=%v err=%v, want missing without error", ok, err)
	}
}

func TestTiKVPreparedManifestIndexIntegration(t *testing.T) {
	requireTiKVIntegration(t)

	ctx := context.Background()
	store := openIntegrationStore(t, integrationNamespace(t, "prepared-index"))
	defer store.Close()
	ready := model.BatchManifest{
		SchemaVersion:          model.SchemaBatchManifest,
		BatchID:                "ready",
		NodeID:                 "node-a",
		State:                  model.BatchStatePrepared,
		MaterializeNextUnixN:   10,
		MaterializeAttempts:    1,
		MaterializeFailureCode: "retry",
	}
	future := ready
	future.BatchID = "future"
	future.MaterializeNextUnixN = 1_000
	for _, manifest := range []model.BatchManifest{
		{SchemaVersion: model.SchemaBatchManifest, BatchID: "committed", State: model.BatchStateCommitted},
		future,
		ready,
	} {
		if err := store.PutManifest(ctx, manifest); err != nil {
			t.Fatalf("PutManifest(%s): %v", manifest.BatchID, err)
		}
	}

	got, err := store.ListPreparedManifests(ctx, "node-a", 100, 10)
	if err != nil {
		t.Fatalf("ListPreparedManifests: %v", err)
	}
	if len(got) != 1 || got[0].BatchID != ready.BatchID {
		t.Fatalf("prepared manifests = %#v", got)
	}
	ready.State = model.BatchStateCommitted
	if err := store.PutManifest(ctx, ready); err != nil {
		t.Fatalf("PutManifest(commit ready): %v", err)
	}
	got, err = store.ListPreparedManifests(ctx, "node-a", 100, 10)
	if err != nil {
		t.Fatalf("ListPreparedManifests(after commit): %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("prepared manifests after commit = %#v", got)
	}
}

func TestTiKVBatchTreeSnapshotIntegration(t *testing.T) {
	requireTiKVIntegration(t)

	ctx := context.Background()
	store := openIntegrationStore(t, integrationNamespace(t, "batch-tree-tiles"))
	defer store.Close()
	const leafCount = 1024
	snapshot := model.BatchTreeSnapshot{
		BatchID:        "batch-tree-tiles",
		CreatedAtUnixN: time.Now().UnixNano(),
		RecordIDs:      make([]string, leafCount),
		LeafHashes:     make([][32]byte, leafCount),
	}
	for i := range leafCount {
		snapshot.RecordIDs[i] = fmt.Sprintf("record-%04d", i)
		snapshot.LeafHashes[i][0] = byte(i)
	}
	for level, width := uint64(0), uint64(1); width <= leafCount; level, width = level+1, width*2 {
		for start := uint64(0); start < leafCount; start += width {
			node := model.BatchTreeSnapshotNode{Level: level, StartIndex: start, Width: width}
			if level == 0 {
				node.Hash = snapshot.LeafHashes[start]
			} else {
				node.Hash[0] = byte(level)
			}
			snapshot.Nodes = append(snapshot.Nodes, node)
		}
	}
	writer, ok := any(store).(proofstore.BatchTreeSnapshotWriter)
	if !ok {
		t.Fatal("TiKV store does not implement BatchTreeSnapshotWriter")
	}
	if err := writer.PutBatchTreeSnapshot(ctx, snapshot); err != nil {
		t.Fatalf("PutBatchTreeSnapshot: %v", err)
	}
	leaves, err := store.ListBatchTreeLeaves(ctx, model.BatchTreeLeafListOptions{BatchID: snapshot.BatchID, Limit: 2, AfterLeafIndex: 511, HasAfter: true})
	if err != nil || len(leaves) != 2 || leaves[0].LeafIndex != 512 || !bytes.Equal(leaves[0].LeafHash, snapshot.LeafHashes[512][:]) {
		t.Fatalf("cursor leaves = %+v, err=%v", leaves, err)
	}
	root, err := store.ListBatchTreeNodes(ctx, model.BatchTreeNodeListOptions{BatchID: snapshot.BatchID, Level: 10, Limit: 1})
	if err != nil || len(root) != 1 || root[0].Width != leafCount || !bytes.Equal(root[0].Hash, snapshot.Nodes[len(snapshot.Nodes)-1].Hash[:]) {
		t.Fatalf("root = %+v, err=%v", root, err)
	}
}

func TestTiKVGlobalLogConcurrentServicesRetryConflicts(t *testing.T) {
	requireTiKVIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	namespace := integrationNamespace(t, "global-log-concurrent")
	storeA := openIntegrationStore(t, namespace)
	defer storeA.Close()
	storeB := openIntegrationStore(t, namespace)
	defer storeB.Close()
	_, privateKey, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	newService := func(store globallog.Store, nodeID string) *globallog.Service {
		svc, err := globallog.New(globallog.Options{
			Store:      store,
			NodeID:     nodeID,
			LogID:      "integration-log",
			KeyID:      "integration-key",
			PrivateKey: privateKey,
		})
		if err != nil {
			t.Fatalf("globallog.New(%s): %v", nodeID, err)
		}
		return svc
	}
	services := []*globallog.Service{newService(storeA, "node-a"), newService(storeB, "node-b")}
	const appendsPerService = 8
	start := make(chan struct{})
	errs := make(chan error, len(services)*appendsPerService)
	var wg sync.WaitGroup
	for serviceIndex, svc := range services {
		for appendIndex := 0; appendIndex < appendsPerService; appendIndex++ {
			serviceIndex, appendIndex, svc := serviceIndex, appendIndex, svc
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				batchID := fmt.Sprintf("node-%d-batch-%d", serviceIndex, appendIndex)
				_, err := svc.AppendBatchRoot(ctx, model.BatchRoot{
					SchemaVersion: model.SchemaBatchRoot,
					BatchID:       batchID,
					BatchRoot:     bytes.Repeat([]byte{byte(serviceIndex*appendsPerService + appendIndex + 1)}, 32),
					TreeSize:      1,
				})
				if err != nil {
					errs <- fmt.Errorf("append %s: %w", batchID, err)
				}
			}()
		}
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if t.Failed() {
		return
	}
	state, found, err := storeA.GetGlobalLogState(ctx)
	if err != nil || !found {
		t.Fatalf("GetGlobalLogState found=%v err=%v", found, err)
	}
	wantSize := uint64(len(services) * appendsPerService)
	if state.TreeSize != wantSize {
		t.Fatalf("global tree_size = %d, want %d", state.TreeSize, wantSize)
	}
	for serviceIndex := range services {
		for appendIndex := 0; appendIndex < appendsPerService; appendIndex++ {
			batchID := fmt.Sprintf("node-%d-batch-%d", serviceIndex, appendIndex)
			if _, found, err := storeB.GetGlobalLeafByBatchID(ctx, batchID); err != nil || !found {
				t.Fatalf("GetGlobalLeafByBatchID(%q) found=%v err=%v", batchID, found, err)
			}
		}
	}
}

func requireTiKVIntegration(t *testing.T) {
	t.Helper()
	if strings := os.Getenv("TRUSTDB_TIKV_PD_ENDPOINTS"); strings == "" {
		t.Skip("set TRUSTDB_TIKV_PD_ENDPOINTS to run TiKV integration tests")
	}
}

func openIntegrationStore(t *testing.T, namespace string) *tikvstore.Store {
	t.Helper()
	store, err := tikvstore.OpenWithOptions(tikvstore.Options{
		PDAddressText:    os.Getenv("TRUSTDB_TIKV_PD_ENDPOINTS"),
		Keyspace:         os.Getenv("TRUSTDB_TIKV_KEYSPACE"),
		Namespace:        namespace,
		RecordIndexMode:  tikvstore.RecordIndexModeFull,
		ArtifactSyncMode: tikvstore.ArtifactSyncModeChunk,
	})
	if err != nil {
		t.Fatalf("open TiKV store: %v", err)
	}
	return store
}

func integrationNamespace(t *testing.T, prefix string) string {
	t.Helper()
	return "integration/" + prefix + "/" + uniqueTestID(t)
}

func uniqueTestID(t *testing.T) string {
	t.Helper()
	re := regexp.MustCompile(`[^A-Za-z0-9._-]+`)
	return fmt.Sprintf("%s/%d", re.ReplaceAllString(t.Name(), "_"), time.Now().UTC().UnixNano())
}
