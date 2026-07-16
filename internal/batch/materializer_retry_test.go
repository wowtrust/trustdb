package batch

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/proofstore"
	"github.com/ryan-wong-coder/trustdb/internal/trusterr"
)

type retryMaterializeEngine struct {
	mu        sync.Mutex
	failures  int
	permanent bool
}

func (e *retryMaterializeEngine) CommitBatchIndexes(batchID string, closedAt time.Time, signed []model.SignedClaim, records []model.ServerRecord, accepted []model.AcceptedReceipt) (model.BatchRoot, []model.RecordIndex, error) {
	return fakeEngine{}.CommitBatchIndexes(batchID, closedAt, signed, records, accepted)
}

func (e *retryMaterializeEngine) CommitBatch(batchID string, closedAt time.Time, signed []model.SignedClaim, records []model.ServerRecord, accepted []model.AcceptedReceipt) ([]model.ProofBundle, error) {
	e.mu.Lock()
	if e.failures == 0 {
		e.failures++
		permanent := e.permanent
		e.mu.Unlock()
		if permanent {
			return nil, trusterr.New(trusterr.CodeDataLoss, "broken deterministic input")
		}
		return nil, errors.New("temporary materializer failure")
	}
	e.mu.Unlock()
	return fakeEngine{}.CommitBatch(batchID, closedAt, signed, records, accepted)
}

func TestAsyncMaterializerRetriesPreparedManifest(t *testing.T) {
	store := proofstore.LocalStore{Root: t.TempDir()}
	items := []Accepted{{Signed: signed("retry-record"), Record: recordWithWAL("retry-record", 91), Accepted: accepted("retry-record")}}
	engine := &retryMaterializeEngine{}
	svc := New(engine, store, Options{
		QueueSize: 4, MaxRecords: 1, MaxDelay: time.Hour, ProofMode: ProofModeAsync,
		MaterializerWorkers: 1, MaterializerQueueSize: 1, MaterializerPollInterval: 10 * time.Millisecond,
		LoadBatchItems: func(context.Context, model.BatchManifest) ([]Accepted, error) { return cloneAcceptedItems(items), nil },
	}, nil)
	defer svc.Shutdown(context.Background())
	if err := svc.Enqueue(context.Background(), items[0].Signed, items[0].Record, items[0].Accepted); err != nil {
		t.Fatal(err)
	}
	proof := waitForProof(t, svc, "retry-record")
	manifest, err := store.GetManifest(context.Background(), proof.CommittedReceipt.BatchID)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.State != model.BatchStateCommitted || manifest.MaterializeAttempts != 1 {
		t.Fatalf("manifest=%+v", manifest)
	}
}

func TestAsyncMaterializerMarksPermanentFailure(t *testing.T) {
	store := proofstore.LocalStore{Root: t.TempDir()}
	engine := &retryMaterializeEngine{permanent: true}
	svc := New(engine, store, Options{QueueSize: 4, MaxRecords: 1, MaxDelay: time.Hour, ProofMode: ProofModeAsync, MaterializerWorkers: 1, MaterializerQueueSize: 1, MaterializerPollInterval: 10 * time.Millisecond}, nil)
	defer svc.Shutdown(context.Background())
	if err := svc.Enqueue(context.Background(), signed("failed-record"), recordWithWAL("failed-record", 92), accepted("failed-record")); err != nil {
		t.Fatal(err)
	}
	idx := waitForRecordIndex(t, svc, "failed-record")
	manifest := waitForManifestState(t, store, idx.BatchID, model.BatchStateFailed)
	if manifest.MaterializeFailureCode != string(trusterr.CodeDataLoss) || manifest.MaterializeAttempts != 1 {
		t.Fatalf("manifest=%+v", manifest)
	}
}
