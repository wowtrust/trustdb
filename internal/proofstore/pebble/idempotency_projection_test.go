package pebble

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"path/filepath"
	"sync"
	"testing"
	"time"

	pdb "github.com/cockroachdb/pebble"

	"github.com/wowtrust/trustdb/internal/claim"
	"github.com/wowtrust/trustdb/internal/idempotency"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/receipt"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

func TestIdempotencyProjectionFreshStoreReadyAcrossReopen(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "proofs")
	store := openProjectionStore(t, path)
	if !store.WALCheckpointPruneSafe() {
		t.Fatal("fresh Pebble store is not projection-ready")
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	store = openProjectionStore(t, path)
	defer store.Close()
	if !store.WALCheckpointPruneSafe() {
		t.Fatal("reopened Pebble store lost durable readiness")
	}
}

func TestPublishCommittedBatchPersistsExactDecision(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "proofs")
	store := openProjectionStore(t, path)
	bundle, decision := projectionFixture(t, "batch-a", "request-a", 1, 1)
	manifest := projectionManifest("batch-a", bundle.RecordID)
	if err := store.PutBundle(context.Background(), bundle); err != nil {
		t.Fatalf("PutBundle() error = %v", err)
	}
	decisions, err := store.PublishCommittedBatch(context.Background(), manifest, []model.ProofBundle{bundle})
	if err != nil {
		t.Fatalf("PublishCommittedBatch() error = %v", err)
	}
	if len(decisions) != 1 || !idempotency.Equivalent(decisions[0], decision) {
		t.Fatalf("PublishCommittedBatch() decisions = %+v, want %+v", decisions, decision)
	}
	assertProjectionDecision(t, store, decision)
	if got, err := store.GetManifest(context.Background(), manifest.BatchID); err != nil || got.State != model.BatchStateCommitted {
		t.Fatalf("GetManifest() = (%+v, %v)", got, err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	store = openProjectionStore(t, path)
	defer store.Close()
	assertProjectionDecision(t, store, decision)
}

func TestPublishCommittedBatchRequiresPersistedBundle(t *testing.T) {
	t.Parallel()
	store := openProjectionStore(t, filepath.Join(t.TempDir(), "proofs"))
	defer store.Close()
	bundle, _ := projectionFixture(t, "batch-missing-artifact", "request-missing-artifact", 5, 5)
	manifest := projectionManifest("batch-missing-artifact", bundle.RecordID)
	if _, err := store.PublishCommittedBatch(context.Background(), manifest, []model.ProofBundle{bundle}); trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("PublishCommittedBatch(missing bundle) code=%s err=%v, want data_loss", trusterr.CodeOf(err), err)
	}
	if _, err := store.GetManifest(context.Background(), manifest.BatchID); trusterr.CodeOf(err) != trusterr.CodeNotFound {
		t.Fatalf("GetManifest() after rejected publication code=%s err=%v, want not_found", trusterr.CodeOf(err), err)
	}
}

func TestCommittedProofBundleIsImmutable(t *testing.T) {
	t.Parallel()
	store := openProjectionStore(t, filepath.Join(t.TempDir(), "proofs"))
	defer store.Close()
	bundle, _ := projectionFixture(t, "batch-immutable", "request-immutable", 6, 6)
	if err := store.PutBundle(context.Background(), bundle); err != nil {
		t.Fatalf("PutBundle() error = %v", err)
	}
	if _, err := store.PublishCommittedBatch(
		context.Background(), projectionManifest("batch-immutable", bundle.RecordID), []model.ProofBundle{bundle},
	); err != nil {
		t.Fatalf("PublishCommittedBatch() error = %v", err)
	}
	if err := store.PutBundle(context.Background(), bundle); err != nil {
		t.Fatalf("PutBundle(idempotent) error = %v", err)
	}
	changed := bundle
	changed.AcceptedReceipt.ServerID = "different-server"
	if err := store.PutBundle(context.Background(), changed); trusterr.CodeOf(err) != trusterr.CodeAlreadyExists {
		t.Fatalf("PutBundle(changed committed bundle) code=%s err=%v, want already_exists", trusterr.CodeOf(err), err)
	}
	if !store.WALCheckpointPruneSafe() {
		t.Fatal("rejected committed bundle mutation invalidated a correct projection")
	}
}

func TestPublishCommittedBatchSerializesConflictingIdentities(t *testing.T) {
	t.Parallel()
	store := openProjectionStore(t, filepath.Join(t.TempDir(), "proofs"))
	defer store.Close()
	firstBundle, first := projectionFixture(t, "batch-a", "same-request", 1, 1)
	secondBundle, second := projectionFixture(t, "batch-b", "same-request", 2, 2)
	type publication struct {
		manifest model.BatchManifest
		decision model.IdempotencyDecision
		err      error
	}
	publications := []publication{
		{manifest: projectionManifest("batch-a", firstBundle.RecordID), decision: first},
		{manifest: projectionManifest("batch-b", secondBundle.RecordID), decision: second},
	}
	if err := store.PutBundle(context.Background(), firstBundle); err != nil {
		t.Fatalf("PutBundle(first) error = %v", err)
	}
	if err := store.PutBundle(context.Background(), secondBundle); err != nil {
		t.Fatalf("PutBundle(second) error = %v", err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range publications {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			bundle := firstBundle
			if i == 1 {
				bundle = secondBundle
			}
			_, publications[i].err = store.PublishCommittedBatch(
				context.Background(), publications[i].manifest, []model.ProofBundle{bundle},
			)
		}(i)
	}
	close(start)
	wg.Wait()
	successes, conflicts := 0, 0
	for i := range publications {
		if publications[i].err == nil {
			successes++
			continue
		}
		switch trusterr.CodeOf(publications[i].err) {
		case trusterr.CodeAlreadyExists:
			conflicts++
		default:
			t.Fatalf("PublishCommittedBatch() error = %v", publications[i].err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent publications: successes=%d conflicts=%d", successes, conflicts)
	}
}

func TestGenericCommittedManifestInvalidatesAndRebuildsProjection(t *testing.T) {
	t.Parallel()
	store := openProjectionStore(t, filepath.Join(t.TempDir(), "proofs"))
	defer store.Close()
	bundle, decision := projectionFixture(t, "batch-import", "request-import", 3, 3)
	if err := store.PutBundle(context.Background(), bundle); err != nil {
		t.Fatalf("PutBundle() error = %v", err)
	}
	if err := store.PutCheckpoint(context.Background(), model.WALCheckpoint{
		SchemaVersion: model.SchemaWALCheckpointContiguous,
		SegmentID:     1,
		LastSequence:  2,
		LastOffset:    64,
	}); err != nil {
		t.Fatalf("PutCheckpoint() error = %v", err)
	}
	if err := store.PutManifest(context.Background(), projectionManifest("batch-import", bundle.RecordID)); err != nil {
		t.Fatalf("PutManifest() error = %v", err)
	}
	if store.WALCheckpointPruneSafe() {
		t.Fatal("generic committed manifest left projection ready")
	}
	if _, found, err := store.GetCheckpoint(context.Background()); err != nil || found {
		t.Fatalf("GetCheckpoint() found=%v err=%v after invalidation", found, err)
	}
	if err := store.PutCheckpoint(context.Background(), model.WALCheckpoint{SegmentID: 1, LastSequence: 3}); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
		t.Fatalf("PutCheckpoint(unready) error=%v, want failed_precondition", err)
	}
	called := false
	ran, err := store.WithWALCheckpointPruneGuard(context.Background(), model.WALCheckpoint{LastSequence: 2}, func() error {
		called = true
		return nil
	})
	if err != nil || ran || called {
		t.Fatalf("WithWALCheckpointPruneGuard(invalidated) = ran=%v called=%v err=%v", ran, called, err)
	}
	if err := store.EnsureIdempotencyProjection(context.Background()); err != nil {
		t.Fatalf("EnsureIdempotencyProjection() error = %v", err)
	}
	if !store.WALCheckpointPruneSafe() {
		t.Fatal("rebuilt projection did not become ready")
	}
	assertProjectionDecision(t, store, decision)
}

func TestWALCheckpointPruneGuardSerializesManifestInvalidation(t *testing.T) {
	t.Parallel()
	store := openProjectionStore(t, filepath.Join(t.TempDir(), "proofs"))
	defer store.Close()
	cp := model.WALCheckpoint{
		SchemaVersion:   model.SchemaWALCheckpointContiguous,
		SegmentID:       2,
		LastSequence:    4,
		LastOffset:      256,
		BatchID:         "batch-before-import",
		RecordedAtUnixN: 10,
	}
	if err := store.PutCheckpoint(context.Background(), cp); err != nil {
		t.Fatalf("PutCheckpoint() error = %v", err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	guardDone := make(chan error, 1)
	go func() {
		ran, err := store.WithWALCheckpointPruneGuard(context.Background(), cp, func() error {
			close(entered)
			<-release
			return nil
		})
		if err == nil && !ran {
			err = trusterr.New(trusterr.CodeInternal, "prune guard unexpectedly skipped current checkpoint")
		}
		guardDone <- err
	}()
	<-entered
	invalidateDone := make(chan error, 1)
	go func() {
		invalidateDone <- store.PutManifest(context.Background(), projectionManifest("batch-import", "record-import"))
	}()
	select {
	case err := <-invalidateDone:
		t.Fatalf("manifest invalidation completed inside prune guard: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	if err := <-guardDone; err != nil {
		t.Fatalf("WithWALCheckpointPruneGuard() error = %v", err)
	}
	if err := <-invalidateDone; err != nil {
		t.Fatalf("PutManifest() after prune guard error = %v", err)
	}
	if store.WALCheckpointPruneSafe() {
		t.Fatal("manifest invalidation left projection prune-safe")
	}
}

func TestEnsureIdempotencyProjectionFailsClosedOnMissingBundle(t *testing.T) {
	t.Parallel()
	store := openProjectionStore(t, filepath.Join(t.TempDir(), "proofs"))
	defer store.Close()
	if err := store.PutManifest(context.Background(), projectionManifest("batch-missing", "missing-record")); err != nil {
		t.Fatalf("PutManifest() error = %v", err)
	}
	if err := store.EnsureIdempotencyProjection(context.Background()); trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("EnsureIdempotencyProjection() code=%s err=%v, want data_loss", trusterr.CodeOf(err), err)
	}
	if store.WALCheckpointPruneSafe() {
		t.Fatal("failed projection rebuild became prune-safe")
	}
}

func TestReopenLeavesInterruptedImportResumable(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "proofs")
	store := openProjectionStore(t, path)
	bundle, decision := projectionFixture(t, "batch-resume", "request-resume", 4, 4)
	if err := store.PutManifest(context.Background(), projectionManifest("batch-resume", bundle.RecordID)); err != nil {
		t.Fatalf("PutManifest() error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	store = openProjectionStore(t, path)
	defer store.Close()
	if store.WALCheckpointPruneSafe() {
		t.Fatal("interrupted import reopened as projection-ready")
	}
	if err := store.PutBundle(context.Background(), bundle); err != nil {
		t.Fatalf("PutBundle() during resumed import error = %v", err)
	}
	if err := store.EnsureIdempotencyProjection(context.Background()); err != nil {
		t.Fatalf("EnsureIdempotencyProjection() after resumed import error = %v", err)
	}
	assertProjectionDecision(t, store, decision)
}

func TestLegacyPebbleSchemasAreRejectedWithoutCompatibilityMigration(t *testing.T) {
	t.Parallel()
	for _, schema := range []string{"trustdb-proofstore-v2", "trustdb-proofstore-v3"} {
		schema := schema
		t.Run(schema, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "proofs")
			db, err := pdb.Open(path, &pdb.Options{})
			if err != nil {
				t.Fatalf("pdb.Open() error = %v", err)
			}
			if err := db.Set([]byte(storageSchemaKey), []byte(schema), pdb.Sync); err != nil {
				t.Fatalf("seed %s schema: %v", schema, err)
			}
			if err := db.Close(); err != nil {
				t.Fatalf("close seeded db: %v", err)
			}
			if _, err := Open(path); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
				t.Fatalf("Open(%s) code=%s err=%v, want failed_precondition", schema, trusterr.CodeOf(err), err)
			}
		})
	}
}

func openProjectionStore(t *testing.T, path string) *Store {
	t.Helper()
	store, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	return store
}

func projectionManifest(batchID string, recordIDs ...string) model.BatchManifest {
	return model.BatchManifest{
		SchemaVersion:    model.SchemaBatchManifest,
		BatchID:          batchID,
		State:            model.BatchStateCommitted,
		TreeAlg:          model.DefaultMerkleTreeAlg,
		TreeSize:         uint64(len(recordIDs)),
		RecordIDs:        append([]string(nil), recordIDs...),
		ClosedAtUnixN:    time.Unix(30, 0).UnixNano(),
		CommittedAtUnixN: time.Unix(31, 0).UnixNano(),
	}
}

func projectionFixture(t testing.TB, batchID, idempotencyKey string, seed byte, sequence uint64) (model.ProofBundle, model.IdempotencyDecision) {
	t.Helper()
	clientPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	serverPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{99}, ed25519.SeedSize))
	clientClaim := model.ClientClaim{
		SchemaVersion:   model.SchemaClientClaim,
		TenantID:        "tenant-a",
		ClientID:        "client-a",
		KeyID:           "client-key-a",
		ProducedAtUnixN: time.Unix(10+int64(seed), 0).UnixNano(),
		Nonce:           bytes.Repeat([]byte{seed}, 16),
		IdempotencyKey:  idempotencyKey,
		Content: model.Content{
			HashAlg:       model.DefaultHashAlg,
			ContentHash:   bytes.Repeat([]byte{seed + 10}, 32),
			ContentLength: int64(seed) + 1,
		},
		Metadata: model.Metadata{EventType: "test"},
	}
	signed, err := claim.Sign(clientClaim, clientPrivate)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	canonical, err := claim.Canonical(clientClaim)
	if err != nil {
		t.Fatalf("Canonical() error = %v", err)
	}
	claimHash, _ := trustcrypto.HashBytes(model.DefaultHashAlg, canonical)
	signatureHash, _ := trustcrypto.HashBytes(model.DefaultHashAlg, signed.Signature.Signature)
	position := model.WALPosition{SegmentID: 1, Offset: int64(sequence * 64), Sequence: sequence}
	record := model.ServerRecord{
		SchemaVersion:       model.SchemaServerRecord,
		RecordID:            claim.RecordID(canonical, signed.Signature),
		TenantID:            clientClaim.TenantID,
		ClientID:            clientClaim.ClientID,
		KeyID:               clientClaim.KeyID,
		ClaimHash:           claimHash,
		ClientSignatureHash: signatureHash,
		ReceivedAtUnixN:     time.Unix(20+int64(seed), 0).UnixNano(),
		WAL:                 position,
	}
	accepted := model.AcceptedReceipt{
		SchemaVersion:   model.SchemaAcceptedReceipt,
		RecordID:        record.RecordID,
		Status:          "accepted",
		ServerID:        "server-a",
		ReceivedAtUnixN: record.ReceivedAtUnixN,
		WAL:             position,
	}
	accepted, err = receipt.SignAccepted(accepted, "server-key-a", serverPrivate)
	if err != nil {
		t.Fatalf("SignAccepted() error = %v", err)
	}
	decision, err := idempotency.BuildDecision(batchID, signed, record, accepted)
	if err != nil {
		t.Fatalf("BuildDecision() error = %v", err)
	}
	bundle := model.ProofBundle{
		SchemaVersion:   model.SchemaProofBundle,
		RecordID:        record.RecordID,
		NodeID:          "server-a",
		SignedClaim:     signed,
		ServerRecord:    record,
		AcceptedReceipt: accepted,
		CommittedReceipt: model.CommittedReceipt{
			SchemaVersion: model.SchemaCommittedReceipt,
			RecordID:      record.RecordID,
			Status:        "committed",
			BatchID:       batchID,
			LeafIndex:     0,
			ClosedAtUnixN: time.Unix(30, 0).UnixNano(),
			NodeID:        "server-a",
		},
		BatchProof: model.BatchProof{
			TreeAlg:   model.DefaultMerkleTreeAlg,
			LeafIndex: 0,
			TreeSize:  1,
		},
	}
	return bundle, decision
}

func assertProjectionDecision(t *testing.T, store *Store, want model.IdempotencyDecision) {
	t.Helper()
	got, found, err := store.GetIdempotencyDecision(context.Background(), want.Identity)
	if err != nil || !found || !idempotency.Equivalent(got, want) {
		t.Fatalf("GetIdempotencyDecision() = (%+v, %v, %v), want %+v", got, found, err, want)
	}
}
