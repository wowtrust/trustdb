package batch

import (
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/app"
	"github.com/wowtrust/trustdb/internal/claim"
	"github.com/wowtrust/trustdb/internal/idempotency"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/proofstore"
	"github.com/wowtrust/trustdb/internal/wal"
)

type publishingCheckpointStore struct {
	proofstore.LocalStore

	mu          sync.Mutex
	publishErr  error
	events      []string
	manifests   []model.BatchManifest
	decisionSet [][]model.IdempotencyDecision
}

func (*publishingCheckpointStore) WALCheckpointPruneSafe() bool { return true }

func (s *publishingCheckpointStore) PublishCommittedBatch(ctx context.Context, manifest model.BatchManifest, bundles []model.ProofBundle) ([]model.IdempotencyDecision, error) {
	decisions := make([]model.IdempotencyDecision, 0, len(bundles))
	for i := range bundles {
		if bundles[i].SignedClaim.Claim.IdempotencyKey == "" {
			continue
		}
		decision, err := idempotency.BuildDecision(
			manifest.BatchID,
			bundles[i].SignedClaim,
			bundles[i].ServerRecord,
			bundles[i].AcceptedReceipt,
		)
		if err != nil {
			return nil, err
		}
		decisions = append(decisions, decision)
	}
	s.mu.Lock()
	s.events = append(s.events, "publish")
	s.manifests = append(s.manifests, manifest)
	s.decisionSet = append(s.decisionSet, append([]model.IdempotencyDecision(nil), decisions...))
	err := s.publishErr
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if err := s.LocalStore.PutManifest(ctx, manifest); err != nil {
		return nil, err
	}
	return decisions, nil
}

func (s *publishingCheckpointStore) PutCheckpoint(ctx context.Context, cp model.WALCheckpoint) error {
	s.mu.Lock()
	s.events = append(s.events, "checkpoint")
	s.mu.Unlock()
	return s.LocalStore.PutCheckpoint(ctx, cp)
}

func (s *publishingCheckpointStore) snapshot() ([]string, []model.BatchManifest, [][]model.IdempotencyDecision) {
	s.mu.Lock()
	defer s.mu.Unlock()
	events := append([]string(nil), s.events...)
	manifests := append([]model.BatchManifest(nil), s.manifests...)
	decisions := make([][]model.IdempotencyDecision, len(s.decisionSet))
	for i := range s.decisionSet {
		decisions[i] = append([]model.IdempotencyDecision(nil), s.decisionSet[i]...)
	}
	return events, manifests, decisions
}

func TestServicePublishesIdempotencyBeforeCheckpoint(t *testing.T) {
	store := &publishingCheckpointStore{LocalStore: proofstore.LocalStore{Root: t.TempDir()}}
	svc := New(fakeEngine{}, store, Options{}, nil)
	defer svc.Shutdown(context.Background())
	item := validIdempotencyAccepted(t, "keyed")
	if err := svc.persistBatch(context.Background(), "batch-keyed", time.Unix(0, 1).UTC(), []Accepted{item}); err != nil {
		t.Fatalf("persistBatch() error = %v", err)
	}
	events, manifests, decisions := store.snapshot()
	if len(events) != 2 || events[0] != "publish" || events[1] != "checkpoint" {
		t.Fatalf("events = %v, want [publish checkpoint]", events)
	}
	if len(manifests) != 1 || manifests[0].State != model.BatchStateCommitted {
		t.Fatalf("published manifests = %+v", manifests)
	}
	if len(decisions) != 1 || len(decisions[0]) != 1 || decisions[0][0].Record.RecordID != item.Record.RecordID {
		t.Fatalf("published decisions = %+v", decisions)
	}
	cp, found := readCheckpointExact(t, store)
	if !found || cp.LastSequence != item.Record.WAL.Sequence {
		t.Fatalf("checkpoint = %+v found=%v", cp, found)
	}
}

func TestServicePublicationFailurePreventsCheckpoint(t *testing.T) {
	publishErr := errors.New("injected publication failure")
	store := &publishingCheckpointStore{
		LocalStore: proofstore.LocalStore{Root: t.TempDir()},
		publishErr: publishErr,
	}
	svc := New(fakeEngine{}, store, Options{}, nil)
	defer svc.Shutdown(context.Background())
	item := validIdempotencyAccepted(t, "failed")
	if err := svc.persistBatch(context.Background(), "batch-failed", time.Unix(0, 1).UTC(), []Accepted{item}); !errors.Is(err, publishErr) {
		t.Fatalf("persistBatch() error = %v, want %v", err, publishErr)
	}
	events, _, decisions := store.snapshot()
	if len(events) != 1 || events[0] != "publish" || len(decisions) != 1 || len(decisions[0]) != 1 {
		t.Fatalf("failed publication events=%v decisions=%+v", events, decisions)
	}
	if cp, found := readCheckpointExact(t, store); found {
		t.Fatalf("checkpoint after failed publication = %+v", cp)
	}
}

func TestServiceKeepsEmptyIdempotencyKeyOptOut(t *testing.T) {
	store := &publishingCheckpointStore{LocalStore: proofstore.LocalStore{Root: t.TempDir()}}
	svc := New(fakeEngine{}, store, Options{}, nil)
	defer svc.Shutdown(context.Background())
	item := validIdempotencyAccepted(t, "")
	if err := svc.persistBatch(context.Background(), "batch-unkeyed", time.Unix(0, 1).UTC(), []Accepted{item}); err != nil {
		t.Fatalf("persistBatch() error = %v", err)
	}
	events, _, decisions := store.snapshot()
	if len(events) != 2 || len(decisions) != 1 || len(decisions[0]) != 0 {
		t.Fatalf("unkeyed publication events=%v decisions=%+v", events, decisions)
	}
}

func validIdempotencyAccepted(t *testing.T, idempotencyKey string) Accepted {
	t.Helper()
	clientPublic, clientPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(client) error = %v", err)
	}
	_, serverPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(server) error = %v", err)
	}
	createdAt := time.Unix(1700000000, 0).UTC()
	unsigned, err := claim.NewFileClaim(
		"tenant-a", "client-a", "client-key", createdAt, make([]byte, 16), "temporary-key",
		model.Content{HashAlg: model.DefaultHashAlg, ContentHash: make([]byte, 32)},
		model.Metadata{EventType: "batch-test"},
	)
	if err != nil {
		t.Fatalf("NewFileClaim() error = %v", err)
	}
	unsigned.IdempotencyKey = idempotencyKey
	signed, err := claim.Sign(unsigned, clientPrivate)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	writer, err := wal.OpenWriter(filepath.Join(t.TempDir(), "records.wal"), 1)
	if err != nil {
		t.Fatalf("OpenWriter() error = %v", err)
	}
	engine := app.LocalEngine{
		ServerID:         "server-a",
		ServerKeyID:      "server-key",
		ClientPublicKey:  clientPublic,
		ServerPrivateKey: serverPrivate,
		WAL:              writer,
		Idempotency:      app.NewIdempotencyIndex(),
		Now:              func() time.Time { return createdAt },
	}
	record, accepted, _, err := engine.Submit(context.Background(), signed)
	if closeErr := writer.Close(); err == nil && closeErr != nil {
		err = closeErr
	}
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	return Accepted{Signed: signed, Record: record, Accepted: accepted}
}
