package app

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/claim"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"github.com/wowtrust/trustdb/internal/wal"
)

func TestSubmitSignerFailureLeavesNoWALRecordAndExactRetryConverges(t *testing.T) {
	t.Parallel()
	clientPublic, clientPrivate, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}
	_, serverPrivate, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}
	contentHash, err := trustcrypto.HashBytes(model.DefaultHashAlg, []byte("plugin signer failure"))
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := claim.NewFileClaim(
		"tenant-a",
		"client-a",
		"client-key",
		time.Unix(100, 0),
		bytes.Repeat([]byte{1}, 16),
		"idem-plugin-failure",
		model.Content{HashAlg: model.DefaultHashAlg, ContentHash: contentHash, ContentLength: 21},
		model.Metadata{EventType: "file.snapshot"},
	)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := claim.Sign(unsigned, clientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "000000000001.wal")
	writer, err := wal.OpenWriter(path, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	delegate := trustcrypto.MustNewEd25519Signer("server-key", serverPrivate)
	serverSigner := &failCountSigner{delegate: delegate, remainingFailures: 1}
	engine := LocalEngine{
		ServerID:        "server-a",
		ServerKeyID:     "server-key",
		ClientPublicKey: trustcrypto.MustNewEd25519PublicKey("client-key", clientPublic),
		ServerSigner:    serverSigner,
		WAL:             writer,
		Idempotency:     NewIdempotencyIndex(),
		Now:             func() time.Time { return time.Unix(200, 0) },
	}
	if _, _, _, err := engine.Submit(context.Background(), signed); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first Submit() error = %v, want DeadlineExceeded", err)
	}
	records, err := wal.ReadAll(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("WAL records after signer failure = %d, want 0", len(records))
	}

	record, accepted, loaded, err := engine.Submit(context.Background(), signed)
	if err != nil {
		t.Fatalf("retry Submit() error = %v", err)
	}
	if loaded || record.WAL.Sequence != 1 || accepted.WAL != record.WAL {
		t.Fatalf("retry result loaded=%v record=%+v accepted=%+v", loaded, record.WAL, accepted.WAL)
	}
	replayedRecord, replayedAccepted, loaded, err := engine.Submit(context.Background(), signed)
	if err != nil {
		t.Fatalf("exact retry Submit() error = %v", err)
	}
	if !loaded || replayedRecord.WAL != record.WAL || replayedAccepted.WAL != accepted.WAL {
		t.Fatalf("exact retry did not converge: loaded=%v record=%+v accepted=%+v", loaded, replayedRecord.WAL, replayedAccepted.WAL)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	records, err = wal.ReadAll(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Position != record.WAL {
		t.Fatalf("final WAL records = %+v", records)
	}
}

type failCountSigner struct {
	delegate trustcrypto.Signer

	mu                sync.Mutex
	remainingFailures int
}

func (s *failCountSigner) Handle() trustcrypto.KeyHandle { return s.delegate.Handle() }

func (s *failCountSigner) Capabilities() trustcrypto.CapabilitySet {
	return s.delegate.Capabilities()
}

func (s *failCountSigner) PublicKey(ctx context.Context) (trustcrypto.PublicKeyDescriptor, error) {
	return s.delegate.PublicKey(ctx)
}

func (s *failCountSigner) Sign(ctx context.Context, message []byte) (model.Signature, error) {
	s.mu.Lock()
	if s.remainingFailures > 0 {
		s.remainingFailures--
		s.mu.Unlock()
		return model.Signature{}, context.DeadlineExceeded
	}
	s.mu.Unlock()
	return s.delegate.Sign(ctx, message)
}

var _ trustcrypto.Signer = (*failCountSigner)(nil)
