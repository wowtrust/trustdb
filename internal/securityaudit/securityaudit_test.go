package securityaudit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/trustcrypto"
)

func TestSignedAuditChainAndExportAcrossSuites(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		signer func(t *testing.T) trustcrypto.Signer
	}{
		{"intl-v1", newEd25519Signer},
		{"cn-sm-v1", newSM2Signer},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			logPath := filepath.Join(dir, "audit", "security.audit")
			checkpointPath := filepath.Join(dir, "audit", "security.checkpoint")
			writer := openTestWriter(t, logPath, checkpointPath, test.signer(t), nil)
			first, err := writer.Record(context.Background(), Draft{
				Actor: "security-admin", Roles: []string{"security-admin"}, Action: "security.policy.update",
				Object: "admin-policy", Result: "success", RequestID: "request-1", Source: "admin-http", PolicyVersion: 7,
				Context: map[string]string{"policy_digest": strings.Repeat("a", 64), "access_token": "must-not-leak"},
			})
			if err != nil {
				t.Fatal(err)
			}
			if first.Event.Context["access_token"] != "<redacted>" {
				t.Fatalf("sensitive context = %q", first.Event.Context["access_token"])
			}
			if got := time.Duration(first.Event.RetentionUntilUnix - first.Event.LocalTimeUnixNano); got != 180*24*time.Hour {
				t.Fatalf("retention duration=%s", got)
			}
			second, err := writer.Record(context.Background(), Draft{
				Actor: "backup-operator", Roles: []string{"backup-operator"}, Action: "backup.create",
				Object: "logical-backup", Result: "success", RequestID: "request-2", Source: "cli", PolicyVersion: 7,
			})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(second.Event.PreviousHash, first.EventHash) {
				t.Fatal("second event does not chain to first")
			}
			var exported bytes.Buffer
			stats, err := writer.ExportJSONL(context.Background(), &exported)
			if err != nil {
				t.Fatal(err)
			}
			publicKey := writer.PublicKey()
			if stats.Sequence != 2 {
				t.Fatalf("sequence = %d", stats.Sequence)
			}
			verified, err := VerifyExportJSONL(context.Background(), bytes.NewReader(exported.Bytes()), publicKey)
			if err != nil || verified.Sequence != 2 {
				t.Fatalf("verify export stats=%+v err=%v", verified, err)
			}
			tampered := bytes.Replace(exported.Bytes(), []byte(`"actor":"security-admin"`), []byte(`"actor":"security-admin-x"`), 1)
			if _, err := VerifyExportJSONL(context.Background(), bytes.NewReader(tampered), publicKey); err == nil {
				t.Fatal("tampered export verified")
			}
			newline := bytes.IndexByte(exported.Bytes(), '\n')
			if newline < 0 {
				t.Fatal("export has no manifest line")
			}
			trailingJSON := append([]byte(nil), exported.Bytes()[:newline]...)
			trailingJSON = append(trailingJSON, []byte(" {}")...)
			trailingJSON = append(trailingJSON, exported.Bytes()[newline:]...)
			if _, err := VerifyExportJSONL(context.Background(), bytes.NewReader(trailingJSON), publicKey); err == nil {
				t.Fatal("export line with trailing JSON verified")
			}
			checkpoint, err := writer.Checkpoint(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			checkpointJSON, err := json.Marshal(checkpoint)
			if err != nil {
				t.Fatal(err)
			}
			checkpointStats, err := VerifyCheckpointArtifact(context.Background(), bytes.NewReader(checkpointJSON), publicKey)
			if err != nil || checkpointStats.Sequence != 2 {
				t.Fatalf("verify checkpoint stats=%+v err=%v", checkpointStats, err)
			}
			checkpointJSON = append(checkpointJSON, []byte(" {}")...)
			if _, err := VerifyCheckpointArtifact(context.Background(), bytes.NewReader(checkpointJSON), publicKey); err == nil {
				t.Fatal("checkpoint artifact with trailing JSON verified")
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyLog(context.Background(), logPath, checkpointPath, publicKey); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAuditCrashTailRecoveryAndCheckpointRollbackDetection(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit", "security.audit")
	checkpointPath := filepath.Join(dir, "audit", "security.checkpoint")
	signer := newEd25519Signer(t)
	writer := openTestWriter(t, logPath, checkpointPath, signer, nil)
	if _, err := writer.Record(context.Background(), Draft{Actor: "system-admin", Action: "server.start", Object: "trustdb", Result: "success", Source: "server"}); err != nil {
		t.Fatal(err)
	}
	stats := writer.Stats()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("EVT1\x00\x00")); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	recovered := openTestWriter(t, logPath, checkpointPath, signer, nil)
	if recovered.Stats().LogBytes != stats.LogBytes {
		t.Fatalf("recovered bytes=%d want=%d", recovered.Stats().LogBytes, stats.LogBytes)
	}
	if err := recovered.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(logPath, int64(len(auditFileMagic))); err != nil {
		t.Fatal(err)
	}
	_, err = OpenWriter(context.Background(), testOptions(logPath, checkpointPath, signer, nil))
	if !errors.Is(err, ErrRollback) {
		t.Fatalf("rollback open error = %v", err)
	}
}

func TestClockEvidenceAndFailClosedSynchronization(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "time", "time-reference.json")
	now := time.Date(2026, 7, 26, 9, 0, 0, 0, time.UTC)
	if err := WriteReferenceSample(path, ReferenceSample{
		SchemaVersion: TimeSchema, Source: "chrony-ntp-auth", SampledAtUnixNano: now.Add(-time.Second).UnixNano(),
		OffsetNanos: int64(20 * time.Millisecond), UncertaintyNanos: int64(10 * time.Millisecond),
		Synchronized: true, Confidence: "authenticated",
	}); err != nil {
		t.Fatal(err)
	}
	clock, err := NewClock(ClockOptions{ReferencePath: path, MaxSampleAge: time.Minute, MaxClockDrift: time.Second, RequireSynchronized: true, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	_, evidence, err := clock.Sample(context.Background())
	if err != nil || !evidence.Synchronized || evidence.Status != "synchronized" {
		t.Fatalf("evidence=%+v err=%v", evidence, err)
	}
	staleClock, _ := NewClock(ClockOptions{ReferencePath: path, MaxSampleAge: 500 * time.Millisecond, MaxClockDrift: time.Second, RequireSynchronized: true, Now: func() time.Time { return now }})
	if _, evidence, err := staleClock.Sample(context.Background()); !errors.Is(err, ErrTimeUnsynchronized) || evidence.Status != "stale" {
		t.Fatalf("stale evidence=%+v err=%v", evidence, err)
	}
	if err := WriteReferenceSample(path, ReferenceSample{
		SchemaVersion: TimeSchema, Source: "chrony-ntp-auth", SampledAtUnixNano: now.UnixNano(),
		OffsetNanos: -1 << 63, Synchronized: true, Confidence: "authenticated",
	}); err != nil {
		t.Fatal(err)
	}
	if _, evidence, err := clock.Sample(context.Background()); !errors.Is(err, ErrTimeUnsynchronized) || evidence.Status != "drift-exceeded" {
		t.Fatalf("overflow drift evidence=%+v err=%v", evidence, err)
	}
	if err := WriteReferenceSample(path, ReferenceSample{
		SchemaVersion: TimeSchema, Source: "local-monitor", SampledAtUnixNano: now.UnixNano(),
		Synchronized: true, Confidence: "local",
	}); err != nil {
		t.Fatal(err)
	}
	if _, evidence, err := clock.Sample(context.Background()); !errors.Is(err, ErrTimeUnsynchronized) || evidence.Status != "unverified" {
		t.Fatalf("local confidence evidence=%+v err=%v", evidence, err)
	}
}

func TestUnsynchronizedTimeIsDurablyRecordedBeforeOperationIsBlocked(t *testing.T) {
	dir := t.TempDir()
	clock, err := NewClock(ClockOptions{
		ReferencePath: filepath.Join(dir, "time", "missing-time-reference.json"),
		MaxSampleAge:  time.Minute, MaxClockDrift: time.Second, RequireSynchronized: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	writer := openTestWriter(t, filepath.Join(dir, "audit", "security.audit"), filepath.Join(dir, "audit", "security.checkpoint"), newEd25519Signer(t), clock)
	defer writer.Close()
	event, err := writer.Record(context.Background(), Draft{
		Actor: "system-admin", Action: "system.configuration", Object: "trustdb", Result: "authorized", Source: "test",
	})
	if !errors.Is(err, ErrTimeUnsynchronized) {
		t.Fatalf("record error=%v", err)
	}
	if event.Event.Sequence != 1 || event.Event.Result != "blocked" || event.Event.Time.Status != "unavailable" || event.Event.Time.Synchronized {
		t.Fatalf("blocked event=%+v", event.Event)
	}
	stats, err := writer.Verify(context.Background())
	if err != nil || stats.Sequence != 1 {
		t.Fatalf("verify stats=%+v err=%v", stats, err)
	}
}

func TestAuditCapacityFailsBeforeMutation(t *testing.T) {
	dir := t.TempDir()
	signer := newEd25519Signer(t)
	opts := testOptions(filepath.Join(dir, "audit", "security.audit"), filepath.Join(dir, "audit", "security.checkpoint"), signer, nil)
	opts.MaxBytes = 1 << 20
	writer, err := OpenWriter(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	before := writer.Stats()
	writer.maxBytes = before.LogBytes + 1
	if _, err := writer.Record(context.Background(), Draft{Actor: "audit-admin", Action: "audit.export", Object: "security-audit", Result: "success", Source: "cli"}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity error = %v", err)
	}
	if after := writer.Stats(); after.Sequence != before.Sequence || after.LogBytes != before.LogBytes {
		t.Fatalf("capacity failure mutated stats: before=%+v after=%+v", before, after)
	}
}

func TestConcurrentWritersRefreshAndSerializeChainHead(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit", "security.audit")
	checkpointPath := filepath.Join(dir, "audit", "security.checkpoint")
	signer := newEd25519Signer(t)
	first := openTestWriter(t, logPath, checkpointPath, signer, nil)
	defer first.Close()
	second := openTestWriter(t, logPath, checkpointPath, signer, nil)
	defer second.Close()
	const perWriter = 25
	var wg sync.WaitGroup
	errorsChannel := make(chan error, 2)
	for index, writer := range []*Writer{first, second} {
		wg.Add(1)
		go func(index int, writer *Writer) {
			defer wg.Done()
			for event := 0; event < perWriter; event++ {
				_, err := writer.Record(context.Background(), Draft{
					Actor: "system-admin", Action: "concurrency.test", Object: "writer", Result: "success", Source: "test",
					RequestID: fmt.Sprintf("writer-%d-event-%d", index, event),
				})
				if err != nil {
					errorsChannel <- err
					return
				}
			}
		}(index, writer)
	}
	wg.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Fatal(err)
	}
	stats, err := first.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Sequence != 2*perWriter {
		t.Fatalf("sequence=%d want=%d", stats.Sequence, 2*perWriter)
	}
}

func TestSlowExportDoesNotHoldTheCrossProcessWriterLock(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit", "security.audit")
	checkpointPath := filepath.Join(dir, "audit", "security.checkpoint")
	signer := newEd25519Signer(t)
	exporter := openTestWriter(t, logPath, checkpointPath, signer, nil)
	defer exporter.Close()
	writer := openTestWriter(t, logPath, checkpointPath, signer, nil)
	defer writer.Close()
	if _, err := exporter.Record(context.Background(), Draft{Actor: "audit-admin", Action: "audit.export", Object: "security-audit", Result: "authorized", Source: "test"}); err != nil {
		t.Fatal(err)
	}
	output := &blockingOutput{started: make(chan struct{}), release: make(chan struct{})}
	exportDone := make(chan error, 1)
	go func() {
		_, err := exporter.ExportJSONL(context.Background(), output)
		exportDone <- err
	}()
	select {
	case <-output.started:
	case <-time.After(2 * time.Second):
		t.Fatal("export did not start")
	}
	writeDone := make(chan error, 1)
	go func() {
		_, err := writer.Record(context.Background(), Draft{Actor: "system-admin", Action: "system.operation", Object: "trustdb", Result: "success", Source: "test"})
		writeDone <- err
	}()
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("audit write blocked behind slow export output")
	}
	close(output.release)
	if err := <-exportDone; err != nil {
		t.Fatal(err)
	}
}

type blockingOutput struct {
	once    sync.Once
	started chan struct{}
	release chan struct{}
}

func (w *blockingOutput) Write(data []byte) (int, error) {
	w.once.Do(func() { close(w.started) })
	<-w.release
	return len(data), nil
}

func openTestWriter(t *testing.T, logPath, checkpointPath string, signer trustcrypto.Signer, clock Clock) *Writer {
	t.Helper()
	writer, err := OpenWriter(context.Background(), testOptions(logPath, checkpointPath, signer, clock))
	if err != nil {
		t.Fatal(err)
	}
	return writer
}

func testOptions(logPath, checkpointPath string, signer trustcrypto.Signer, clock Clock) Options {
	return Options{Path: logPath, CheckpointPath: checkpointPath, MaxBytes: 16 << 20, Retention: 180 * 24 * time.Hour, Signer: signer, Clock: clock}
}

func newEd25519Signer(t *testing.T) trustcrypto.Signer {
	t.Helper()
	_, privateKey, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := trustcrypto.NewEd25519Signer("audit-ed25519", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func newSM2Signer(t *testing.T) trustcrypto.Signer {
	t.Helper()
	_, privateKey, err := trustcrypto.GenerateSM2Key()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := trustcrypto.NewSM2Signer("audit-sm2", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}
