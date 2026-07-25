package securityaudit

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sync"
	"time"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
)

var auditFileMagic = [8]byte{'T', 'D', 'B', 'A', 'U', 'D', '1', '\n'}

const (
	eventDomain      = "trustdb.security-audit-event.v1"
	checkpointDomain = "trustdb.security-audit-checkpoint.v1"
)

type Options struct {
	Path           string
	CheckpointPath string
	MaxBytes       int64
	Retention      time.Duration
	Signer         trustcrypto.Signer
	Clock          Clock
}

type Writer struct {
	mu             sync.Mutex
	file           *os.File
	path           string
	checkpointPath string
	maxBytes       int64
	retention      time.Duration
	signer         trustcrypto.Signer
	publicKey      trustcrypto.PublicKeyDescriptor
	clock          Clock
	stats          Stats
	closed         bool
}

type scanResult struct {
	stats        Stats
	goodOffset   int64
	truncated    bool
	hashByTarget []byte
}

func OpenWriter(ctx context.Context, opts Options) (*Writer, error) {
	if opts.Path == "" || opts.CheckpointPath == "" {
		return nil, errors.New("securityaudit: path and checkpoint path are required")
	}
	if opts.Signer == nil {
		return nil, errors.New("securityaudit: signer is required")
	}
	if opts.MaxBytes < 1<<20 {
		return nil, errors.New("securityaudit: max bytes must be at least 1 MiB")
	}
	if opts.Retention < 24*time.Hour {
		return nil, errors.New("securityaudit: retention must be at least 24 hours")
	}
	if opts.Clock == nil {
		var err error
		opts.Clock, err = NewClock(ClockOptions{})
		if err != nil {
			return nil, err
		}
	}
	publicKey, err := opts.Signer.PublicKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("securityaudit: resolve signer public key: %w", err)
	}
	if err := trustcrypto.ValidatePublicKeyForSuite(publicKey.Suite, publicKey); err != nil {
		return nil, fmt.Errorf("securityaudit: invalid signer public key: %w", err)
	}
	unlock, err := acquireLock(opts.Path)
	if err != nil {
		return nil, fmt.Errorf("securityaudit: acquire writer lock: %w", err)
	}
	closeLock := true
	defer func() {
		if closeLock {
			_ = unlock()
		}
	}()
	file, err := openProtectedAppend(opts.Path)
	if err != nil {
		return nil, err
	}
	closeFile := true
	defer func() {
		if closeFile {
			_ = file.Close()
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() == 0 {
		if _, err := file.Write(auditFileMagic[:]); err != nil {
			return nil, err
		}
		if err := file.Sync(); err != nil {
			return nil, err
		}
	}
	writer := &Writer{
		file: file, path: opts.Path, checkpointPath: opts.CheckpointPath, maxBytes: opts.MaxBytes,
		retention: opts.Retention, signer: opts.Signer, publicKey: publicKey.Clone(), clock: opts.Clock,
		stats: Stats{LogBytes: int64(len(auditFileMagic)), Suite: publicKey.Suite},
	}
	if err := writer.refreshLocked(ctx); err != nil {
		return nil, err
	}
	if err := unlock(); err != nil {
		return nil, err
	}
	closeFile = false
	closeLock = false
	return writer, nil
}

func (w *Writer) Record(ctx context.Context, draft Draft) (SignedEvent, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return SignedEvent{}, errors.New("securityaudit: writer is closed")
	}
	unlock, err := acquireLock(w.path)
	if err != nil {
		return SignedEvent{}, err
	}
	defer unlock()
	if err := w.refreshLocked(ctx); err != nil {
		return SignedEvent{}, err
	}
	clean, err := sanitizeDraft(draft)
	if err != nil {
		return SignedEvent{}, err
	}
	now, timeEvidence, clockErr := w.clock.Sample(ctx)
	if clockErr != nil && !errors.Is(clockErr, ErrTimeUnsynchronized) {
		return SignedEvent{}, clockErr
	}
	if errors.Is(clockErr, ErrTimeUnsynchronized) {
		clean.Result = "blocked"
	}
	if !validTimeEvidence(timeEvidence) {
		if clockErr != nil {
			return SignedEvent{}, errors.Join(clockErr, ErrInvalidEvent)
		}
		return SignedEvent{}, ErrInvalidEvent
	}
	if now.IsZero() {
		return SignedEvent{}, errors.New("securityaudit: clock returned zero time")
	}
	eventID, err := randomID()
	if err != nil {
		return SignedEvent{}, err
	}
	event := Event{
		SchemaVersion: EventSchema, CryptoSuite: w.publicKey.Suite, Sequence: w.stats.Sequence + 1,
		EventID: eventID, PreviousHash: append([]byte(nil), w.stats.EventHash...), Actor: clean.Actor,
		Roles: append([]string(nil), clean.Roles...), Action: clean.Action, Object: clean.Object,
		Result: clean.Result, RequestID: clean.RequestID, Source: clean.Source, PolicyVersion: clean.PolicyVersion,
		LocalTimeUnixNano: now.UTC().UnixNano(), Time: timeEvidence,
		RetentionUntilUnix: now.UTC().Add(w.retention).UnixNano(), Context: clean.Context,
	}
	input, err := eventInput(event)
	if err != nil {
		return SignedEvent{}, err
	}
	suite, err := cryptosuite.RequireAvailable(event.CryptoSuite)
	if err != nil {
		return SignedEvent{}, err
	}
	eventHash, err := trustcrypto.HashBytesForSuite(event.CryptoSuite, suite.StorageIntegrityHash.Algorithm, input)
	if err != nil {
		return SignedEvent{}, err
	}
	signature, err := trustcrypto.Sign(ctx, event.CryptoSuite, w.signer, input)
	if err != nil {
		return SignedEvent{}, fmt.Errorf("securityaudit: sign event: %w", err)
	}
	signed := SignedEvent{Event: event, EventHash: eventHash, Signature: signature}
	payload, err := cborx.Marshal(signed)
	if err != nil {
		return SignedEvent{}, err
	}
	if len(payload) > maxRecordBytes {
		return SignedEvent{}, fmt.Errorf("%w: encoded record too large", ErrInvalidEvent)
	}
	frameBytes := int64(8 + len(payload))
	if w.stats.LogBytes+frameBytes > w.maxBytes {
		return SignedEvent{}, ErrCapacity
	}
	var header [8]byte
	copy(header[:4], []byte{'E', 'V', 'T', '1'})
	binary.BigEndian.PutUint32(header[4:], uint32(len(payload)))
	frame := make([]byte, 0, len(header)+len(payload))
	frame = append(frame, header[:]...)
	frame = append(frame, payload...)
	if _, err := w.file.Seek(0, io.SeekEnd); err != nil {
		return SignedEvent{}, err
	}
	if _, err := w.file.Write(frame); err != nil {
		return SignedEvent{}, fmt.Errorf("securityaudit: append event: %w", err)
	}
	if err := w.file.Sync(); err != nil {
		return SignedEvent{}, fmt.Errorf("securityaudit: sync event: %w", err)
	}
	w.stats = Stats{Sequence: event.Sequence, EventHash: append([]byte(nil), eventHash...), LogBytes: w.stats.LogBytes + frameBytes, Suite: event.CryptoSuite}
	if err := w.writeCheckpoint(ctx, now.UTC()); err != nil {
		return SignedEvent{}, err
	}
	return cloneSignedEvent(signed), clockErr
}

func (w *Writer) Stats() Stats {
	w.mu.Lock()
	defer w.mu.Unlock()
	return cloneStats(w.stats)
}

func (w *Writer) PublicKey() trustcrypto.PublicKeyDescriptor { return w.publicKey.Clone() }

func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	return w.file.Close()
}

func (w *Writer) refreshLocked(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	checkpoint, checkpointExists, err := readCheckpoint(ctx, w.checkpointPath, w.publicKey)
	if err != nil {
		return err
	}
	info, err := w.file.Stat()
	if err != nil {
		return err
	}
	if checkpointExists && checkpoint.Checkpoint.CryptoSuite == w.publicKey.Suite &&
		checkpoint.Checkpoint.Sequence == w.stats.Sequence &&
		bytes.Equal(checkpoint.Checkpoint.EventHash, w.stats.EventHash) &&
		checkpoint.Checkpoint.LogBytes == w.stats.LogBytes && info.Size() == w.stats.LogBytes {
		return nil
	}
	result, err := scanAuditFile(ctx, w.file, w.publicKey, 0, nil)
	if err != nil {
		return err
	}
	if checkpointExists {
		if checkpoint.Checkpoint.CryptoSuite != w.publicKey.Suite || checkpoint.Checkpoint.Sequence > result.stats.Sequence {
			return ErrRollback
		}
		if checkpoint.Checkpoint.Sequence > 0 {
			match, err := hashAtSequence(ctx, w.file, w.publicKey, checkpoint.Checkpoint.Sequence)
			if err != nil || !bytes.Equal(match, checkpoint.Checkpoint.EventHash) {
				return ErrRollback
			}
		}
		if checkpoint.Checkpoint.Sequence == result.stats.Sequence && checkpoint.Checkpoint.LogBytes > result.goodOffset {
			return ErrRollback
		}
	}
	if result.truncated {
		if err := w.file.Truncate(result.goodOffset); err != nil {
			return fmt.Errorf("securityaudit: remove incomplete crash tail: %w", err)
		}
		if err := w.file.Sync(); err != nil {
			return err
		}
	}
	w.stats = cloneStats(result.stats)
	if !checkpointExists || checkpoint.Checkpoint.Sequence != result.stats.Sequence || !bytes.Equal(checkpoint.Checkpoint.EventHash, result.stats.EventHash) || checkpoint.Checkpoint.LogBytes != result.stats.LogBytes {
		if err := w.writeCheckpoint(ctx, time.Now().UTC()); err != nil {
			return err
		}
	}
	return nil
}

func (w *Writer) writeCheckpoint(ctx context.Context, now time.Time) error {
	checkpoint := Checkpoint{
		SchemaVersion: CheckpointSchema, CryptoSuite: w.publicKey.Suite, Sequence: w.stats.Sequence,
		EventHash: append([]byte(nil), w.stats.EventHash...), LogBytes: w.stats.LogBytes, CreatedUnixN: now.UnixNano(),
	}
	input, err := checkpointInput(checkpoint)
	if err != nil {
		return err
	}
	signature, err := trustcrypto.Sign(ctx, checkpoint.CryptoSuite, w.signer, input)
	if err != nil {
		return fmt.Errorf("securityaudit: sign checkpoint: %w", err)
	}
	data, err := cborx.Marshal(SignedCheckpoint{Checkpoint: checkpoint, Signature: signature})
	if err != nil {
		return err
	}
	if err := writeProtectedAtomic(w.checkpointPath, data); err != nil {
		return fmt.Errorf("securityaudit: persist checkpoint: %w", err)
	}
	return nil
}

func scanAuditFile(ctx context.Context, file io.ReadSeeker, publicKey trustcrypto.PublicKeyDescriptor, target uint64, visit func(SignedEvent) error) (scanResult, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return scanResult{}, err
	}
	var magic [8]byte
	if _, err := io.ReadFull(file, magic[:]); err != nil || magic != auditFileMagic {
		return scanResult{}, fmt.Errorf("%w: invalid file header", ErrInvalidChain)
	}
	result := scanResult{stats: Stats{LogBytes: int64(len(magic)), Suite: publicKey.Suite}, goodOffset: int64(len(magic))}
	for {
		if err := ctx.Err(); err != nil {
			return scanResult{}, err
		}
		var header [8]byte
		n, err := io.ReadFull(file, header[:])
		if errors.Is(err, io.EOF) && n == 0 {
			break
		}
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			result.truncated = true
			break
		}
		if err != nil {
			return scanResult{}, err
		}
		if string(header[:4]) != "EVT1" {
			return scanResult{}, fmt.Errorf("%w: invalid frame marker", ErrInvalidChain)
		}
		length := binary.BigEndian.Uint32(header[4:])
		if length == 0 || length > maxRecordBytes {
			return scanResult{}, fmt.Errorf("%w: invalid frame length %d", ErrInvalidChain, length)
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(file, payload); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
				result.truncated = true
				break
			}
			return scanResult{}, err
		}
		var signed SignedEvent
		if err := cborx.UnmarshalLimits(payload, &signed, maxRecordBytes, 64, 64); err != nil {
			return scanResult{}, fmt.Errorf("%w: decode event: %v", ErrInvalidChain, err)
		}
		if err := verifyEvent(ctx, signed, publicKey, result.stats.Sequence, result.stats.EventHash); err != nil {
			return scanResult{}, err
		}
		result.stats.Sequence = signed.Event.Sequence
		result.stats.EventHash = append(result.stats.EventHash[:0], signed.EventHash...)
		result.goodOffset += int64(len(header)) + int64(length)
		result.stats.LogBytes = result.goodOffset
		if target > 0 && signed.Event.Sequence == target {
			result.hashByTarget = append([]byte(nil), signed.EventHash...)
		}
		if visit != nil {
			if err := visit(cloneSignedEvent(signed)); err != nil {
				return scanResult{}, err
			}
		}
	}
	return result, nil
}

func hashAtSequence(ctx context.Context, file *os.File, publicKey trustcrypto.PublicKeyDescriptor, sequence uint64) ([]byte, error) {
	result, err := scanAuditFile(ctx, file, publicKey, sequence, nil)
	if err != nil {
		return nil, err
	}
	if sequence == 0 {
		return nil, nil
	}
	if len(result.hashByTarget) == 0 {
		return nil, ErrRollback
	}
	return result.hashByTarget, nil
}

func verifyEvent(ctx context.Context, signed SignedEvent, publicKey trustcrypto.PublicKeyDescriptor, previousSequence uint64, previousHash []byte) error {
	event := signed.Event
	if event.SchemaVersion != EventSchema || event.CryptoSuite != publicKey.Suite || event.Sequence != previousSequence+1 || !bytes.Equal(event.PreviousHash, previousHash) {
		return ErrInvalidChain
	}
	if event.LocalTimeUnixNano <= 0 || event.RetentionUntilUnix <= event.LocalTimeUnixNano || !validEventID(event.EventID) || len(signed.EventHash) != 32 {
		return ErrInvalidEvent
	}
	if event.Sequence == 1 && len(event.PreviousHash) != 0 || event.Sequence > 1 && len(event.PreviousHash) != 32 || !validTimeEvidence(event.Time) {
		return ErrInvalidEvent
	}
	draft := Draft{Actor: event.Actor, Roles: event.Roles, Action: event.Action, Object: event.Object, Result: event.Result, RequestID: event.RequestID, Source: event.Source, PolicyVersion: event.PolicyVersion, Context: event.Context}
	clean, err := sanitizeDraft(draft)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(clean, draft) {
		return fmt.Errorf("%w: event fields are not canonical or privacy-redacted", ErrInvalidEvent)
	}
	input, err := eventInput(event)
	if err != nil {
		return err
	}
	suite, err := cryptosuite.RequireKnown(event.CryptoSuite)
	if err != nil {
		return err
	}
	hash, err := trustcrypto.HashBytesForSuite(event.CryptoSuite, suite.StorageIntegrityHash.Algorithm, input)
	if err != nil || !bytes.Equal(hash, signed.EventHash) {
		return ErrInvalidChain
	}
	if err := trustcrypto.VerifySignatureForSuite(ctx, event.CryptoSuite, publicKey, input, signed.Signature); err != nil {
		return fmt.Errorf("%w: signature: %v", ErrInvalidChain, err)
	}
	return nil
}

func validEventID(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16
}

func validTimeEvidence(value TimeEvidence) bool {
	if cleanIdentifier(value.Source, 128) == "" || cleanIdentifier(value.Status, 64) == "" || cleanIdentifier(value.Confidence, 64) == "" || value.UncertaintyNanos < 0 {
		return false
	}
	if value.ReferenceSampleUnixN == 0 {
		local := value.Source == "system-clock" && value.Status == "unverified" && value.Confidence == "local"
		unavailable := value.Source == "configured-reference" && (value.Status == "unavailable" || value.Status == "invalid") && value.Confidence == "none"
		return (local || unavailable) && !value.Synchronized && value.OffsetNanos == 0 && value.UncertaintyNanos == 0 && value.SampleAgeNanos == 0
	}
	if value.ReferenceSampleUnixN < 0 || value.Source == "system-clock" || value.Source == "configured-reference" {
		return false
	}
	switch value.Confidence {
	case "authenticated", "network", "hardware", "local":
	default:
		return false
	}
	switch value.Status {
	case "synchronized":
		return value.Synchronized && value.Confidence != "local" && value.SampleAgeNanos >= 0
	case "stale", "drift-exceeded", "unsynchronized", "unverified":
		return !value.Synchronized
	default:
		return false
	}
}

func eventInput(event Event) ([]byte, error) {
	payload, err := cborx.Marshal(event)
	if err != nil {
		return nil, err
	}
	return domainInput(eventDomain, payload), nil
}

func checkpointInput(checkpoint Checkpoint) ([]byte, error) {
	payload, err := cborx.Marshal(checkpoint)
	if err != nil {
		return nil, err
	}
	return domainInput(checkpointDomain, payload), nil
}

func domainInput(domain string, payload []byte) []byte {
	result := make([]byte, 0, 4+len(domain)+len(payload))
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(domain)))
	result = append(result, size[:]...)
	result = append(result, domain...)
	result = append(result, payload...)
	return result
}

func readCheckpoint(ctx context.Context, path string, publicKey trustcrypto.PublicKeyDescriptor) (SignedCheckpoint, bool, error) {
	data, err := readProtectedFile(path, maxRecordBytes)
	if errors.Is(err, os.ErrNotExist) {
		return SignedCheckpoint{}, false, nil
	}
	if err != nil {
		return SignedCheckpoint{}, false, err
	}
	var signed SignedCheckpoint
	if err := cborx.UnmarshalLimits(data, &signed, maxRecordBytes, 16, 32); err != nil {
		return SignedCheckpoint{}, false, fmt.Errorf("%w: decode: %v", ErrInvalidCheckpoint, err)
	}
	checkpoint := signed.Checkpoint
	if checkpoint.SchemaVersion != CheckpointSchema || checkpoint.CryptoSuite != publicKey.Suite || checkpoint.LogBytes < int64(len(auditFileMagic)) || checkpoint.CreatedUnixN <= 0 {
		return SignedCheckpoint{}, false, ErrInvalidCheckpoint
	}
	if checkpoint.Sequence == 0 && len(checkpoint.EventHash) != 0 || checkpoint.Sequence > 0 && len(checkpoint.EventHash) != 32 {
		return SignedCheckpoint{}, false, ErrInvalidCheckpoint
	}
	input, err := checkpointInput(checkpoint)
	if err != nil {
		return SignedCheckpoint{}, false, err
	}
	if err := trustcrypto.VerifySignatureForSuite(ctx, checkpoint.CryptoSuite, publicKey, input, signed.Signature); err != nil {
		return SignedCheckpoint{}, false, fmt.Errorf("%w: signature: %v", ErrInvalidCheckpoint, err)
	}
	return signed, true, nil
}

func randomID() (string, error) {
	var value [16]byte
	if _, err := io.ReadFull(rand.Reader, value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

func cloneStats(stats Stats) Stats {
	stats.EventHash = append([]byte(nil), stats.EventHash...)
	return stats
}

func cloneSignedEvent(event SignedEvent) SignedEvent {
	event.Event.PreviousHash = append([]byte(nil), event.Event.PreviousHash...)
	event.Event.Roles = append([]string(nil), event.Event.Roles...)
	if event.Event.Context != nil {
		contextValues := make(map[string]string, len(event.Event.Context))
		for key, value := range event.Event.Context {
			contextValues[key] = value
		}
		event.Event.Context = contextValues
	}
	event.EventHash = append([]byte(nil), event.EventHash...)
	event.Signature.Signature = append([]byte(nil), event.Signature.Signature...)
	return event
}
