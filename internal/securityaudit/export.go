package securityaudit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
)

type exportLine struct {
	SchemaVersion string                           `json:"schema_version"`
	Kind          string                           `json:"kind"`
	ExportedUnixN int64                            `json:"exported_unix_nano,omitempty"`
	CryptoSuite   cryptosuite.ID                   `json:"crypto_suite,omitempty"`
	PublicKey     *trustcrypto.PublicKeyDescriptor `json:"public_key,omitempty"`
	Event         *SignedEvent                     `json:"event,omitempty"`
	Checkpoint    *SignedCheckpoint                `json:"checkpoint,omitempty"`
}

func (w *Writer) ExportJSONL(ctx context.Context, output io.Writer) (Stats, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return Stats{}, errors.New("securityaudit: writer is closed")
	}
	unlock, err := acquireLock(w.path)
	if err != nil {
		return Stats{}, err
	}
	defer unlock()
	if err := w.refreshLocked(ctx); err != nil {
		return Stats{}, err
	}
	if output == nil {
		return Stats{}, errors.New("securityaudit: export writer is nil")
	}
	checkpoint, exists, err := readCheckpoint(ctx, w.checkpointPath, w.publicKey)
	if err != nil || !exists {
		return Stats{}, fmt.Errorf("securityaudit: export checkpoint: %w", err)
	}
	encoder := json.NewEncoder(output)
	publicKey := w.publicKey.Clone()
	if err := encoder.Encode(exportLine{SchemaVersion: ExportSchema, Kind: "manifest", ExportedUnixN: time.Now().UTC().UnixNano(), CryptoSuite: publicKey.Suite, PublicKey: &publicKey}); err != nil {
		return Stats{}, err
	}
	result, err := scanAuditFile(ctx, w.file, w.publicKey, 0, func(event SignedEvent) error {
		return encoder.Encode(exportLine{SchemaVersion: ExportSchema, Kind: "event", Event: &event})
	})
	if err != nil {
		return Stats{}, err
	}
	if result.truncated {
		return Stats{}, ErrInvalidChain
	}
	if checkpoint.Checkpoint.Sequence != result.stats.Sequence || !bytes.Equal(checkpoint.Checkpoint.EventHash, result.stats.EventHash) {
		return Stats{}, ErrRollback
	}
	if err := encoder.Encode(exportLine{SchemaVersion: ExportSchema, Kind: "checkpoint", Checkpoint: &checkpoint}); err != nil {
		return Stats{}, err
	}
	return cloneStats(result.stats), nil
}

func VerifyLog(ctx context.Context, path, checkpointPath string, publicKey trustcrypto.PublicKeyDescriptor) (Stats, error) {
	unlock, err := acquireLock(path)
	if err != nil {
		return Stats{}, err
	}
	defer unlock()
	file, err := openProtectedExisting(path)
	if err != nil {
		return Stats{}, err
	}
	defer file.Close()
	result, err := scanAuditFile(ctx, file, publicKey, 0, nil)
	if err != nil {
		return Stats{}, err
	}
	if result.truncated {
		return Stats{}, ErrInvalidChain
	}
	if checkpointPath != "" {
		checkpoint, exists, err := readCheckpoint(ctx, checkpointPath, publicKey)
		if err != nil || !exists {
			return Stats{}, fmt.Errorf("securityaudit: verify checkpoint: %w", err)
		}
		if checkpoint.Checkpoint.Sequence != result.stats.Sequence || !bytes.Equal(checkpoint.Checkpoint.EventHash, result.stats.EventHash) || checkpoint.Checkpoint.LogBytes != result.stats.LogBytes {
			return Stats{}, ErrRollback
		}
	}
	return cloneStats(result.stats), nil
}

func (w *Writer) Verify(ctx context.Context) (Stats, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return Stats{}, errors.New("securityaudit: writer is closed")
	}
	unlock, err := acquireLock(w.path)
	if err != nil {
		return Stats{}, err
	}
	defer unlock()
	if err := w.refreshLocked(ctx); err != nil {
		return Stats{}, err
	}
	result, err := scanAuditFile(ctx, w.file, w.publicKey, 0, nil)
	if err != nil {
		return Stats{}, err
	}
	if result.truncated {
		return Stats{}, ErrInvalidChain
	}
	checkpoint, exists, err := readCheckpoint(ctx, w.checkpointPath, w.publicKey)
	if err != nil || !exists {
		return Stats{}, fmt.Errorf("securityaudit: verify checkpoint: %w", err)
	}
	if checkpoint.Checkpoint.Sequence != result.stats.Sequence || !bytes.Equal(checkpoint.Checkpoint.EventHash, result.stats.EventHash) || checkpoint.Checkpoint.LogBytes != result.stats.LogBytes {
		return Stats{}, ErrRollback
	}
	return cloneStats(result.stats), nil
}

func (w *Writer) Checkpoint(ctx context.Context) (CheckpointArtifact, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return CheckpointArtifact{}, errors.New("securityaudit: writer is closed")
	}
	unlock, err := acquireLock(w.path)
	if err != nil {
		return CheckpointArtifact{}, err
	}
	defer unlock()
	if err := w.refreshLocked(ctx); err != nil {
		return CheckpointArtifact{}, err
	}
	checkpoint, exists, err := readCheckpoint(ctx, w.checkpointPath, w.publicKey)
	if err != nil || !exists {
		return CheckpointArtifact{}, fmt.Errorf("securityaudit: read checkpoint: %w", err)
	}
	checkpoint.Checkpoint.EventHash = append([]byte(nil), checkpoint.Checkpoint.EventHash...)
	checkpoint.Signature.Signature = append([]byte(nil), checkpoint.Signature.Signature...)
	return CheckpointArtifact{SchemaVersion: CheckpointExportSchema, PublicKey: w.publicKey.Clone(), Checkpoint: checkpoint}, nil
}

func VerifyCheckpointArtifact(ctx context.Context, input io.Reader, publicKey trustcrypto.PublicKeyDescriptor) (Stats, error) {
	if input == nil {
		return Stats{}, errors.New("securityaudit: checkpoint reader is nil")
	}
	data, err := io.ReadAll(io.LimitReader(input, maxRecordBytes+1))
	if err != nil {
		return Stats{}, err
	}
	if len(data) > maxRecordBytes {
		return Stats{}, errors.New("securityaudit: checkpoint artifact is too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var artifact CheckpointArtifact
	if err := decoder.Decode(&artifact); err != nil {
		return Stats{}, fmt.Errorf("securityaudit: decode checkpoint artifact: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Stats{}, errors.New("securityaudit: checkpoint artifact has trailing JSON")
	}
	if artifact.SchemaVersion != CheckpointExportSchema || !samePublicKey(artifact.PublicKey, publicKey) {
		return Stats{}, ErrInvalidCheckpoint
	}
	if err := verifyCheckpoint(ctx, artifact.Checkpoint, publicKey); err != nil {
		return Stats{}, err
	}
	checkpoint := artifact.Checkpoint.Checkpoint
	return Stats{Sequence: checkpoint.Sequence, EventHash: append([]byte(nil), checkpoint.EventHash...), LogBytes: checkpoint.LogBytes, Suite: checkpoint.CryptoSuite}, nil
}

func VerifyExportJSONL(ctx context.Context, input io.Reader, publicKey trustcrypto.PublicKeyDescriptor) (Stats, error) {
	if input == nil {
		return Stats{}, errors.New("securityaudit: export reader is nil")
	}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64<<10), 512<<10)
	lineNumber := 0
	stats := Stats{Suite: publicKey.Suite, LogBytes: int64(len(auditFileMagic))}
	manifestSeen := false
	checkpointSeen := false
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return Stats{}, err
		}
		lineNumber++
		var line exportLine
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&line); err != nil {
			return Stats{}, fmt.Errorf("securityaudit: export line %d: %w", lineNumber, err)
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return Stats{}, fmt.Errorf("securityaudit: export line %d has trailing JSON", lineNumber)
		}
		if line.SchemaVersion != ExportSchema {
			return Stats{}, fmt.Errorf("securityaudit: export line %d has unsupported schema", lineNumber)
		}
		switch line.Kind {
		case "manifest":
			if manifestSeen || lineNumber != 1 || line.ExportedUnixN <= 0 || line.CryptoSuite != publicKey.Suite || line.PublicKey == nil || line.Event != nil || line.Checkpoint != nil || !samePublicKey(*line.PublicKey, publicKey) {
				return Stats{}, errors.New("securityaudit: invalid export manifest")
			}
			manifestSeen = true
		case "event":
			if !manifestSeen || checkpointSeen || line.ExportedUnixN != 0 || line.CryptoSuite != "" || line.PublicKey != nil || line.Event == nil || line.Checkpoint != nil {
				return Stats{}, errors.New("securityaudit: invalid export event order")
			}
			if err := verifyEvent(ctx, *line.Event, publicKey, stats.Sequence, stats.EventHash); err != nil {
				return Stats{}, err
			}
			payload, err := cborx.Marshal(*line.Event)
			if err != nil {
				return Stats{}, err
			}
			stats.Sequence = line.Event.Event.Sequence
			stats.EventHash = append(stats.EventHash[:0], line.Event.EventHash...)
			stats.LogBytes += int64(8 + len(payload))
		case "checkpoint":
			if !manifestSeen || checkpointSeen || line.ExportedUnixN != 0 || line.CryptoSuite != "" || line.PublicKey != nil || line.Event != nil || line.Checkpoint == nil {
				return Stats{}, errors.New("securityaudit: invalid export checkpoint order")
			}
			if err := verifyCheckpoint(ctx, *line.Checkpoint, publicKey); err != nil {
				return Stats{}, err
			}
			if line.Checkpoint.Checkpoint.Sequence != stats.Sequence || !bytes.Equal(line.Checkpoint.Checkpoint.EventHash, stats.EventHash) || line.Checkpoint.Checkpoint.LogBytes != stats.LogBytes {
				return Stats{}, ErrRollback
			}
			checkpointSeen = true
		default:
			return Stats{}, fmt.Errorf("securityaudit: unsupported export line kind %q", line.Kind)
		}
	}
	if err := scanner.Err(); err != nil {
		return Stats{}, err
	}
	if !manifestSeen || !checkpointSeen {
		return Stats{}, errors.New("securityaudit: incomplete export")
	}
	return cloneStats(stats), nil
}

func verifyCheckpoint(ctx context.Context, signed SignedCheckpoint, publicKey trustcrypto.PublicKeyDescriptor) error {
	checkpoint := signed.Checkpoint
	if checkpoint.SchemaVersion != CheckpointSchema || checkpoint.CryptoSuite != publicKey.Suite || checkpoint.LogBytes < int64(len(auditFileMagic)) || checkpoint.CreatedUnixN <= 0 {
		return ErrInvalidCheckpoint
	}
	if checkpoint.Sequence == 0 && len(checkpoint.EventHash) != 0 || checkpoint.Sequence > 0 && len(checkpoint.EventHash) != 32 {
		return ErrInvalidCheckpoint
	}
	input, err := checkpointInput(checkpoint)
	if err != nil {
		return err
	}
	if err := trustcrypto.VerifySignatureForSuite(ctx, checkpoint.CryptoSuite, publicKey, input, signed.Signature); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidCheckpoint, err)
	}
	return nil
}

func samePublicKey(left, right trustcrypto.PublicKeyDescriptor) bool {
	return left.Suite == right.Suite && left.KeyID == right.KeyID && left.Algorithm == right.Algorithm && left.Encoding == right.Encoding && bytes.Equal(left.Bytes, right.Bytes)
}
