package anchor

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

// FileSinkName is the stable Sink identifier recorded in every
// STHAnchorResult produced by FileSink. Changing this
// value is a breaking change for existing proof bundles, so treat it
// as a schema constant.
const FileSinkName = "file"

// FileSink is a development/on-prem Sink that appends each published
// SignedTreeHead to a local JSONL log and fsyncs the file. It is not an
// independent trust anchor: an operator with write access can rewrite both
// the TrustDB state and this file. Results are therefore always local_only
// and must never grant L5.
//
// The writer mutex also keeps direct and test callers serialized.
type FileSink struct {
	path string

	mu sync.Mutex
}

// FileAnchorEntry is the JSONL record written for every published
// SignedTreeHead. It mirrors the exported STHAnchorResult so a verifier can
// replay the log without touching the proofstore.
type FileAnchorEntry struct {
	SchemaVersion     string `json:"schema_version"`
	CryptoSuite       string `json:"crypto_suite"`
	NodeID            string `json:"node_id"`
	LogID             string `json:"log_id"`
	SinkName          string `json:"sink_name"`
	AnchorID          string `json:"anchor_id"`
	RootHashHex       string `json:"root_hash_hex"`
	TreeSize          uint64 `json:"tree_size"`
	STHTimestampUnixN int64  `json:"sth_timestamp_unix_nano"`
	PublishedAtUnixN  int64  `json:"published_at_unix_nano"`
}

// NewFileSink opens (or creates) path for append and returns a ready
// FileSink. The caller owns the file and the sink does not close it
// automatically; the anchor service shuts down by stopping the
// worker, which finishes any in-flight Publish before returning.
func NewFileSink(path string) (*FileSink, error) {
	if path == "" {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "file sink path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeInternal, "create file sink dir", err)
	}
	// Touch the file so subsequent Publish calls can assume it exists.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeInternal, "open file sink", err)
	}
	_ = f.Close()
	return &FileSink{path: path}, nil
}

// Name identifies this sink in STHAnchorResult.SinkName. A verifier uses this to route the Proof bytes
// to the right parser.
func (s *FileSink) Name() string { return FileSinkName }

// Publish appends a JSONL entry for the STH and returns an
// STHAnchorResult. The AnchorID is derived deterministically from
// tree size + root hash so re-publishing the same STH (e.g. after a crash between
// the append and the schedule completion) yields the same AnchorID —
// which keeps the file log idempotent at the cost of a duplicate line
// per retry. Consumers dedupe by AnchorID.
//
// The returned error is never ErrPermanent because local filesystem
// failures are all transient from the sink's perspective (the disk
// comes back, a rename races, etc.). If we ever want to declare a
// hard failure here we would return a wrapped ErrPermanent.
func (s *FileSink) Publish(ctx context.Context, sth model.SignedTreeHead) (model.STHAnchorResult, error) {
	if err := ctx.Err(); err != nil {
		return model.STHAnchorResult{}, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "anchor file sink canceled", err)
	}
	if sth.TreeSize == 0 {
		return model.STHAnchorResult{}, fmt.Errorf("%w: tree_size is empty", ErrPermanent)
	}

	now := time.Now().UTC().UnixNano()
	anchorID, err := deterministicAnchorID(FileSinkName, "file2-", sth)
	if err != nil {
		return model.STHAnchorResult{}, fmt.Errorf("%w: %v", ErrPermanent, err)
	}
	entry := FileAnchorEntry{
		SchemaVersion:     "trustdb.anchor-file-entry.v2",
		CryptoSuite:       string(sth.CryptoSuite),
		NodeID:            sth.NodeID,
		LogID:             sth.LogID,
		SinkName:          s.Name(),
		AnchorID:          anchorID,
		RootHashHex:       hex.EncodeToString(sth.RootHash),
		TreeSize:          sth.TreeSize,
		STHTimestampUnixN: sth.TimestampUnixN,
		PublishedAtUnixN:  now,
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return model.STHAnchorResult{}, fmt.Errorf("%w: %v", ErrPermanent, err)
	}
	line = append(line, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return model.STHAnchorResult{}, trusterr.Wrap(trusterr.CodeInternal, "open file sink", err)
	}
	// Use a closure so fsync runs even if Write succeeds partially;
	// a file descriptor leak on error path is still fatal but rare.
	if err := func() error {
		defer f.Close()
		if _, werr := f.Write(line); werr != nil {
			return werr
		}
		return f.Sync()
	}(); err != nil {
		return model.STHAnchorResult{}, trusterr.Wrap(trusterr.CodeDataLoss, "append anchor entry", err)
	}
	return model.STHAnchorResult{
		SchemaVersion:    model.SchemaSTHAnchorResult,
		CryptoSuite:      sth.CryptoSuite,
		NodeID:           sth.NodeID,
		LogID:            sth.LogID,
		TreeSize:         sth.TreeSize,
		SinkName:         s.Name(),
		AnchorID:         anchorID,
		RootHash:         sth.RootHash,
		STH:              sth,
		Proof:            line, // JSONL line is the "proof" a verifier compares
		EvidenceStage:    model.AnchorEvidenceStageLocalOnly,
		PublishedAtUnixN: now,
	}, nil
}

// DeterministicFileAnchorID hashes the stable fields of the STH so every
// retry for the same global root produces the same anchor id. This
// keeps the JSONL log replayable — duplicates are easy to dedupe by
// anchor_id — and the API stable to clients fetching anchor results.
// It is exported so offline verifiers (see internal/verify) can
// recompute the id from a trusted STH and compare it against an
// STHAnchorResult, which proves the sink did not lie about the id.
func DeterministicFileAnchorID(sth model.SignedTreeHead) string {
	id, _ := deterministicAnchorID(FileSinkName, "file2-", sth)
	return id
}

// DeterministicNoopAnchorID mirrors DeterministicFileAnchorID for the
// NoopSink. Kept separate so verifiers have a single authoritative
// source for each sink's id derivation.
func DeterministicNoopAnchorID(sth model.SignedTreeHead) string {
	id, _ := deterministicAnchorID(NoopSinkName, "noop2-", sth)
	return id
}

func deterministicAnchorID(sinkName, prefix string, sth model.SignedTreeHead) (string, error) {
	suite, err := cryptosuite.RequireAvailable(sth.CryptoSuite)
	if err != nil {
		return "", fmt.Errorf("anchor crypto_suite: %w", err)
	}
	if sth.TreeSize == 0 {
		return "", fmt.Errorf("tree_size is empty")
	}
	if len(sth.RootHash) != suite.AnchorDigest.DigestBytes {
		return "", fmt.Errorf(
			"root_hash must be %d bytes for %s, got %d",
			suite.AnchorDigest.DigestBytes,
			suite.ID,
			len(sth.RootHash),
		)
	}

	input := make([]byte, 0, 128+len(sth.NodeID)+len(sth.LogID))
	input = appendLengthFramed(input, []byte("trustdb.anchor-id.v2"))
	input = appendLengthFramed(input, []byte(sinkName))
	input = appendLengthFramed(input, []byte(sth.CryptoSuite))
	input = appendLengthFramed(input, []byte(sth.NodeID))
	input = appendLengthFramed(input, []byte(sth.LogID))
	var treeSize [8]byte
	binary.BigEndian.PutUint64(treeSize[:], sth.TreeSize)
	input = appendLengthFramed(input, treeSize[:])
	input = appendLengthFramed(input, sth.RootHash)

	digest, err := trustcrypto.HashBytesForSuite(sth.CryptoSuite, suite.AnchorDigest.Algorithm, input)
	if err != nil {
		return "", fmt.Errorf("hash anchor id: %w", err)
	}
	return prefix + hex.EncodeToString(digest)[:32], nil
}

func appendLengthFramed(dst, value []byte) []byte {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	dst = append(dst, size[:]...)
	return append(dst, value...)
}
