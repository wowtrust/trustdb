package anchor

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/model"
)

func fileSinkSTH(treeSize uint64) model.SignedTreeHead {
	root := make([]byte, 32)
	root[0] = 0xaa
	root[31] = byte(treeSize)
	return model.SignedTreeHead{
		SchemaVersion:  model.SchemaSignedTreeHead,
		CryptoSuite:    cryptosuite.INTLV1,
		TreeAlg:        model.DefaultMerkleTreeAlg,
		TreeSize:       treeSize,
		RootHash:       root,
		TimestampUnixN: 1_234,
		NodeID:         "node-a",
		LogID:          "log-a",
	}
}

func TestFileSinkPublishAppendsJSONL(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "anchors.jsonl")
	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}

	sth := fileSinkSTH(5)
	result, err := sink.Publish(context.Background(), sth)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if result.TreeSize != sth.TreeSize {
		t.Fatalf("result.TreeSize = %d, want %d", result.TreeSize, sth.TreeSize)
	}
	if result.SinkName != FileSinkName {
		t.Fatalf("result.SinkName = %q, want %q", result.SinkName, FileSinkName)
	}
	if result.AnchorID == "" {
		t.Fatalf("result.AnchorID is empty")
	}
	if result.EvidenceStage != model.AnchorEvidenceStageLocalOnly {
		t.Fatalf("result.EvidenceStage = %q, want local_only", result.EvidenceStage)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open sink file: %v", err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		t.Fatalf("no line written")
	}
	var entry FileAnchorEntry
	if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
		t.Fatalf("decode jsonl: %v", err)
	}
	if entry.TreeSize != sth.TreeSize || entry.RootHashHex != hex.EncodeToString(sth.RootHash) {
		t.Fatalf("entry = %+v", entry)
	}
	if entry.SchemaVersion != "trustdb.anchor-file-entry.v2" ||
		entry.CryptoSuite != string(sth.CryptoSuite) ||
		entry.NodeID != sth.NodeID ||
		entry.LogID != sth.LogID {
		t.Fatalf("entry identity = %+v", entry)
	}
	if scanner.Scan() {
		t.Fatalf("second line written unexpectedly: %q", scanner.Text())
	}
}

func TestNativeAnchorIDsBindFullSTHIdentityAndSuite(t *testing.T) {
	t.Parallel()

	base := fileSinkSTH(9)
	for name, mutate := range map[string]func(*model.SignedTreeHead){
		"suite": func(sth *model.SignedTreeHead) {
			sth.CryptoSuite = cryptosuite.CNSMV1
			sth.TreeAlg = cryptosuite.MerkleRFC6962SM3
		},
		"node":      func(sth *model.SignedTreeHead) { sth.NodeID = "node-b" },
		"log":       func(sth *model.SignedTreeHead) { sth.LogID = "log-b" },
		"tree_size": func(sth *model.SignedTreeHead) { sth.TreeSize++ },
		"root":      func(sth *model.SignedTreeHead) { sth.RootHash[0] ^= 0xff },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			changed.RootHash = append([]byte(nil), base.RootHash...)
			mutate(&changed)
			if got, want := DeterministicFileAnchorID(changed), DeterministicFileAnchorID(base); got == "" || got == want {
				t.Fatalf("file anchor id = %q, base = %q", got, want)
			}
			if got, want := DeterministicNoopAnchorID(changed), DeterministicNoopAnchorID(base); got == "" || got == want {
				t.Fatalf("noop anchor id = %q, base = %q", got, want)
			}
		})
	}
}

func TestFileSinkDeterministicAnchorID(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "anchors.jsonl")
	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	sth := fileSinkSTH(9)
	first, err := sink.Publish(context.Background(), sth)
	if err != nil {
		t.Fatalf("first Publish: %v", err)
	}
	second, err := sink.Publish(context.Background(), sth)
	if err != nil {
		t.Fatalf("second Publish: %v", err)
	}
	if first.AnchorID != second.AnchorID {
		t.Fatalf("anchor id not deterministic: %q vs %q", first.AnchorID, second.AnchorID)
	}
}

func TestFileSinkRejectsEmptyTreeSize(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "anchors.jsonl")
	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	_, err = sink.Publish(context.Background(), model.SignedTreeHead{})
	if err == nil {
		t.Fatalf("Publish: want error, got nil")
	}
	if !errors.Is(err, ErrPermanent) {
		t.Fatalf("Publish: err = %v, want wrapped ErrPermanent", err)
	}
}

func TestNoopSinkPublishNeverFails(t *testing.T) {
	t.Parallel()
	sink := NewNoopSink()
	if sink.Name() != NoopSinkName {
		t.Fatalf("Name = %q, want %q", sink.Name(), NoopSinkName)
	}
	result, err := sink.Publish(context.Background(), fileSinkSTH(12))
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if result.AnchorID == "" || result.SinkName != NoopSinkName {
		t.Fatalf("result = %+v", result)
	}
}
