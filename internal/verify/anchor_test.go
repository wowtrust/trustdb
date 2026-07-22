package verify

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/wowtrust/trustdb/internal/anchor"
	"github.com/wowtrust/trustdb/internal/model"
)

// newGlobalProofWithSTH returns the minimal GlobalLogProof that
// AnchorConsistency needs: the STH/global root that L5 anchored.
func newGlobalProofWithSTH(treeSize uint64, root []byte) model.GlobalLogProof {
	return model.GlobalLogProof{
		SchemaVersion: model.SchemaGlobalLogProof,
		STH: model.SignedTreeHead{
			SchemaVersion: model.SchemaSignedTreeHead,
			TreeAlg:       model.DefaultMerkleTreeAlg,
			TreeSize:      treeSize,
			RootHash:      root,
		},
	}
}

func writeOtsVaruint(buf *bytes.Buffer, v uint64) {
	for {
		c := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			c |= 0x80
		}
		buf.WriteByte(c)
		if v == 0 {
			return
		}
	}
}

func writeOtsVarbytes(buf *bytes.Buffer, p []byte) {
	writeOtsVaruint(buf, uint64(len(p)))
	buf.Write(p)
}

func pendingOtsTimestamp(t *testing.T, uri string) []byte {
	t.Helper()
	magic, err := hex.DecodeString("83dfe30d2ef90c8e")
	if err != nil {
		t.Fatalf("decode pending magic: %v", err)
	}
	var payload bytes.Buffer
	writeOtsVarbytes(&payload, []byte(uri))

	var raw bytes.Buffer
	raw.WriteByte(0x00)
	raw.Write(magic)
	writeOtsVarbytes(&raw, payload.Bytes())
	return raw.Bytes()
}

func otsAnchorResult(t *testing.T, proof model.GlobalLogProof, digest []byte, timestamp []byte) model.STHAnchorResult {
	t.Helper()
	otsProof := anchor.OtsAnchorProof{
		SchemaVersion: anchor.SchemaOtsAnchorProof,
		TreeSize:      proof.STH.TreeSize,
		HashAlg:       model.DefaultHashAlg,
		Digest:        digest,
		Calendars: []anchor.OtsCalendarTimestamp{
			{
				URL:          "https://a.pool.opentimestamps.org",
				Accepted:     true,
				RawTimestamp: timestamp,
				StatusCode:   200,
			},
		},
	}
	proofBytes, err := json.Marshal(otsProof)
	if err != nil {
		t.Fatalf("marshal ots proof: %v", err)
	}
	return model.STHAnchorResult{
		SchemaVersion: model.SchemaSTHAnchorResult,
		TreeSize:      proof.STH.TreeSize,
		SinkName:      anchor.OtsSinkName,
		AnchorID:      anchor.DeterministicOtsAnchorID(proof.STH),
		RootHash:      proof.STH.RootHash,
		STH:           proof.STH,
		Proof:         proofBytes,
	}
}

func TestAnchorConsistencyFileSinkOK(t *testing.T) {
	t.Parallel()
	root := []byte{0xaa, 0xbb, 0xcc}
	proof := newGlobalProofWithSTH(7, root)
	ar := model.STHAnchorResult{
		SchemaVersion: model.SchemaSTHAnchorResult,
		TreeSize:      proof.STH.TreeSize,
		SinkName:      anchor.FileSinkName,
		AnchorID:      anchor.DeterministicFileAnchorID(proof.STH),
		RootHash:      root,
		STH:           proof.STH,
	}
	if err := AnchorConsistency(proof, ar); err != nil {
		t.Fatalf("AnchorConsistency: %v", err)
	}
}

func TestAnchorConsistencyNoopSinkOK(t *testing.T) {
	t.Parallel()
	root := []byte{1, 2, 3}
	proof := newGlobalProofWithSTH(8, root)
	ar := model.STHAnchorResult{
		SchemaVersion: model.SchemaSTHAnchorResult,
		TreeSize:      proof.STH.TreeSize,
		SinkName:      anchor.NoopSinkName,
		AnchorID:      anchor.DeterministicNoopAnchorID(proof.STH),
		RootHash:      root,
		STH:           proof.STH,
	}
	if err := AnchorConsistency(proof, ar); err != nil {
		t.Fatalf("AnchorConsistency: %v", err)
	}
}

func TestAnchorConsistencyOtsSinkOK(t *testing.T) {
	t.Parallel()
	root := bytes.Repeat([]byte{0x42}, 32)
	proof := newGlobalProofWithSTH(9, root)
	ar := otsAnchorResult(t, proof, root, pendingOtsTimestamp(t, "https://a.pool.opentimestamps.org"))
	if err := AnchorConsistency(proof, ar); err != nil {
		t.Fatalf("AnchorConsistency (ots): %v", err)
	}
}

func TestAnchorConsistencyRejectsOtsDigestMismatch(t *testing.T) {
	t.Parallel()
	root := bytes.Repeat([]byte{0x42}, 32)
	proof := newGlobalProofWithSTH(9, root)
	ar := otsAnchorResult(t, proof, bytes.Repeat([]byte{0x24}, 32), pendingOtsTimestamp(t, "https://a.pool.opentimestamps.org"))
	err := AnchorConsistency(proof, ar)
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("want ots digest mismatch, got %v", err)
	}
}

func TestAnchorConsistencyRejectsUnknownSink(t *testing.T) {
	t.Parallel()
	root := []byte{9, 9}
	proof := newGlobalProofWithSTH(9, root)
	ar := model.STHAnchorResult{
		SchemaVersion: model.SchemaSTHAnchorResult,
		TreeSize:      proof.STH.TreeSize,
		SinkName:      "ct-log",
		AnchorID:      "arbitrary-opaque-id-from-ct-log",
		RootHash:      root,
		STH:           proof.STH,
	}
	err := AnchorConsistency(proof, ar)
	if err == nil || !strings.Contains(err.Error(), "unsupported anchor sink") {
		t.Fatalf("want unsupported sink error, got %v", err)
	}
}

func TestAnchorConsistencyRejectsSchema(t *testing.T) {
	t.Parallel()
	proof := newGlobalProofWithSTH(1, []byte{1})
	ar := model.STHAnchorResult{
		SchemaVersion: "bogus",
		TreeSize:      proof.STH.TreeSize,
		SinkName:      anchor.NoopSinkName,
		AnchorID:      anchor.DeterministicNoopAnchorID(proof.STH),
		RootHash:      []byte{1},
	}
	err := AnchorConsistency(proof, ar)
	if err == nil || !strings.Contains(err.Error(), "schema") {
		t.Fatalf("want schema error, got %v", err)
	}
}

func TestAnchorConsistencyRejectsTreeSizeMismatch(t *testing.T) {
	t.Parallel()
	proof := newGlobalProofWithSTH(2, []byte{1})
	ar := model.STHAnchorResult{
		SchemaVersion: model.SchemaSTHAnchorResult,
		TreeSize:      3,
		SinkName:      anchor.NoopSinkName,
		AnchorID:      "noop-sth-3",
		RootHash:      []byte{1},
	}
	err := AnchorConsistency(proof, ar)
	if err == nil || !strings.Contains(err.Error(), "tree_size") {
		t.Fatalf("want tree_size error, got %v", err)
	}
}

func TestAnchorConsistencyRejectsRootMismatch(t *testing.T) {
	t.Parallel()
	proof := newGlobalProofWithSTH(4, []byte{1, 2, 3})
	ar := model.STHAnchorResult{
		SchemaVersion: model.SchemaSTHAnchorResult,
		TreeSize:      proof.STH.TreeSize,
		SinkName:      anchor.NoopSinkName,
		AnchorID:      anchor.DeterministicNoopAnchorID(proof.STH),
		RootHash:      []byte{9, 9, 9},
	}
	err := AnchorConsistency(proof, ar)
	if err == nil || !strings.Contains(err.Error(), "root_hash") {
		t.Fatalf("want root_hash error, got %v", err)
	}
}

func TestAnchorConsistencyRejectsFileAnchorIDTamper(t *testing.T) {
	t.Parallel()
	root := []byte{1, 2}
	proof := newGlobalProofWithSTH(5, root)
	ar := model.STHAnchorResult{
		SchemaVersion: model.SchemaSTHAnchorResult,
		TreeSize:      proof.STH.TreeSize,
		SinkName:      anchor.FileSinkName,
		AnchorID:      "file-tampered-0000000000000000000",
		RootHash:      root,
	}
	err := AnchorConsistency(proof, ar)
	if err == nil || !strings.Contains(err.Error(), "file sink anchor_id") {
		t.Fatalf("want anchor_id mismatch error, got %v", err)
	}
}

func TestAnchorConsistencyRejectsEmptyAnchorID(t *testing.T) {
	t.Parallel()
	proof := newGlobalProofWithSTH(6, []byte{1})
	ar := model.STHAnchorResult{
		SchemaVersion: model.SchemaSTHAnchorResult,
		TreeSize:      proof.STH.TreeSize,
		SinkName:      anchor.FileSinkName,
		RootHash:      []byte{1},
	}
	err := AnchorConsistency(proof, ar)
	if err == nil || !strings.Contains(err.Error(), "anchor_id") {
		t.Fatalf("want anchor_id missing error, got %v", err)
	}
}
