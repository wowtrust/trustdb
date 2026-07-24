package verify

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/wowtrust/trustdb/internal/anchor"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/model"
)

// newGlobalProofWithSTH returns the minimal GlobalLogProof that
// AnchorConsistency needs: the STH/global root that L5 anchored.
func newGlobalProofWithSTH(treeSize uint64, root []byte) model.GlobalLogProof {
	return model.GlobalLogProof{
		SchemaVersion: model.SchemaGlobalLogProof,
		CryptoSuite:   cryptosuite.INTLV1,
		STH: model.SignedTreeHead{
			SchemaVersion: model.SchemaSignedTreeHead,
			CryptoSuite:   cryptosuite.INTLV1,
			TreeAlg:       model.DefaultMerkleTreeAlg,
			TreeSize:      treeSize,
			RootHash:      root,
			NodeID:        "node-1",
			LogID:         "log-1",
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
		CryptoSuite:   proof.CryptoSuite,
		EvidenceStage: model.AnchorEvidenceStageOfflineVerified,
		NodeID:        proof.STH.NodeID,
		LogID:         proof.STH.LogID,
		TreeSize:      proof.STH.TreeSize,
		SinkName:      anchor.OtsSinkName,
		AnchorID:      anchor.DeterministicOtsAnchorID(proof.STH),
		RootHash:      proof.STH.RootHash,
		STH:           proof.STH,
		Proof:         proofBytes,
	}
}

func TestAnchorConsistencyRejectsFileSinkLocalOnlyResult(t *testing.T) {
	t.Parallel()
	root := bytes.Repeat([]byte{0xaa}, cryptosuite.DigestSize)
	proof := newGlobalProofWithSTH(7, root)
	ar := model.STHAnchorResult{
		SchemaVersion: model.SchemaSTHAnchorResult,
		CryptoSuite:   proof.CryptoSuite,
		EvidenceStage: model.AnchorEvidenceStageLocalOnly,
		NodeID:        proof.STH.NodeID,
		LogID:         proof.STH.LogID,
		TreeSize:      proof.STH.TreeSize,
		SinkName:      anchor.FileSinkName,
		AnchorID:      anchor.DeterministicFileAnchorID(proof.STH),
		RootHash:      root,
		STH:           proof.STH,
	}
	if err := AnchorConsistency(proof, ar); err == nil || !strings.Contains(err.Error(), "offline_verified") {
		t.Fatalf("AnchorConsistency() error=%v, want local-only rejection", err)
	}
}

func TestAnchorConsistencyRejectsNoopLocalOnlyResult(t *testing.T) {
	t.Parallel()
	root := bytes.Repeat([]byte{0x01}, cryptosuite.DigestSize)
	proof := newGlobalProofWithSTH(8, root)
	ar := model.STHAnchorResult{
		SchemaVersion: model.SchemaSTHAnchorResult,
		CryptoSuite:   proof.CryptoSuite,
		EvidenceStage: model.AnchorEvidenceStageLocalOnly,
		NodeID:        proof.STH.NodeID,
		LogID:         proof.STH.LogID,
		TreeSize:      proof.STH.TreeSize,
		SinkName:      anchor.NoopSinkName,
		AnchorID:      anchor.DeterministicNoopAnchorID(proof.STH),
		RootHash:      root,
		STH:           proof.STH,
	}
	if err := AnchorConsistency(proof, ar); err == nil || !strings.Contains(err.Error(), "offline_verified") {
		t.Fatalf("AnchorConsistency() error=%v, want local-only rejection", err)
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
		CryptoSuite:   proof.CryptoSuite,
		EvidenceStage: model.AnchorEvidenceStageOfflineVerified,
		NodeID:        proof.STH.NodeID,
		LogID:         proof.STH.LogID,
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

type testAnchorVerifier struct {
	called bool
	err    error
}

func (v *testAnchorVerifier) VerifyAnchor(_ model.SignedTreeHead, _ model.STHAnchorResult) error {
	v.called = true
	return v.err
}

func TestAnchorConsistencyUsesExternalVerifier(t *testing.T) {
	root := bytes.Repeat([]byte{0x91}, 32)
	proof := newGlobalProofWithSTH(12, root)
	ar := model.STHAnchorResult{
		SchemaVersion: model.SchemaSTHAnchorResult,
		CryptoSuite:   proof.CryptoSuite,
		EvidenceStage: model.AnchorEvidenceStageOfflineVerified,
		NodeID:        proof.STH.NodeID,
		LogID:         proof.STH.LogID,
		TreeSize:      proof.STH.TreeSize,
		SinkName:      "vendor-chain",
		AnchorID:      "transaction-1",
		RootHash:      root,
		STH:           proof.STH,
	}
	verifier := &testAnchorVerifier{}
	if err := AnchorConsistencyWithVerifier(proof, ar, verifier); err != nil {
		t.Fatalf("AnchorConsistencyWithVerifier() error = %v", err)
	}
	if !verifier.called {
		t.Fatal("external verifier was not called")
	}
}

func TestAnchorContainerConsistencyAllowsBoundCustomProof(t *testing.T) {
	t.Parallel()
	root := bytes.Repeat([]byte{0x92}, 32)
	proof := newGlobalProofWithSTH(13, root)
	ar := model.STHAnchorResult{
		SchemaVersion: model.SchemaSTHAnchorResult,
		CryptoSuite:   proof.CryptoSuite,
		EvidenceStage: model.AnchorEvidenceStageOfflineVerified,
		NodeID:        proof.STH.NodeID,
		LogID:         proof.STH.LogID,
		TreeSize:      proof.STH.TreeSize,
		SinkName:      "vendor-chain",
		AnchorID:      "transaction-2",
		RootHash:      root,
		STH:           proof.STH,
		Proof:         []byte("opaque"),
	}
	if err := AnchorContainerConsistency(proof, ar); err != nil {
		t.Fatalf("AnchorContainerConsistency() error = %v", err)
	}
	if err := AnchorConsistency(proof, ar); err == nil || !strings.Contains(err.Error(), "unsupported anchor sink") {
		t.Fatalf("AnchorConsistency() error = %v, want fail closed", err)
	}
}

func TestAnchorConsistencyRejectsSchema(t *testing.T) {
	t.Parallel()
	proof := newGlobalProofWithSTH(1, []byte{1})
	ar := model.STHAnchorResult{
		SchemaVersion: "bogus",
		EvidenceStage: model.AnchorEvidenceStageOfflineVerified,
		NodeID:        proof.STH.NodeID,
		LogID:         proof.STH.LogID,
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
		CryptoSuite:   proof.CryptoSuite,
		EvidenceStage: model.AnchorEvidenceStageOfflineVerified,
		NodeID:        proof.STH.NodeID,
		LogID:         proof.STH.LogID,
		TreeSize:      3,
		SinkName:      anchor.NoopSinkName,
		AnchorID:      "noop-sth-3",
		RootHash:      []byte{1},
		STH:           proof.STH,
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
		CryptoSuite:   proof.CryptoSuite,
		EvidenceStage: model.AnchorEvidenceStageOfflineVerified,
		NodeID:        proof.STH.NodeID,
		LogID:         proof.STH.LogID,
		TreeSize:      proof.STH.TreeSize,
		SinkName:      anchor.NoopSinkName,
		AnchorID:      anchor.DeterministicNoopAnchorID(proof.STH),
		RootHash:      []byte{9, 9, 9},
		STH:           proof.STH,
	}
	err := AnchorConsistency(proof, ar)
	if err == nil || !strings.Contains(err.Error(), "root_hash") {
		t.Fatalf("want root_hash error, got %v", err)
	}
}

func TestAnchorConsistencyRejectsForgedOfflineVerifiedFileResult(t *testing.T) {
	t.Parallel()
	root := bytes.Repeat([]byte{0x12}, cryptosuite.DigestSize)
	proof := newGlobalProofWithSTH(5, root)
	ar := model.STHAnchorResult{
		SchemaVersion: model.SchemaSTHAnchorResult,
		CryptoSuite:   proof.CryptoSuite,
		EvidenceStage: model.AnchorEvidenceStageOfflineVerified,
		NodeID:        proof.STH.NodeID,
		LogID:         proof.STH.LogID,
		TreeSize:      proof.STH.TreeSize,
		SinkName:      anchor.FileSinkName,
		AnchorID:      anchor.DeterministicFileAnchorID(proof.STH),
		RootHash:      root,
		STH:           proof.STH,
	}
	err := AnchorConsistency(proof, ar)
	if err == nil || !strings.Contains(err.Error(), "local-only") {
		t.Fatalf("want forged file-sink evidence rejection, got %v", err)
	}
}

func TestAnchorConsistencyRejectsEmptyAnchorID(t *testing.T) {
	t.Parallel()
	proof := newGlobalProofWithSTH(6, []byte{1})
	ar := model.STHAnchorResult{
		SchemaVersion: model.SchemaSTHAnchorResult,
		CryptoSuite:   proof.CryptoSuite,
		EvidenceStage: model.AnchorEvidenceStageOfflineVerified,
		NodeID:        proof.STH.NodeID,
		LogID:         proof.STH.LogID,
		TreeSize:      proof.STH.TreeSize,
		SinkName:      "vendor-chain",
		RootHash:      []byte{1},
		STH:           proof.STH,
	}
	err := AnchorConsistency(proof, ar)
	if err == nil || !strings.Contains(err.Error(), "anchor_id") {
		t.Fatalf("want anchor_id missing error, got %v", err)
	}
}

func TestAnchorConsistencyRejectsNonVerifiedEvidenceStages(t *testing.T) {
	t.Parallel()
	proof := newGlobalProofWithSTH(7, bytes.Repeat([]byte{0x71}, 32))
	for _, stage := range []string{"", model.AnchorEvidenceStageRaw, model.AnchorEvidenceStageLocalOnly, "future_stage"} {
		stage := stage
		t.Run(stage, func(t *testing.T) {
			ar := model.STHAnchorResult{
				SchemaVersion: model.SchemaSTHAnchorResult,
				CryptoSuite:   proof.CryptoSuite,
				EvidenceStage: stage,
				NodeID:        proof.STH.NodeID,
				LogID:         proof.STH.LogID,
				TreeSize:      proof.STH.TreeSize,
				SinkName:      "vendor-chain",
				AnchorID:      "vendor-anchor-7",
				RootHash:      append([]byte(nil), proof.STH.RootHash...),
				STH:           proof.STH,
			}
			if err := AnchorConsistency(proof, ar); err == nil || !strings.Contains(err.Error(), "offline_verified") {
				t.Fatalf("stage %q error=%v, want fail-closed evidence-stage rejection", stage, err)
			}
		})
	}
}

func TestAnchorBindingConsistencyRequiresExactNodeAndLogIdentity(t *testing.T) {
	t.Parallel()
	proof := newGlobalProofWithSTH(8, bytes.Repeat([]byte{0x81}, 32))
	base := model.STHAnchorResult{
		SchemaVersion: model.SchemaSTHAnchorResult,
		CryptoSuite:   proof.CryptoSuite,
		EvidenceStage: model.AnchorEvidenceStageOfflineVerified,
		NodeID:        proof.STH.NodeID,
		LogID:         proof.STH.LogID,
		TreeSize:      proof.STH.TreeSize,
		SinkName:      "vendor-chain",
		AnchorID:      "vendor-anchor-8",
		RootHash:      append([]byte(nil), proof.STH.RootHash...),
		STH:           proof.STH,
	}
	tests := []struct {
		name   string
		mutate func(*model.STHAnchorResult, *model.GlobalLogProof)
		want   string
	}{
		{name: "missing anchor node", mutate: func(ar *model.STHAnchorResult, _ *model.GlobalLogProof) { ar.NodeID = "" }, want: "node_id"},
		{name: "missing sth node", mutate: func(_ *model.STHAnchorResult, proof *model.GlobalLogProof) { proof.STH.NodeID = "" }, want: "node_id"},
		{name: "different node", mutate: func(ar *model.STHAnchorResult, _ *model.GlobalLogProof) { ar.NodeID = "node-2" }, want: "node_id"},
		{name: "missing anchor log", mutate: func(ar *model.STHAnchorResult, _ *model.GlobalLogProof) { ar.LogID = "" }, want: "log_id"},
		{name: "missing sth log", mutate: func(_ *model.STHAnchorResult, proof *model.GlobalLogProof) { proof.STH.LogID = "" }, want: "log_id"},
		{name: "different log", mutate: func(ar *model.STHAnchorResult, _ *model.GlobalLogProof) { ar.LogID = "log-2" }, want: "log_id"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			ar, candidateProof := base, proof
			test.mutate(&ar, &candidateProof)
			if err := AnchorBindingConsistency(candidateProof, ar); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("AnchorBindingConsistency() error=%v, want %s rejection", err, test.want)
			}
		})
	}
}
