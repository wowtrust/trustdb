package anchor

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/proofstore"
)

func TestExamplePluginExecutablePublishAndVerify(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the standalone example plugin")
	}
	binaryName := "anchor-plugin"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binaryPath := filepath.Join(t.TempDir(), binaryName)
	build := exec.Command("go", "build", "-o", binaryPath, "../../examples/anchor-plugin")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build example plugin: %v\n%s", err, output)
	}

	sink, err := NewPluginSink(context.Background(), PluginSinkOptions{
		Command:      binaryPath,
		StartTimeout: 20 * time.Second,
		RPCTimeout:   5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewPluginSink() error = %v", err)
	}
	defer sink.Close()

	key := model.STHAnchorScheduleKey{NodeID: "node-1", LogID: "log-1", SinkName: sink.Name()}
	sth := model.SignedTreeHead{
		SchemaVersion:  model.SchemaSignedTreeHead,
		TreeAlg:        model.DefaultMerkleTreeAlg,
		TreeSize:       3,
		RootHash:       bytes.Repeat([]byte{0x61}, 32),
		TimestampUnixN: 123,
		NodeID:         "node-1",
		LogID:          "log-1",
		Signature: model.Signature{
			Alg: model.DefaultSignatureAlg, KeyID: "server-key", Signature: bytes.Repeat([]byte{0x22}, 64),
		},
	}
	store := proofstore.LocalStore{Root: t.TempDir()}
	offer(t, store, key, sth, 100, 100)
	now := time.Unix(0, 100)
	service := newTestService(t, store, sink, key, &now, nil)
	service.tick(context.Background())
	result, found, err := store.GetSTHAnchorResult(context.Background(), sth.TreeSize)
	if err != nil || !found {
		t.Fatalf("GetSTHAnchorResult() result=%+v found=%v error=%v", result, found, err)
	}
	if err := sink.VerifyAnchor(sth, result); err != nil {
		t.Fatalf("VerifyAnchor() error = %v", err)
	}
	system, err := sink.System(context.Background())
	if err != nil || system.SystemID != "example-evidence-chain" || system.Kind != model.AnchorSystemKindEvidenceBlockchain {
		t.Fatalf("System() = %+v err=%v", system, err)
	}
	status, err := sink.Status(context.Background())
	if err != nil || status.State != model.AnchorSystemStateHealthy || status.Details["block_count"] != "1" {
		t.Fatalf("Status() = %+v err=%v", status, err)
	}
	blocks, err := sink.ListResources(context.Background(), model.AnchorResourceListOptions{Kind: model.AnchorResourceKindBlock, Limit: 10})
	if err != nil || len(blocks.Resources) != 1 || blocks.Resources[0].Height != sth.TreeSize {
		t.Fatalf("ListResources(block) = %+v err=%v", blocks, err)
	}
	transaction, found, err := sink.Resource(context.Background(), model.AnchorResourceKindTransaction, result.AnchorID)
	if err != nil || !found || transaction.ParentID != "3" {
		t.Fatalf("Resource(transaction) = %+v found=%v err=%v", transaction, found, err)
	}
	result.Proof[0] ^= 0xff
	if err := sink.VerifyAnchor(sth, result); err == nil {
		t.Fatal("VerifyAnchor() accepted tampered proof")
	}
}
