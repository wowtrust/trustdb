//go:build e2e

package e2e

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCLILocalProofFlow(t *testing.T) {
	t.Parallel()

	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}
	tmp := t.TempDir()
	payload := filepath.Join(tmp, "payload.bin")
	if err := os.WriteFile(payload, []byte("hello trustdb e2e"), 0o600); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	runTrustDB(t, root, "keygen", "--out", tmp, "--prefix", "client")
	runTrustDB(t, root, "keygen", "--out", tmp, "--prefix", "server")
	runTrustDB(t, root, "keygen", "--out", tmp, "--prefix", "registry")
	registry := filepath.Join(tmp, "keys.tdkeys")
	runTrustDB(t, root,
		"key-register",
		"--registry", registry,
		"--registry-private-key", filepath.Join(tmp, "registry.key"),
		"--registry-key-id", "registry-key",
		"--tenant", "tenant-e2e",
		"--client", "client-e2e",
		"--key-id", "client-key",
		"--public-key", filepath.Join(tmp, "client.pub"),
		"--valid-from-unix", "0",
	)

	claimPath := filepath.Join(tmp, "claim.tdclaim")
	runTrustDB(t, root,
		"claim-file",
		"--file", payload,
		"--tenant", "tenant-e2e",
		"--client", "client-e2e",
		"--key-id", "client-key",
		"--private-key", filepath.Join(tmp, "client.key"),
		"--object-dir", filepath.Join(tmp, "objects"),
		"--out", claimPath,
	)

	proofPath := filepath.Join(tmp, "proof.tdproof")
	runTrustDB(t, root,
		"commit",
		"--claim", claimPath,
		"--key-registry", registry,
		"--registry-public-key", filepath.Join(tmp, "registry.pub"),
		"--server-private-key", filepath.Join(tmp, "server.key"),
		"--server-key-id", "server-key",
		"--wal", filepath.Join(tmp, "trustdb.wal"),
		"--out", proofPath,
	)
	inspectOut := runTrustDB(t, root, "proof", "inspect", "--proof", proofPath)
	var inspected struct {
		RecordID string `json:"record_id"`
		TreeSize uint64 `json:"tree_size"`
	}
	if err := json.Unmarshal(inspectOut, &inspected); err != nil {
		t.Fatalf("decode proof inspect output %q: %v", inspectOut, err)
	}
	if inspected.RecordID == "" || inspected.TreeSize != 1 {
		t.Fatalf("proof inspect = %+v", inspected)
	}

	out := runTrustDB(t, root,
		"verify",
		"--file", payload,
		"--proof", proofPath,
		"--key-registry", registry,
		"--registry-public-key", filepath.Join(tmp, "registry.pub"),
		"--server-public-key", filepath.Join(tmp, "server.pub"),
	)
	var result struct {
		Valid      bool   `json:"valid"`
		RecordID   string `json:"record_id"`
		ProofLevel string `json:"proof_level"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("decode verify output %q: %v", out, err)
	}
	if !result.Valid || result.RecordID == "" || result.ProofLevel != "L3" {
		t.Fatalf("verify result = %+v", result)
	}
}

func TestCLIBatchProofFlow(t *testing.T) {
	t.Parallel()

	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}
	tmp := t.TempDir()
	payloadA := filepath.Join(tmp, "a.bin")
	payloadB := filepath.Join(tmp, "b.bin")
	if err := os.WriteFile(payloadA, []byte("batch payload a"), 0o600); err != nil {
		t.Fatalf("write payload a: %v", err)
	}
	if err := os.WriteFile(payloadB, []byte("batch payload b"), 0o600); err != nil {
		t.Fatalf("write payload b: %v", err)
	}
	runTrustDB(t, root, "keygen", "--out", tmp, "--prefix", "client")
	runTrustDB(t, root, "keygen", "--out", tmp, "--prefix", "server")
	runTrustDB(t, root, "keygen", "--out", tmp, "--prefix", "registry")
	registry := filepath.Join(tmp, "keys.tdkeys")
	runTrustDB(t, root,
		"key-register",
		"--registry", registry,
		"--registry-private-key", filepath.Join(tmp, "registry.key"),
		"--tenant", "tenant-e2e",
		"--client", "client-e2e",
		"--key-id", "client-key",
		"--public-key", filepath.Join(tmp, "client.pub"),
		"--valid-from-unix", "0",
	)
	claimA := filepath.Join(tmp, "a.tdclaim")
	claimB := filepath.Join(tmp, "b.tdclaim")
	for _, item := range []struct {
		payload string
		claim   string
	}{
		{payload: payloadA, claim: claimA},
		{payload: payloadB, claim: claimB},
	} {
		runTrustDB(t, root,
			"claim-file",
			"--file", item.payload,
			"--tenant", "tenant-e2e",
			"--client", "client-e2e",
			"--key-id", "client-key",
			"--private-key", filepath.Join(tmp, "client.key"),
			"--object-dir", filepath.Join(tmp, "objects"),
			"--out", item.claim,
		)
	}
	proofsDir := filepath.Join(tmp, "proofs")
	out := runTrustDB(t, root,
		"commit-batch",
		"--claim", claimA,
		"--claim", claimB,
		"--key-registry", registry,
		"--registry-public-key", filepath.Join(tmp, "registry.pub"),
		"--server-private-key", filepath.Join(tmp, "server.key"),
		"--wal", filepath.Join(tmp, "batch.wal"),
		"--out-dir", proofsDir,
		"--batch-id", "batch-e2e",
	)
	var committed []struct {
		RecordID string `json:"record_id"`
		Proof    string `json:"proof"`
		Level    string `json:"level"`
	}
	if err := json.Unmarshal(out, &committed); err != nil {
		t.Fatalf("decode commit-batch output %q: %v", out, err)
	}
	if len(committed) != 2 {
		t.Fatalf("commit-batch returned %d proofs", len(committed))
	}
	for i, item := range []string{payloadA, payloadB} {
		out := runTrustDB(t, root,
			"verify",
			"--file", item,
			"--proof", committed[i].Proof,
			"--key-registry", registry,
			"--registry-public-key", filepath.Join(tmp, "registry.pub"),
			"--server-public-key", filepath.Join(tmp, "server.pub"),
		)
		var result struct {
			Valid bool `json:"Valid"`
		}
		if err := json.Unmarshal(out, &result); err != nil {
			t.Fatalf("decode verify output %q: %v", out, err)
		}
		if !result.Valid {
			t.Fatalf("verify result = %+v", result)
		}
	}
}

func runTrustDB(t *testing.T, root string, args ...string) []byte {
	t.Helper()
	cmdArgs := append([]string{"run", "./cmd/trustdb"}, args...)
	cmd := exec.Command("go", cmdArgs...)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go %v failed: %v\n%s", cmdArgs, err, out)
	}
	return out
}
