package app

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/ryan-wong-coder/trustdb/internal/merkle"
	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/receipt"
)

func TestComputeBatchPlanOnlyAndMaterialized(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	engine := LocalEngine{ServerID: "server-1", LogID: "log-1", ServerKeyID: "server-key", ServerPrivateKey: privateKey, ProofWorkers: 2}
	signed, records, accepted := syntheticCommitBatchInputs(8)
	closedAt := time.Unix(123, 0).UTC()

	planned, err := engine.ComputeBatch(context.Background(), "batch-1", closedAt, signed, records, accepted, model.BatchComputeOptions{Mode: model.BatchComputePlanOnly, IncludeTree: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(planned.Bundles) != 0 || len(planned.Indexes) != len(records) {
		t.Fatalf("planned result = %+v", planned)
	}
	for i := range planned.Indexes {
		if planned.Indexes[i].ProofLevel != "L2" {
			t.Fatalf("planned index %d proof_level=%q", i, planned.Indexes[i].ProofLevel)
		}
	}
	if len(planned.Tree.LeafHashes) != len(records) {
		t.Fatalf("tree leaves=%d want=%d", len(planned.Tree.LeafHashes), len(records))
	}

	materialized, err := engine.ComputeBatch(context.Background(), "batch-1", closedAt, signed, records, accepted, model.BatchComputeOptions{Mode: model.BatchComputeMaterialized})
	if err != nil {
		t.Fatal(err)
	}
	if len(materialized.Bundles) != len(records) {
		t.Fatalf("bundles=%d want=%d", len(materialized.Bundles), len(records))
	}
	for i := range materialized.Bundles {
		bundle := materialized.Bundles[i]
		if materialized.Indexes[i].ProofLevel != "L3" {
			t.Fatalf("materialized index %d proof_level=%q", i, materialized.Indexes[i].ProofLevel)
		}
		if err := receipt.VerifyCommitted(bundle.CommittedReceipt, privateKey.Public().(ed25519.PublicKey)); err != nil {
			t.Fatalf("receipt %d: %v", i, err)
		}
		if !merkle.Verify(bundle.CommittedReceipt.LeafHash, uint64(i), uint64(len(records)), bundle.BatchProof.AuditPath, materialized.Root.BatchRoot) {
			t.Fatalf("proof %d does not verify", i)
		}
	}
}
