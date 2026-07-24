package app_test

import (
	"testing"

	"github.com/wowtrust/trustdb/test/cnsmvectors"
)

func TestServerGenerationMatchesSharedCNSMInteropCorpus(t *testing.T) {
	want, err := cnsmvectors.Load()
	if err != nil {
		t.Fatal(err)
	}
	got, err := cnsmvectors.Generate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		name string
		got  cnsmvectors.Artifact
		want cnsmvectors.Artifact
	}{
		{"signed claim", got.Artifacts.SignedClaim, want.Artifacts.SignedClaim},
		{"server record", got.Artifacts.ServerRecord, want.Artifacts.ServerRecord},
		{"accepted receipt", got.Artifacts.AcceptedReceipt, want.Artifacts.AcceptedReceipt},
		{"committed receipt", got.Artifacts.CommittedReceipt, want.Artifacts.CommittedReceipt},
		{"batch root", got.Artifacts.BatchRoot, want.Artifacts.BatchRoot},
		{"proof bundle", got.Artifacts.ProofBundle, want.Artifacts.ProofBundle},
		{"global leaf", got.Artifacts.GlobalLogLeaf, want.Artifacts.GlobalLogLeaf},
		{"signed tree head", got.Artifacts.SignedTreeHead, want.Artifacts.SignedTreeHead},
		{"global proof", got.Artifacts.GlobalLogProof, want.Artifacts.GlobalLogProof},
	} {
		if item.got != item.want {
			t.Fatalf("%s drifted from the shared CN_SM_V1 corpus", item.name)
		}
	}
}
