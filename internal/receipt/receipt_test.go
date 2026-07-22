package receipt

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/model"
)

func TestSignCommittedPreservesDomainEncoding(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	receipt := model.CommittedReceipt{
		SchemaVersion: model.SchemaCommittedReceipt,
		RecordID:      "record-1",
		Status:        "committed",
		BatchID:       "batch-1",
		LeafIndex:     3,
		LeafHash:      bytes.Repeat([]byte{0x11}, 32),
		BatchRoot:     bytes.Repeat([]byte{0x22}, 32),
		ClosedAtUnixN: 1234,
		NodeID:        "node-1",
		LogID:         "log-1",
	}
	payload, err := cborx.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	legacyInput := append(append([]byte(committedDomain), 0), payload...)
	want := ed25519.Sign(privateKey, legacyInput)

	signed, err := SignCommitted(receipt, "server-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signed.ServerSig.Signature, want) {
		t.Fatal("pooled receipt encoder changed committed signature bytes")
	}
	if err := VerifyCommitted(signed, privateKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("VerifyCommitted: %v", err)
	}
}
