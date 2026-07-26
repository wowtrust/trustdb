package sproof

import (
	"bytes"
	"testing"

	"github.com/wowtrust/trustdb/v2/internal/model"
)

func FuzzUnmarshalV2(f *testing.F) {
	valid, err := Marshal(vectorProof())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte("TDBSPROOF1"))
	f.Add([]byte{0xa0})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxBytes {
			return
		}
		proof, err := Unmarshal(data)
		if err != nil {
			return
		}
		if err := Validate(proof); err != nil {
			t.Fatalf("Unmarshal() returned an invalid proof: %v", err)
		}
		canonical, err := Marshal(proof)
		if err != nil {
			t.Fatalf("Marshal(valid proof) error = %v", err)
		}
		roundTrip, err := Unmarshal(canonical)
		if err != nil {
			t.Fatalf("Unmarshal(canonical proof) error = %v", err)
		}
		equal, err := EqualEncoded(proof, roundTrip)
		if err != nil || !equal {
			t.Fatalf("EqualEncoded() = %v, %v", equal, err)
		}
		if !bytes.Equal(data, canonical) {
			t.Fatal("Unmarshal() accepted a non-canonical V2 representation")
		}
	})
}

func FuzzValidateIdentityEvidence(f *testing.F) {
	proof := vectorProof()
	proof.ProofBundle.SignedClaim.Signature.KeyID = "client-key"
	proof.IdentityEvidence = []model.ProofIdentityEvidence{{
		SchemaVersion: model.SchemaProofIdentity,
		CryptoSuite:   proof.CryptoSuite,
		Role:          model.ProofIdentityRoleClient,
		KeyID:         "client-key",
		KeyDescriptor: verifierDescriptor(f, "client-key"),
	}}
	valid, err := Marshal(proof)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxBytes {
			return
		}
		decoded, err := Unmarshal(data)
		if err != nil {
			return
		}
		_, _ = VerifyIdentityEvidence(decoded, IdentityTrust{})
	})
}
