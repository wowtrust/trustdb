package model

import (
	"testing"

	"github.com/wowtrust/trustdb/internal/cryptosuite"
)

func TestDefaultCryptographyMatchesINTLV1Registry(t *testing.T) {
	suite, ok := cryptosuite.Lookup(cryptosuite.INTLV1)
	if !ok {
		t.Fatal("INTL_V1 missing from cryptographic suite registry")
	}
	if DefaultCryptoSuite != string(suite.ID) {
		t.Fatalf("DefaultCryptoSuite = %q, want %q", DefaultCryptoSuite, suite.ID)
	}
	if DefaultHashAlg != suite.ContentHash.Algorithm {
		t.Fatalf("DefaultHashAlg = %q, want %q", DefaultHashAlg, suite.ContentHash.Algorithm)
	}
	if DefaultSignatureAlg != suite.Signature.Algorithm {
		t.Fatalf("DefaultSignatureAlg = %q, want %q", DefaultSignatureAlg, suite.Signature.Algorithm)
	}
	if DefaultMerkleTreeAlg != suite.Merkle.Algorithm {
		t.Fatalf("DefaultMerkleTreeAlg = %q, want %q", DefaultMerkleTreeAlg, suite.Merkle.Algorithm)
	}
}
