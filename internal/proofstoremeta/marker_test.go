package proofstoremeta

import (
	"errors"
	"testing"

	"github.com/wowtrust/trustdb/v2/internal/cborx"
	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
)

func TestMarkerValidation(t *testing.T) {
	t.Parallel()
	marker, err := New(cryptosuite.INTLV1, "node-1", "log-1", "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := Validate(marker, cryptosuite.INTLV1); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := Validate(marker, cryptosuite.CNSMV1); !errors.Is(err, ErrSuiteMismatch) {
		t.Fatalf("Validate mismatch error = %v, want ErrSuiteMismatch", err)
	}

	invalid := marker
	invalid.CryptoSuite = cryptosuite.ID("UNKNOWN")
	if err := Validate(invalid, cryptosuite.INTLV1); !errors.Is(err, ErrInvalidMarker) {
		t.Fatalf("Validate unknown error = %v, want ErrInvalidMarker", err)
	}
}

func TestDecodeDistinguishesLegacySchemaFromCorruption(t *testing.T) {
	t.Parallel()
	legacy, err := cborx.Marshal("trustdb-proofstore-v4")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(legacy); !errors.Is(err, ErrLegacySchema) {
		t.Fatalf("Decode legacy error = %v", err)
	}
	if _, err := Decode([]byte{0xff}); err == nil || errors.Is(err, ErrLegacySchema) {
		t.Fatalf("Decode corrupt error = %v", err)
	}
}

func TestRequestedSuiteRequiresExplicitConfiguration(t *testing.T) {
	t.Parallel()
	if _, err := RequestedSuite(""); !errors.Is(err, ErrInvalidMarker) {
		t.Fatalf("RequestedSuite(empty) error = %v", err)
	}
	if _, err := RequestedSuite(cryptosuite.ID("intl_v1")); !errors.Is(err, cryptosuite.ErrUnknownSuite) {
		t.Fatalf("RequestedSuite(non-canonical) error = %v", err)
	}
}

func TestNamespaceIdentityRejectsAmbiguousValues(t *testing.T) {
	t.Parallel()
	oversized := make([]byte, MaxIdentityBytes+1)
	for i := range oversized {
		oversized[i] = 'a'
	}
	for _, tc := range []struct {
		name        string
		nodeID      string
		logID       string
		namespaceID string
	}{
		{name: "empty", nodeID: "", logID: "log", namespaceID: "namespace"},
		{name: "leading whitespace", nodeID: " node", logID: "log", namespaceID: "namespace"},
		{name: "trailing whitespace", nodeID: "node", logID: "log ", namespaceID: "namespace"},
		{name: "control", nodeID: "node", logID: "log", namespaceID: "name\nspace"},
		{name: "oversized", nodeID: string(oversized), logID: "log", namespaceID: "namespace"},
		{name: "invalid utf8", nodeID: string([]byte{0xff}), logID: "log", namespaceID: "namespace"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := New(cryptosuite.INTLV1, tc.nodeID, tc.logID, tc.namespaceID); !errors.Is(err, ErrInvalidMarker) {
				t.Fatalf("New() error = %v, want ErrInvalidMarker", err)
			}
		})
	}
}
