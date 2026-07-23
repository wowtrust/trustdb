package proofstoremeta

import (
	"errors"
	"testing"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
)

func TestMarkerValidation(t *testing.T) {
	t.Parallel()
	marker, err := New(cryptosuite.INTLV1)
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
	legacy, err := cborx.Marshal(StorageSchemaV4)
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

func TestRequestedSuiteDefaultsOnlyAnOmittedConfiguration(t *testing.T) {
	t.Parallel()
	got, err := RequestedSuite("")
	if err != nil || got != cryptosuite.INTLV1 {
		t.Fatalf("RequestedSuite(empty) = %q, %v", got, err)
	}
	if _, err := RequestedSuite(cryptosuite.ID("intl_v1")); !errors.Is(err, cryptosuite.ErrUnknownSuite) {
		t.Fatalf("RequestedSuite(non-canonical) error = %v", err)
	}
}
