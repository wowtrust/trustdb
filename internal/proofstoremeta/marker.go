// Package proofstoremeta defines the durable cryptographic-suite binding shared
// by every proofstore backend. The marker is deliberately independent from the
// concrete storage engine so file, Pebble, TiKV, backup, and migration paths
// validate exactly the same bytes and invariants.
package proofstoremeta

import (
	"errors"
	"fmt"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
)

const (
	MarkerSchema     = "trustdb.proofstore-suite-marker.v1"
	StorageSchemaV4  = "trustdb-proofstore-v4"
	FormatGeneration = uint64(4)
	MaxMarkerBytes   = 4 << 10
)

var (
	ErrInvalidMarker = errors.New("invalid proofstore suite marker")
	ErrLegacySchema  = errors.New("legacy proofstore schema has no cryptographic suite marker")
	ErrSuiteMismatch = errors.New("proofstore cryptographic suite mismatch")
)

// Marker is the single durable namespace identity written at the same atomic
// boundary as proofstore schema initialization. CryptoSuite is immutable for
// the lifetime of a non-empty namespace.
type Marker struct {
	SchemaVersion    string         `cbor:"schema_version" json:"schema_version"`
	StorageSchema    string         `cbor:"storage_schema" json:"storage_schema"`
	FormatGeneration uint64         `cbor:"format_generation" json:"format_generation"`
	CryptoSuite      cryptosuite.ID `cbor:"crypto_suite" json:"crypto_suite"`
}

// Decode rejects the former string-only schema explicitly. Recognizing that
// shape is only for a clear fail-closed diagnostic; it never enables a legacy
// reader, marker backfill, or migration path.
func Decode(data []byte) (Marker, error) {
	var marker Marker
	if err := cborx.UnmarshalLimit(data, &marker, MaxMarkerBytes); err == nil {
		return marker, nil
	} else {
		var legacy string
		if legacyErr := cborx.UnmarshalLimit(data, &legacy, MaxMarkerBytes); legacyErr == nil {
			return Marker{}, fmt.Errorf("%w: %q", ErrLegacySchema, legacy)
		}
		return Marker{}, err
	}
}

func New(suiteID cryptosuite.ID) (Marker, error) {
	if _, err := cryptosuite.RequireKnown(suiteID); err != nil {
		return Marker{}, fmt.Errorf("%w: %v", ErrInvalidMarker, err)
	}
	return Marker{
		SchemaVersion:    MarkerSchema,
		StorageSchema:    StorageSchemaV4,
		FormatGeneration: FormatGeneration,
		CryptoSuite:      suiteID,
	}, nil
}

// RequestedSuite preserves the current INTL_V1 default for callers that have
// not yet exposed suite selection. An explicitly supplied value is never
// normalized or guessed.
func RequestedSuite(suiteID cryptosuite.ID) (cryptosuite.ID, error) {
	if suiteID == "" {
		suiteID = cryptosuite.INTLV1
	}
	if _, err := cryptosuite.RequireKnown(suiteID); err != nil {
		return "", err
	}
	return suiteID, nil
}

func Validate(marker Marker, expected cryptosuite.ID) error {
	if marker.SchemaVersion != MarkerSchema {
		return fmt.Errorf("%w: schema_version=%q want=%q", ErrInvalidMarker, marker.SchemaVersion, MarkerSchema)
	}
	if marker.StorageSchema != StorageSchemaV4 {
		return fmt.Errorf("%w: storage_schema=%q want=%q", ErrInvalidMarker, marker.StorageSchema, StorageSchemaV4)
	}
	if marker.FormatGeneration != FormatGeneration {
		return fmt.Errorf("%w: format_generation=%d want=%d", ErrInvalidMarker, marker.FormatGeneration, FormatGeneration)
	}
	if _, err := cryptosuite.RequireKnown(marker.CryptoSuite); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidMarker, err)
	}
	if _, err := cryptosuite.RequireKnown(expected); err != nil {
		return fmt.Errorf("%w: expected suite: %v", ErrInvalidMarker, err)
	}
	if marker.CryptoSuite != expected {
		return fmt.Errorf("%w: stored=%s configured=%s", ErrSuiteMismatch, marker.CryptoSuite, expected)
	}
	return nil
}
