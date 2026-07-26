// Package proofstoremeta defines the durable cryptographic-suite binding shared
// by every proofstore backend. The marker is deliberately independent from the
// concrete storage engine so file, Pebble, TiKV, backup, and migration paths
// validate exactly the same bytes and invariants.
package proofstoremeta

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/wowtrust/trustdb/v2/internal/cborx"
	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
)

const (
	MarkerSchema     = "trustdb.proofstore-namespace.v2"
	StorageSchemaV5  = "trustdb-proofstore-v5"
	FormatGeneration = uint64(5)
	MaxMarkerBytes   = 4 << 10
	MaxIdentityBytes = 256
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
	NodeID           string         `cbor:"node_id" json:"node_id"`
	LogID            string         `cbor:"log_id" json:"log_id"`
	NamespaceID      string         `cbor:"namespace_id" json:"namespace_id"`
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

func New(suiteID cryptosuite.ID, nodeID, logID, namespaceID string) (Marker, error) {
	if _, err := cryptosuite.RequireAvailable(suiteID); err != nil {
		return Marker{}, fmt.Errorf("%w: %v", ErrInvalidMarker, err)
	}
	if err := ValidateIdentity(nodeID, logID, namespaceID); err != nil {
		return Marker{}, err
	}
	return Marker{
		SchemaVersion:    MarkerSchema,
		StorageSchema:    StorageSchemaV5,
		FormatGeneration: FormatGeneration,
		CryptoSuite:      suiteID,
		NodeID:           nodeID,
		LogID:            logID,
		NamespaceID:      namespaceID,
	}, nil
}

func RequestedSuite(suiteID cryptosuite.ID) (cryptosuite.ID, error) {
	if suiteID == "" {
		return "", fmt.Errorf("%w: crypto_suite is required", ErrInvalidMarker)
	}
	if _, err := cryptosuite.RequireAvailable(suiteID); err != nil {
		return "", err
	}
	return suiteID, nil
}

func Validate(marker Marker, expected cryptosuite.ID) error {
	if marker.SchemaVersion != MarkerSchema {
		return fmt.Errorf("%w: schema_version=%q want=%q", ErrInvalidMarker, marker.SchemaVersion, MarkerSchema)
	}
	if marker.StorageSchema != StorageSchemaV5 {
		return fmt.Errorf("%w: storage_schema=%q want=%q", ErrInvalidMarker, marker.StorageSchema, StorageSchemaV5)
	}
	if marker.FormatGeneration != FormatGeneration {
		return fmt.Errorf("%w: format_generation=%d want=%d", ErrInvalidMarker, marker.FormatGeneration, FormatGeneration)
	}
	if _, err := cryptosuite.RequireKnown(marker.CryptoSuite); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidMarker, err)
	}
	if err := ValidateIdentity(marker.NodeID, marker.LogID, marker.NamespaceID); err != nil {
		return err
	}
	if _, err := cryptosuite.RequireKnown(expected); err != nil {
		return fmt.Errorf("%w: expected suite: %v", ErrInvalidMarker, err)
	}
	if marker.CryptoSuite != expected {
		return fmt.Errorf("%w: stored=%s configured=%s", ErrSuiteMismatch, marker.CryptoSuite, expected)
	}
	return nil
}

func ValidateBinding(marker Marker, expected cryptosuite.ID, nodeID, logID, namespaceID string) error {
	if err := ValidateIdentity(nodeID, logID, namespaceID); err != nil {
		return err
	}
	if err := Validate(marker, expected); err != nil {
		return err
	}
	if marker.NodeID != nodeID || marker.LogID != logID || marker.NamespaceID != namespaceID {
		return fmt.Errorf(
			"%w: stored=(%q,%q,%q) configured=(%q,%q,%q)",
			ErrInvalidMarker,
			marker.NodeID,
			marker.LogID,
			marker.NamespaceID,
			nodeID,
			logID,
			namespaceID,
		)
	}
	return nil
}

func ValidateIdentity(nodeID, logID, namespaceID string) error {
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "node_id", value: nodeID},
		{name: "log_id", value: logID},
		{name: "namespace_id", value: namespaceID},
	} {
		if field.value == "" || strings.TrimSpace(field.value) != field.value {
			return fmt.Errorf("%w: %s is empty or has surrounding whitespace", ErrInvalidMarker, field.name)
		}
		if len(field.value) > MaxIdentityBytes || !utf8.ValidString(field.value) {
			return fmt.Errorf("%w: %s is oversized or invalid UTF-8", ErrInvalidMarker, field.name)
		}
		for _, r := range field.value {
			if unicode.IsControl(r) {
				return fmt.Errorf("%w: %s contains a control character", ErrInvalidMarker, field.name)
			}
		}
	}
	return nil
}
