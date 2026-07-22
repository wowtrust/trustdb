package proofstore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/wowtrust/trustdb/internal/cborx"
	pebblestore "github.com/wowtrust/trustdb/internal/proofstore/pebble"
	tikvstore "github.com/wowtrust/trustdb/internal/proofstore/tikv"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

// Backend enumerates the supported proof store implementations.
type Backend string

const (
	BackendFile   Backend = "file"
	BackendPebble Backend = "pebble"
	BackendTiKV   Backend = "tikv"

	localStorageSchemaFile = ".trustdb-proofstore-schema"
	localStorageSchemaV4   = "trustdb-proofstore-v4"
)

// Config picks the backend and its on-disk location. Path is treated as
// a directory path for both file and Pebble modes; the file backend
// puts manifests/bundles/roots/checkpoint under it, while the Pebble
// backend uses it as the database directory.
type Config struct {
	Kind                         Backend
	Path                         string
	TiKVPDAddresses              []string
	TiKVKeyspace                 string
	TiKVNamespace                string
	CheckpointNodeID             string
	CheckpointWALID              string
	RecordIndexMode              string
	ArtifactSyncMode             string
	IndexStorageTokens           bool
	IndexStorageTokensConfigured bool
}

// Open constructs a Store using cfg. An empty Kind defaults to the file
// backend so existing deployments that only pass a proof directory keep
// working without any CLI changes.
func Open(cfg Config) (Store, error) {
	if cfg.Path == "" && Backend(strings.ToLower(string(cfg.Kind))) != BackendTiKV {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "proofstore path is required")
	}
	switch Backend(strings.ToLower(string(cfg.Kind))) {
	case "", BackendFile:
		if err := ensureLocalStorageSchema(cfg.Path); err != nil {
			return nil, err
		}
		return &LocalStore{Root: cfg.Path}, nil
	case BackendPebble:
		return pebblestore.OpenWithOptions(cfg.Path, pebblestore.Options{
			RecordIndexMode:              cfg.RecordIndexMode,
			ArtifactSyncMode:             cfg.ArtifactSyncMode,
			IndexStorageTokens:           cfg.IndexStorageTokens,
			IndexStorageTokensConfigured: cfg.IndexStorageTokensConfigured,
		})
	case BackendTiKV:
		if !hasTiKVPDAddress(cfg) {
			return nil, trusterr.New(trusterr.CodeInvalidArgument, "tikv proofstore requires at least one PD endpoint")
		}
		return tikvstore.OpenWithOptions(tikvstore.Options{
			PDAddresses:                  cfg.TiKVPDAddresses,
			PDAddressText:                cfg.Path,
			Keyspace:                     cfg.TiKVKeyspace,
			Namespace:                    cfg.TiKVNamespace,
			CheckpointNodeID:             cfg.CheckpointNodeID,
			CheckpointWALID:              cfg.CheckpointWALID,
			RecordIndexMode:              cfg.RecordIndexMode,
			ArtifactSyncMode:             cfg.ArtifactSyncMode,
			IndexStorageTokens:           cfg.IndexStorageTokens,
			IndexStorageTokensConfigured: cfg.IndexStorageTokensConfigured,
		})
	default:
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "unknown proofstore backend: "+string(cfg.Kind))
	}
}

func ensureLocalStorageSchema(root string) error {
	markerPath := filepath.Join(root, localStorageSchemaFile)
	data, err := readStoredFileLimit(markerPath, 1024)
	if err == nil {
		var schema string
		if err := cborx.UnmarshalLimit(data, &schema, 1024); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "decode file proofstore schema", err)
		}
		if schema != localStorageSchemaV4 {
			return trusterr.New(trusterr.CodeFailedPrecondition, fmt.Sprintf("unsupported file proofstore schema %q; expected %q; clear or rebuild the proofstore", schema, localStorageSchemaV4))
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return trusterr.Wrap(trusterr.CodeDataLoss, "read file proofstore schema", err)
	}

	entries, err := os.ReadDir(root)
	switch {
	case err == nil:
		if len(entries) != 0 {
			return trusterr.New(trusterr.CodeFailedPrecondition, "unversioned file proofstore detected; clear or rebuild the proofstore")
		}
	case errors.Is(err, os.ErrNotExist):
		// writeCBORAtomic creates and durably publishes the missing directory.
	default:
		return trusterr.Wrap(trusterr.CodeDataLoss, "inspect file proofstore contents", err)
	}
	if err := writeCBORAtomic(markerPath, localStorageSchemaV4); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "initialize file proofstore schema", err)
	}
	return nil
}

func hasTiKVPDAddress(cfg Config) bool {
	if strings.TrimSpace(cfg.Path) != "" {
		return true
	}
	for _, address := range cfg.TiKVPDAddresses {
		if strings.TrimSpace(address) != "" {
			return true
		}
	}
	return false
}
