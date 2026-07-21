package proofstore

import (
	"strings"

	pebblestore "github.com/ryan-wong-coder/trustdb/internal/proofstore/pebble"
	tikvstore "github.com/ryan-wong-coder/trustdb/internal/proofstore/tikv"
	"github.com/ryan-wong-coder/trustdb/internal/trusterr"
)

// Backend enumerates the supported proof store implementations.
type Backend string

const (
	BackendFile   Backend = "file"
	BackendPebble Backend = "pebble"
	BackendTiKV   Backend = "tikv"
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
