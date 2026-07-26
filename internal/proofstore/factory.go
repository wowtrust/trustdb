package proofstore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	pebblestore "github.com/wowtrust/trustdb/v2/internal/proofstore/pebble"
	tikvstore "github.com/wowtrust/trustdb/v2/internal/proofstore/tikv"
	"github.com/wowtrust/trustdb/v2/internal/proofstoremeta"
	"github.com/wowtrust/trustdb/v2/internal/trusterr"
)

// Backend enumerates the supported proof store implementations.
type Backend string

const (
	BackendFile   Backend = "file"
	BackendPebble Backend = "pebble"
	BackendTiKV   Backend = "tikv"

	localStorageSchemaFile = ".trustdb-proofstore-schema"
)

var localStorageInitMu sync.Mutex

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
	CryptoSuite                  cryptosuite.ID
	NodeID                       string
	LogID                        string
	NamespaceID                  string
}

// Open constructs a Store using an explicit V5 backend and namespace binding.
func Open(cfg Config) (Store, error) {
	if cfg.Path == "" && Backend(strings.ToLower(string(cfg.Kind))) != BackendTiKV {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "proofstore path is required")
	}
	suiteID, err := proofstoremeta.RequestedSuite(cfg.CryptoSuite)
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeInvalidArgument, "invalid proofstore cryptographic suite", err)
	}
	if strings.TrimSpace(cfg.NodeID) == "" || strings.TrimSpace(cfg.LogID) == "" || strings.TrimSpace(cfg.NamespaceID) == "" {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "proofstore node_id, log_id, and namespace_id are required")
	}
	switch Backend(strings.ToLower(string(cfg.Kind))) {
	case BackendFile:
		return OpenLocalStore(cfg.Path, suiteID, cfg.NodeID, cfg.LogID, cfg.NamespaceID)
	case BackendPebble:
		return pebblestore.OpenWithOptions(cfg.Path, pebblestore.Options{
			RecordIndexMode:              cfg.RecordIndexMode,
			ArtifactSyncMode:             cfg.ArtifactSyncMode,
			IndexStorageTokens:           cfg.IndexStorageTokens,
			IndexStorageTokensConfigured: cfg.IndexStorageTokensConfigured,
			CryptoSuite:                  suiteID,
			NodeID:                       cfg.NodeID,
			LogID:                        cfg.LogID,
			NamespaceID:                  cfg.NamespaceID,
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
			CryptoSuite:                  suiteID,
			NodeID:                       cfg.NodeID,
			LogID:                        cfg.LogID,
			NamespaceID:                  cfg.NamespaceID,
		})
	default:
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "unknown proofstore backend: "+string(cfg.Kind))
	}
}

// OpenLocalStore opens a file proofstore only after its complete V5 namespace
// identity has been validated and durably bound.
func OpenLocalStore(root string, suiteID cryptosuite.ID, nodeID, logID, namespaceID string) (*LocalStore, error) {
	if strings.TrimSpace(root) == "" {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "proofstore path is required")
	}
	requested, err := proofstoremeta.RequestedSuite(suiteID)
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeInvalidArgument, "invalid proofstore cryptographic suite", err)
	}
	namespaceLock, err := acquireLocalNamespaceLock(root)
	if err != nil {
		return nil, err
	}
	marker, err := ensureLocalStorageSchema(root, requested, nodeID, logID, namespaceID)
	if err != nil {
		_ = namespaceLock.close()
		return nil, err
	}
	return newBoundLocalStore(root, marker, namespaceLock), nil
}

func ensureLocalStorageSchema(root string, expected cryptosuite.ID, nodeID, logID, namespaceID string) (proofstoremeta.Marker, error) {
	localStorageInitMu.Lock()
	defer localStorageInitMu.Unlock()

	markerPath := filepath.Join(root, localStorageSchemaFile)
	data, err := readStoredFileLimit(markerPath, proofstoremeta.MaxMarkerBytes)
	if err == nil {
		marker, err := proofstoremeta.Decode(data)
		if errors.Is(err, proofstoremeta.ErrLegacySchema) {
			return proofstoremeta.Marker{}, trusterr.Wrap(trusterr.CodeFailedPrecondition, "file proofstore requires a cryptographic suite marker", err)
		}
		if err != nil {
			return proofstoremeta.Marker{}, trusterr.Wrap(trusterr.CodeDataLoss, "decode file proofstore suite marker", err)
		}
		if err := proofstoremeta.ValidateBinding(marker, expected, nodeID, logID, namespaceID); err != nil {
			return proofstoremeta.Marker{}, trusterr.Wrap(trusterr.CodeFailedPrecondition, "validate file proofstore suite marker", err)
		}
		return marker, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return proofstoremeta.Marker{}, trusterr.Wrap(trusterr.CodeDataLoss, "read file proofstore suite marker", err)
	}

	entries, err := os.ReadDir(root)
	switch {
	case err == nil:
		for _, entry := range entries {
			if entry.Name() == localNamespaceLockFile {
				continue
			}
			if isLocalStorageMarkerTemp(entry.Name()) {
				if err := removeLocalFileDurable(filepath.Join(root, entry.Name())); err != nil {
					return proofstoremeta.Marker{}, trusterr.Wrap(trusterr.CodeDataLoss, "remove interrupted file proofstore marker", err)
				}
				continue
			}
			return proofstoremeta.Marker{}, trusterr.New(trusterr.CodeFailedPrecondition, "non-empty file proofstore has no cryptographic suite marker; clear or rebuild the proofstore")
		}
	case errors.Is(err, os.ErrNotExist):
		// writeCBORAtomic creates and durably publishes the missing directory.
	default:
		return proofstoremeta.Marker{}, trusterr.Wrap(trusterr.CodeDataLoss, "inspect file proofstore contents", err)
	}
	marker, err := proofstoremeta.New(expected, nodeID, logID, namespaceID)
	if err != nil {
		return proofstoremeta.Marker{}, trusterr.Wrap(trusterr.CodeInvalidArgument, "build file proofstore suite marker", err)
	}
	if err := writeCBORAtomic(markerPath, marker); err != nil {
		return proofstoremeta.Marker{}, trusterr.Wrap(trusterr.CodeDataLoss, "initialize file proofstore suite marker", err)
	}
	return marker, nil
}

func isLocalStorageMarkerTemp(name string) bool {
	prefix := "." + localStorageSchemaFile + "."
	return strings.HasPrefix(name, prefix) && strings.HasSuffix(name, ".tmp")
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
