// Package backup implements TrustDB's portable proofstore backup format.
// A .tdbackup archive is logical rather than backend-specific: it stores
// deterministic CBOR objects in a tar stream so file and Pebble stores can
// restore each other's data without copying implementation directories.
package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/bits"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/wowtrust/trustdb/v2/internal/anchor/fiscobcos"
	"github.com/wowtrust/trustdb/v2/internal/anchorschedule"
	"github.com/wowtrust/trustdb/v2/internal/cborx"
	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/keyenvelope"
	"github.com/wowtrust/trustdb/v2/internal/keystore"
	"github.com/wowtrust/trustdb/v2/internal/model"
	"github.com/wowtrust/trustdb/v2/internal/proofstore"
	"github.com/wowtrust/trustdb/v2/internal/proofstoremeta"
	"github.com/wowtrust/trustdb/v2/internal/trustcrypto"
	"github.com/wowtrust/trustdb/v2/internal/trusterr"
)

const SchemaManifest = "trustdb.backup.v5"
const SchemaRestoreCheckpoint = "trustdb.backup-restore-checkpoint.v2"
const scanPageSize = 1024
const maxRestoreEntryBytes int64 = 128 << 20
const maxRestoreCheckpointBytes int64 = 1 << 20
const maxRecoveryArtifactBytes int64 = 128 << 20

const (
	paxBackupID  = "trustdb.backup_id"
	paxOrdinal   = "trustdb.ordinal"
	paxDigest    = "trustdb.digest"
	paxDigestAlg = "trustdb.digest_algorithm"
	paxType      = "trustdb.type"
	paxSuite     = "trustdb.crypto_suite"

	encodedArchiveNamePrefix = "~"
)

type Entry struct {
	Ordinal         int64          `cbor:"ordinal" json:"ordinal"`
	Name            string         `cbor:"name" json:"name"`
	Type            string         `cbor:"type" json:"type"`
	Size            int64          `cbor:"size" json:"size"`
	CryptoSuite     cryptosuite.ID `cbor:"crypto_suite" json:"crypto_suite"`
	DigestAlgorithm string         `cbor:"digest_algorithm" json:"digest_algorithm"`
	Digest          []byte         `cbor:"digest" json:"digest"`
}

type Manifest struct {
	SchemaVersion     string         `cbor:"schema_version" json:"schema_version"`
	BackupID          string         `cbor:"backup_id" json:"backup_id"`
	ParentBackupID    string         `cbor:"parent_backup_id,omitempty" json:"parent_backup_id,omitempty"`
	CreatedAt         string         `cbor:"created_at" json:"created_at"`
	Compression       string         `cbor:"compression" json:"compression"`
	CryptoSuite       cryptosuite.ID `cbor:"crypto_suite" json:"crypto_suite"`
	FormatGeneration  uint64         `cbor:"format_generation" json:"format_generation"`
	NodeID            string         `cbor:"node_id" json:"node_id"`
	LogID             string         `cbor:"log_id" json:"log_id"`
	NamespaceID       string         `cbor:"namespace_id" json:"namespace_id"`
	TargetNamespaceID string         `cbor:"target_namespace_id,omitempty" json:"target_namespace_id,omitempty"`
	Encryption        string         `cbor:"encryption" json:"encryption"`
	KEKProvider       string         `cbor:"kek_provider" json:"kek_provider"`
	KEKKeyID          string         `cbor:"kek_key_id" json:"kek_key_id"`
	DigestAlgorithm   string         `cbor:"digest_algorithm" json:"digest_algorithm"`

	Manifests       int       `cbor:"manifests" json:"manifests"`
	Bundles         int       `cbor:"bundles" json:"bundles"`
	BatchTreeLeaves int       `cbor:"batch_tree_leaves" json:"batch_tree_leaves"`
	BatchTreeNodes  int       `cbor:"batch_tree_nodes" json:"batch_tree_nodes"`
	Roots           int       `cbor:"roots" json:"roots"`
	GlobalLeaves    int       `cbor:"global_leaves" json:"global_leaves"`
	GlobalNodes     int       `cbor:"global_nodes" json:"global_nodes"`
	GlobalState     bool      `cbor:"global_state" json:"global_state"`
	STHs            int       `cbor:"sths" json:"sths"`
	GlobalTiles     int       `cbor:"global_tiles" json:"global_tiles"`
	GlobalOutboxes  int       `cbor:"global_outboxes" json:"global_outboxes"`
	AnchorResults   int       `cbor:"anchor_results" json:"anchor_results"`
	AnchorSchedules int       `cbor:"anchor_schedules" json:"anchor_schedules"`
	KeyRegistries   int       `cbor:"key_registries" json:"key_registries"`
	Inventory       Inventory `cbor:"inventory" json:"inventory"`
	Entries         []Entry   `cbor:"entries" json:"entries"`
}

type Inventory struct {
	SecretReferences       []string `cbor:"secret_references" json:"secret_references"`
	PublicEvidence         []string `cbor:"public_evidence" json:"public_evidence"`
	DerivedIndexes         []string `cbor:"derived_indexes" json:"derived_indexes"`
	RebuildableCheckpoints []string `cbor:"rebuildable_checkpoints" json:"rebuildable_checkpoints"`
}

type Options struct {
	Compression     string
	Clock           func() time.Time
	Random          io.Reader
	FrameBytes      int
	ParentBackupID  string
	KEKProvider     keyenvelope.KEKProvider
	KEKKeyID        string
	KeyRegistryPath string
}

type RestoreOptions struct {
	Resume         bool
	CheckpointPath string
	KEKProviders   []keyenvelope.KEKProvider
	RecoveryDir    string
}

type RestoreCheckpoint struct {
	SchemaVersion     string         `json:"schema_version"`
	BackupID          string         `json:"backup_id"`
	CryptoSuite       cryptosuite.ID `json:"crypto_suite"`
	NodeID            string         `json:"node_id"`
	LogID             string         `json:"log_id"`
	SourceNamespaceID string         `json:"source_namespace_id"`
	TargetNamespaceID string         `json:"target_namespace_id"`
	RecoveryDir       string         `json:"recovery_dir,omitempty"`
	LastOrdinal       int64          `json:"last_ordinal"`
	LastName          string         `json:"last_name"`
	UpdatedAt         string         `json:"updated_at"`
}

func Create(ctx context.Context, store proofstore.Store, path string, opts Options) (Manifest, error) {
	if store == nil {
		return Manifest{}, trusterr.New(trusterr.CodeInvalidArgument, "backup store is required")
	}
	if path == "" {
		return Manifest{}, trusterr.New(trusterr.CodeInvalidArgument, "backup output path is required")
	}
	binding, err := proofstore.BoundNamespace(store)
	if err != nil {
		return Manifest{}, err
	}
	suiteID := binding.CryptoSuite
	_, suite, err := requireBackupV5(suiteID)
	if err != nil {
		return Manifest{}, err
	}
	if opts.KEKProvider == nil || strings.TrimSpace(opts.KEKKeyID) == "" {
		return Manifest{}, trusterr.New(trusterr.CodeInvalidArgument, "backup KEK provider and key ID are required")
	}
	resultLister, ok := store.(proofstore.STHAnchorResultLister)
	if !ok {
		return Manifest{}, trusterr.New(trusterr.CodeFailedPrecondition, "backup store cannot enumerate STH anchor results")
	}
	scheduleStore, ok := store.(proofstore.STHAnchorScheduleStore)
	if !ok {
		return Manifest{}, trusterr.New(trusterr.CodeFailedPrecondition, "backup store cannot enumerate STH anchor schedules")
	}
	compression, err := normaliseCompression(opts.Compression)
	if err != nil {
		return Manifest{}, err
	}
	clock := opts.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Manifest{}, trusterr.Wrap(trusterr.CodeInternal, "create backup directory", err)
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return Manifest{}, trusterr.Wrap(trusterr.CodeInternal, "create backup file", err)
	}
	tmpPath := f.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
		_ = f.Close()
	}()

	createdAt := clock().UTC()
	backupID := fmt.Sprintf("tdb-%d", createdAt.UnixNano())
	frameBytes := opts.FrameBytes
	if frameBytes == 0 {
		frameBytes = defaultFramePlainBytes
	}
	frames, envelope, err := newEncryptedArchiveWriter(ctx, f, EnvelopeHeader{
		BackupID:            backupID,
		CreatedAt:           createdAt.Format(time.RFC3339Nano),
		Compression:         compression,
		CryptoSuite:         suiteID,
		FormatGeneration:    binding.FormatGeneration,
		NodeID:              binding.NodeID,
		LogID:               binding.LogID,
		NamespaceID:         binding.NamespaceID,
		FramePlaintextBytes: uint32(frameBytes),
		KEKKeyID:            strings.TrimSpace(opts.KEKKeyID),
	}, opts.KEKProvider, opts.Random)
	if err != nil {
		return Manifest{}, err
	}
	var out io.Writer = frames
	var gz *gzip.Writer
	if compression == "gzip" {
		gz = gzip.NewWriter(frames)
		gz.Header.ModTime = time.Unix(0, 0).UTC()
		gz.Header.OS = 255
		out = gz
	}
	tw := tar.NewWriter(out)
	closeArchive := func() error {
		if err := tw.Close(); err != nil {
			return err
		}
		if gz != nil {
			if err := gz.Close(); err != nil {
				return err
			}
		}
		return frames.Close()
	}

	report := Manifest{
		SchemaVersion:    SchemaManifest,
		BackupID:         envelope.BackupID,
		ParentBackupID:   strings.TrimSpace(opts.ParentBackupID),
		CreatedAt:        envelope.CreatedAt,
		Compression:      envelope.Compression,
		CryptoSuite:      envelope.CryptoSuite,
		FormatGeneration: envelope.FormatGeneration,
		NodeID:           envelope.NodeID,
		LogID:            envelope.LogID,
		NamespaceID:      envelope.NamespaceID,
		Encryption:       envelope.ContentAlgorithm,
		KEKProvider:      envelope.KEKProvider,
		KEKKeyID:         envelope.KEKKeyID,
		DigestAlgorithm:  suite.StorageIntegrityHash.Algorithm,
		Inventory:        backupInventory(envelope.KEKProvider, envelope.KEKKeyID, false),
		Entries:          make([]Entry, 0),
	}
	var ordinal int64

	afterBatchID := ""
	for {
		manifests, err := store.ListManifestsAfter(ctx, afterBatchID, scanPageSize)
		if err != nil {
			return Manifest{}, err
		}
		if len(manifests) == 0 {
			break
		}
		for _, manifest := range manifests {
			for _, recordID := range manifest.RecordIDs {
				bundle, err := store.GetBundle(ctx, recordID)
				if err != nil {
					if trusterr.CodeOf(err) == trusterr.CodeNotFound {
						return Manifest{}, trusterr.Wrap(
							trusterr.CodeDataLoss,
							fmt.Sprintf("backup manifest %q references missing proof bundle %q", manifest.BatchID, recordID),
							err,
						)
					}
					return Manifest{}, err
				}
				if err := writeCBORTracked(tw, &report, &ordinal, "bundles/"+safeName(recordID)+".tdproof", "proof_bundle", bundle); err != nil {
					return Manifest{}, err
				}
				report.Bundles++
			}
			var afterLeaf uint64
			hasAfterLeaf := false
			for {
				leaves, err := store.ListBatchTreeLeaves(ctx, model.BatchTreeLeafListOptions{
					BatchID: manifest.BatchID, Limit: scanPageSize, AfterLeafIndex: afterLeaf, HasAfter: hasAfterLeaf,
				})
				if err != nil {
					return Manifest{}, err
				}
				if len(leaves) == 0 {
					break
				}
				for _, leaf := range leaves {
					name := fmt.Sprintf("batch-tree/%s/leaves/%020d.tdbleaf", safeName(manifest.BatchID), leaf.LeafIndex)
					if err := writeCBORTracked(tw, &report, &ordinal, name, "batch_tree_leaf", leaf); err != nil {
						return Manifest{}, err
					}
					report.BatchTreeLeaves++
					afterLeaf, hasAfterLeaf = leaf.LeafIndex, true
				}
			}
			for level := uint64(1); level <= uint64(bits.Len64(manifest.TreeSize)); level++ {
				var afterStart uint64
				hasAfterStart := false
				for {
					nodes, err := store.ListBatchTreeNodes(ctx, model.BatchTreeNodeListOptions{
						BatchID: manifest.BatchID, Level: level, Limit: scanPageSize, AfterStartIndex: afterStart, HasAfter: hasAfterStart,
					})
					if err != nil {
						return Manifest{}, err
					}
					if len(nodes) == 0 {
						break
					}
					for _, node := range nodes {
						name := fmt.Sprintf("batch-tree/%s/nodes/%020d_%020d.tdbnode", safeName(manifest.BatchID), node.Level, node.StartIndex)
						if err := writeCBORTracked(tw, &report, &ordinal, name, "batch_tree_node", node); err != nil {
							return Manifest{}, err
						}
						report.BatchTreeNodes++
						afterStart, hasAfterStart = node.StartIndex, true
					}
				}
			}
			if err := writeCBORTracked(tw, &report, &ordinal, "manifests/"+safeName(manifest.BatchID)+".tdmanifest", "batch_manifest", manifest); err != nil {
				return Manifest{}, err
			}
			report.Manifests++
		}
		afterBatchID = manifests[len(manifests)-1].BatchID
	}

	afterRootClosedAt := int64(0)
	afterRootBatchID := ""
	for {
		roots, err := store.ListRootsPage(ctx, model.RootListOptions{
			Limit:              scanPageSize,
			Direction:          model.RecordListDirectionAsc,
			AfterClosedAtUnixN: afterRootClosedAt,
			AfterBatchID:       afterRootBatchID,
		})
		if err != nil {
			return Manifest{}, err
		}
		if len(roots) == 0 {
			break
		}
		for _, root := range roots {
			if err := writeCBORTracked(tw, &report, &ordinal, "roots/"+safeName(root.BatchID)+".tdroot", "batch_root", root); err != nil {
				return Manifest{}, err
			}
			report.Roots++
		}
		lastRoot := roots[len(roots)-1]
		afterRootClosedAt = lastRoot.ClosedAtUnixN
		afterRootBatchID = lastRoot.BatchID
	}

	nextLeafIndex := uint64(0)
	for {
		leaves, err := store.ListGlobalLeavesRange(ctx, nextLeafIndex, scanPageSize)
		if err != nil {
			return Manifest{}, err
		}
		if len(leaves) == 0 {
			break
		}
		for _, leaf := range leaves {
			name := fmt.Sprintf("global/leaves/%020d.tdgleaf", leaf.LeafIndex)
			if err := writeCBORTracked(tw, &report, &ordinal, name, "global_leaf", leaf); err != nil {
				return Manifest{}, err
			}
			report.GlobalLeaves++
			nextLeafIndex = leaf.LeafIndex + 1
		}
	}

	afterNodeLevel, afterNodeStart := ^uint64(0), ^uint64(0)
	for {
		nodes, err := store.ListGlobalLogNodesAfter(ctx, afterNodeLevel, afterNodeStart, scanPageSize)
		if err != nil {
			return Manifest{}, err
		}
		if len(nodes) == 0 {
			break
		}
		for _, node := range nodes {
			name := fmt.Sprintf("global/nodes/%020d_%020d.tdgnode", node.Level, node.StartIndex)
			if err := writeCBORTracked(tw, &report, &ordinal, name, "global_node", node); err != nil {
				return Manifest{}, err
			}
			report.GlobalNodes++
			afterNodeLevel, afterNodeStart = node.Level, node.StartIndex
		}
	}

	state, ok, err := store.GetGlobalLogState(ctx)
	if err != nil {
		return Manifest{}, err
	}
	if ok {
		if err := writeCBORTracked(tw, &report, &ordinal, "global/state.tdgstate", "global_state", state); err != nil {
			return Manifest{}, err
		}
		report.GlobalState = true
	}

	afterSTHTreeSize := uint64(0)
	for {
		sths, err := store.ListSignedTreeHeadsAfter(ctx, afterSTHTreeSize, scanPageSize)
		if err != nil {
			return Manifest{}, err
		}
		if len(sths) == 0 {
			break
		}
		for _, sth := range sths {
			name := fmt.Sprintf("global/sth/%020d.tdsth", sth.TreeSize)
			if err := writeCBORTracked(tw, &report, &ordinal, name, "signed_tree_head", sth); err != nil {
				return Manifest{}, err
			}
			report.STHs++
			afterSTHTreeSize = sth.TreeSize
		}
	}

	afterTileLevel, afterTileStart := ^uint64(0), ^uint64(0)
	for {
		tiles, err := store.ListGlobalLogTilesAfter(ctx, afterTileLevel, afterTileStart, scanPageSize)
		if err != nil {
			return Manifest{}, err
		}
		if len(tiles) == 0 {
			break
		}
		for _, tile := range tiles {
			name := fmt.Sprintf("global/tiles/%020d_%020d_%020d.tdgtile", tile.Level, tile.StartIndex, tile.Width)
			if err := writeCBORTracked(tw, &report, &ordinal, name, "global_tile", tile); err != nil {
				return Manifest{}, err
			}
			report.GlobalTiles++
			afterTileLevel, afterTileStart = tile.Level, tile.StartIndex
		}
	}

	afterGlobalOutboxBatchID := ""
	for {
		items, err := store.ListGlobalLogOutboxItemsAfter(ctx, afterGlobalOutboxBatchID, scanPageSize)
		if err != nil {
			return Manifest{}, err
		}
		if len(items) == 0 {
			break
		}
		for _, item := range items {
			name := "global/outbox/" + safeName(item.BatchID) + ".tdgoutbox"
			if err := writeCBORTracked(tw, &report, &ordinal, name, "global_log_outbox", item); err != nil {
				return Manifest{}, err
			}
			report.GlobalOutboxes++
			afterGlobalOutboxBatchID = item.BatchID
		}
	}

	// Capture mutable scheduler state before immutable results. If a publish
	// completes while the backup is running, this ordering can at worst retain
	// a retryable in-flight target alongside its successful result; it cannot
	// omit both the result and the retry intent.
	schedules, err := scheduleStore.ListSTHAnchorSchedules(ctx)
	if err != nil {
		return Manifest{}, err
	}
	anchorschedule.Sort(schedules)

	afterAnchorResult := model.STHAnchorResultKey{}
	for {
		results, err := resultLister.ListSTHAnchorResultsAfter(ctx, afterAnchorResult, scanPageSize)
		if err != nil {
			return Manifest{}, err
		}
		if len(results) == 0 {
			break
		}
		for _, result := range results {
			resultKey := anchorschedule.ResultKey(result)
			if anchorschedule.CompareResultKeys(resultKey, afterAnchorResult) <= 0 {
				return Manifest{}, trusterr.New(trusterr.CodeDataLoss, "STH anchor result listing did not advance")
			}
			resultName := fmt.Sprintf("anchors/sth-result/%09d.tdsth-anchor-result", report.AnchorResults)
			if err := writeCBORTracked(tw, &report, &ordinal, resultName, "sth_anchor_result", result); err != nil {
				return Manifest{}, err
			}
			report.AnchorResults++
			afterAnchorResult = resultKey
		}
	}

	for i, schedule := range schedules {
		if err := anchorschedule.ValidateSchedule(schedule); err != nil {
			return Manifest{}, trusterr.Wrap(trusterr.CodeDataLoss, "backup invalid STH anchor schedule", err)
		}
		if err := validateBCOSScheduleProviderState(schedule); err != nil {
			return Manifest{}, err
		}
		name := fmt.Sprintf("anchors/schedules/%06d.tdanchor-schedule", i)
		if err := writeCBORTracked(tw, &report, &ordinal, name, "sth_anchor_schedule", schedule); err != nil {
			return Manifest{}, err
		}
		report.AnchorSchedules++
	}

	if strings.TrimSpace(opts.KeyRegistryPath) != "" {
		registryBytes, err := readRecoveryArtifact(opts.KeyRegistryPath, maxRecoveryArtifactBytes)
		if err != nil {
			return Manifest{}, trusterr.Wrap(trusterr.CodeDataLoss, "read key registry audit evidence", err)
		}
		registrySummary, err := keystore.InspectEvidence(registryBytes)
		if err != nil {
			return Manifest{}, trusterr.Wrap(trusterr.CodeDataLoss, "validate key registry audit evidence", err)
		}
		if registrySummary.Manifest.CryptoSuite != suiteID {
			return Manifest{}, trusterr.New(trusterr.CodeFailedPrecondition, "key registry and proofstore cryptographic suites do not match")
		}
		if err := writeBytesTracked(tw, &report, &ordinal, "recovery/key-registry.tdkeys", "key_registry_audit", registryBytes); err != nil {
			return Manifest{}, err
		}
		report.KeyRegistries++
		report.Inventory = backupInventory(envelope.KEKProvider, envelope.KEKKeyID, true)
	}

	if err := writeCBOR(tw, "manifest.tdmanifest", report); err != nil {
		return Manifest{}, err
	}
	if err := closeArchive(); err != nil {
		return Manifest{}, trusterr.Wrap(trusterr.CodeDataLoss, "close backup archive", err)
	}
	if err := f.Sync(); err != nil {
		return Manifest{}, trusterr.Wrap(trusterr.CodeDataLoss, "sync backup file", err)
	}
	if err := f.Close(); err != nil {
		return Manifest{}, trusterr.Wrap(trusterr.CodeDataLoss, "close backup file", err)
	}
	if err := renameReplace(tmpPath, path); err != nil {
		return Manifest{}, trusterr.Wrap(trusterr.CodeDataLoss, "publish backup archive", err)
	}
	cleanup = false
	return report, nil
}

func Verify(ctx context.Context, path string, providers ...keyenvelope.KEKProvider) (Manifest, error) {
	var manifest Manifest
	var foundManifest bool
	observed := make([]Entry, 0)
	seenNames := make(map[string]struct{})
	header, err := readArchiveStream(ctx, path, providers, func(entry archiveEntry) error {
		if foundManifest {
			return trusterr.New(trusterr.CodeDataLoss, "backup manifest must be the final archive entry")
		}
		if entry.Name == "manifest.tdmanifest" {
			foundManifest = true
			return decodeCBORUntrackedEntry(entry, &manifest)
		}
		if _, exists := seenNames[entry.Name]; exists {
			return trusterr.New(trusterr.CodeDataLoss, fmt.Sprintf("duplicate backup entry %q", entry.Name))
		}
		seenNames[entry.Name] = struct{}{}
		if err := validateStreamEntry(entry); err != nil {
			return err
		}
		observed = append(observed, Entry{
			Ordinal: entry.Ordinal, Name: entry.Name, Type: entry.Type, Size: entry.Size,
			CryptoSuite: entry.CryptoSuite, DigestAlgorithm: entry.DigestAlgorithm, Digest: append([]byte(nil), entry.Digest...),
		})
		return nil
	})
	if err != nil {
		return Manifest{}, err
	}
	if !foundManifest {
		return Manifest{}, trusterr.New(trusterr.CodeDataLoss, "backup manifest.tdmanifest is missing")
	}
	if err := validateManifestAgainstHeader(manifest, header); err != nil {
		return Manifest{}, err
	}
	if !reflect.DeepEqual(manifest.Entries, observed) {
		return Manifest{}, trusterr.New(trusterr.CodeDataLoss, "backup manifest entry inventory does not match the authenticated archive")
	}
	if err := validateManifestCounts(manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func Restore(ctx context.Context, store proofstore.Store, path string, providers ...keyenvelope.KEKProvider) (Manifest, error) {
	return RestoreWithOptions(ctx, store, path, RestoreOptions{KEKProviders: providers})
}

func RestoreWithOptions(ctx context.Context, store proofstore.Store, path string, opts RestoreOptions) (Manifest, error) {
	if store == nil {
		return Manifest{}, trusterr.New(trusterr.CodeInvalidArgument, "restore store is required")
	}
	resultWriter, ok := store.(proofstore.STHAnchorResultWriter)
	if !ok {
		return Manifest{}, trusterr.New(trusterr.CodeFailedPrecondition, "restore store cannot write STH anchor results")
	}
	scheduleRestorer, ok := store.(proofstore.STHAnchorScheduleRestorer)
	if !ok {
		return Manifest{}, trusterr.New(trusterr.CodeFailedPrecondition, "restore store cannot restore STH anchor schedules")
	}
	verified, err := Verify(ctx, path, opts.KEKProviders...)
	if err != nil {
		return Manifest{}, err
	}
	destination, err := proofstore.BoundNamespace(store)
	if err != nil {
		return Manifest{}, err
	}
	if destination.CryptoSuite != verified.CryptoSuite || destination.FormatGeneration != verified.FormatGeneration ||
		destination.NodeID != verified.NodeID || destination.LogID != verified.LogID {
		return Manifest{}, trusterr.New(trusterr.CodeFailedPrecondition, "backup and destination proofstore namespace bindings do not match")
	}
	report := Manifest{
		SchemaVersion: SchemaManifest, BackupID: verified.BackupID, CryptoSuite: verified.CryptoSuite,
		FormatGeneration: verified.FormatGeneration, NodeID: verified.NodeID, LogID: verified.LogID,
		NamespaceID: verified.NamespaceID, TargetNamespaceID: destination.NamespaceID,
	}
	checkpointPath := opts.CheckpointPath
	var restoreCP RestoreCheckpoint
	if opts.Resume && checkpointPath == "" {
		checkpointPath = path + ".restore-checkpoint.json"
	}
	if opts.Resume {
		var err error
		restoreCP, err = readRestoreCheckpoint(checkpointPath)
		if err != nil {
			return Manifest{}, trusterr.Wrap(trusterr.CodeDataLoss, "read restore checkpoint", err)
		}
		if restoreCP.BackupID != "" {
			recoveryDir, pathErr := normalizedOptionalPath(opts.RecoveryDir)
			if pathErr != nil {
				return Manifest{}, pathErr
			}
			if restoreCP.SchemaVersion != SchemaRestoreCheckpoint || restoreCP.BackupID != verified.BackupID ||
				restoreCP.CryptoSuite != verified.CryptoSuite || restoreCP.NodeID != verified.NodeID || restoreCP.LogID != verified.LogID ||
				restoreCP.SourceNamespaceID != verified.NamespaceID || restoreCP.TargetNamespaceID != destination.NamespaceID ||
				restoreCP.RecoveryDir != recoveryDir {
				return Manifest{}, trusterr.New(trusterr.CodeFailedPrecondition, "restore checkpoint binding does not match this backup and destination")
			}
		}
	}
	if verified.KeyRegistries > 0 {
		if strings.TrimSpace(opts.RecoveryDir) == "" {
			return Manifest{}, trusterr.New(trusterr.CodeFailedPrecondition, "backup contains key registry audit evidence; recovery directory is required")
		}
		if err := prepareRecoveryDirectory(opts.RecoveryDir, restoreCP.BackupID != ""); err != nil {
			return Manifest{}, err
		}
	}
	emptyDestination, err := restoreDestinationEmpty(ctx, store)
	if err != nil {
		return Manifest{}, err
	}
	if restoreCP.BackupID == "" && !emptyDestination {
		return Manifest{}, trusterr.New(trusterr.CodeFailedPrecondition, "backup restore destination is not empty")
	}
	if restoreCP.BackupID != "" && restoreCP.LastOrdinal > 0 && emptyDestination {
		return Manifest{}, trusterr.New(trusterr.CodeFailedPrecondition, "restore checkpoint cannot resume into an empty destination")
	}
	batchLeaves := make(map[string][]model.BatchTreeLeaf)
	batchNodes := make(map[string][]model.BatchTreeNode)
	restoredHeader, err := readArchiveStream(ctx, path, opts.KEKProviders, func(entry archiveEntry) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.Name != "manifest.tdmanifest" && entry.CryptoSuite != verified.CryptoSuite {
			return trusterr.New(trusterr.CodeDataLoss, fmt.Sprintf("backup entry %q suite changed between verification and restore", entry.Name))
		}
		if opts.Resume && restoreCP.BackupID != "" && entry.BackupID == restoreCP.BackupID && entry.Ordinal <= restoreCP.LastOrdinal {
			_, _ = io.Copy(io.Discard, entry.Reader)
			return nil
		}
		markRestored := func() error {
			if !opts.Resume {
				return nil
			}
			recoveryDir, err := normalizedOptionalPath(opts.RecoveryDir)
			if err != nil {
				return err
			}
			return writeRestoreCheckpoint(checkpointPath, RestoreCheckpoint{
				SchemaVersion: SchemaRestoreCheckpoint, BackupID: verified.BackupID,
				CryptoSuite: verified.CryptoSuite, NodeID: verified.NodeID, LogID: verified.LogID,
				SourceNamespaceID: verified.NamespaceID, TargetNamespaceID: destination.NamespaceID,
				RecoveryDir: recoveryDir,
				LastOrdinal: entry.Ordinal, LastName: entry.Name, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
			})
		}
		switch {
		case entry.Name == "manifest.tdmanifest":
			var archiveManifest Manifest
			if err := decodeCBORUntrackedEntry(entry, &archiveManifest); err != nil {
				return err
			}
			if !reflect.DeepEqual(archiveManifest, verified) {
				return trusterr.New(trusterr.CodeDataLoss, "backup changed between verification and restore")
			}
			return markRestored()
		case strings.HasPrefix(entry.Name, "batch-tree/") && strings.Contains(entry.Name, "/leaves/"):
			var v model.BatchTreeLeaf
			if err := decodeCBOREntry(entry, &v); err != nil {
				return err
			}
			batchLeaves[v.BatchID] = append(batchLeaves[v.BatchID], v)
			report.BatchTreeLeaves++
			return nil
		case strings.HasPrefix(entry.Name, "batch-tree/") && strings.Contains(entry.Name, "/nodes/"):
			var v model.BatchTreeNode
			if err := decodeCBOREntry(entry, &v); err != nil {
				return err
			}
			batchNodes[v.BatchID] = append(batchNodes[v.BatchID], v)
			report.BatchTreeNodes++
			return nil
		case strings.HasPrefix(entry.Name, "manifests/"):
			var v model.BatchManifest
			if err := decodeCBOREntry(entry, &v); err != nil {
				return err
			}
			report.Manifests++
			leaves, hasLeaves := batchLeaves[v.BatchID]
			if hasLeaves {
				if err := store.PutBatchTreeArtifacts(ctx, leaves, batchNodes[v.BatchID]); err != nil {
					return err
				}
				delete(batchLeaves, v.BatchID)
				delete(batchNodes, v.BatchID)
			}
			if err := store.PutManifest(ctx, v); err != nil {
				return err
			}
			return markRestored()
		case strings.HasPrefix(entry.Name, "bundles/"):
			var v model.ProofBundle
			if err := decodeCBOREntry(entry, &v); err != nil {
				return err
			}
			report.Bundles++
			if err := store.PutBundle(ctx, v); err != nil {
				return err
			}
			return markRestored()
		case strings.HasPrefix(entry.Name, "roots/"):
			var v model.BatchRoot
			if err := decodeCBOREntry(entry, &v); err != nil {
				return err
			}
			report.Roots++
			if err := store.PutRoot(ctx, v); err != nil {
				return err
			}
			return markRestored()
		case strings.HasPrefix(entry.Name, "global/leaves/"):
			var v model.GlobalLogLeaf
			if err := decodeCBOREntry(entry, &v); err != nil {
				return err
			}
			report.GlobalLeaves++
			if err := store.PutGlobalLeaf(ctx, v); err != nil {
				return err
			}
			return markRestored()
		case strings.HasPrefix(entry.Name, "global/nodes/"):
			var v model.GlobalLogNode
			if err := decodeCBOREntry(entry, &v); err != nil {
				return err
			}
			report.GlobalNodes++
			if err := store.PutGlobalLogNode(ctx, v); err != nil {
				return err
			}
			return markRestored()
		case entry.Name == "global/state.tdgstate":
			var v model.GlobalLogState
			if err := decodeCBOREntry(entry, &v); err != nil {
				return err
			}
			report.GlobalState = true
			if err := store.PutGlobalLogState(ctx, v); err != nil {
				return err
			}
			return markRestored()
		case strings.HasPrefix(entry.Name, "global/sth/"):
			var v model.SignedTreeHead
			if err := decodeCBOREntry(entry, &v); err != nil {
				return err
			}
			report.STHs++
			if err := store.PutSignedTreeHead(ctx, v); err != nil {
				return err
			}
			return markRestored()
		case strings.HasPrefix(entry.Name, "global/tiles/"):
			var v model.GlobalLogTile
			if err := decodeCBOREntry(entry, &v); err != nil {
				return err
			}
			report.GlobalTiles++
			if err := store.PutGlobalLogTile(ctx, v); err != nil {
				return err
			}
			return markRestored()
		case strings.HasPrefix(entry.Name, "global/outbox/"):
			var v model.GlobalLogOutboxItem
			if err := decodeCBOREntry(entry, &v); err != nil {
				return err
			}
			report.GlobalOutboxes++
			if err := store.EnqueueGlobalLog(ctx, v); err != nil && trusterr.CodeOf(err) != trusterr.CodeAlreadyExists {
				return err
			}
			return markRestored()
		case strings.HasPrefix(entry.Name, "anchors/sth-result/"):
			var v model.STHAnchorResult
			if err := decodeCBOREntry(entry, &v); err != nil {
				return err
			}
			report.AnchorResults++
			if err := resultWriter.PutSTHAnchorResult(ctx, v); err != nil {
				return err
			}
			return markRestored()
		case strings.HasPrefix(entry.Name, "anchors/schedules/"):
			var v model.STHAnchorSchedule
			if err := decodeCBOREntry(entry, &v); err != nil {
				return err
			}
			if err := validateBCOSScheduleProviderState(v); err != nil {
				return err
			}
			v, err := anchorschedule.ClearLeaseForRestore(v)
			if err != nil {
				return trusterr.Wrap(trusterr.CodeDataLoss, "restore invalid STH anchor schedule", err)
			}
			report.AnchorSchedules++
			if err := scheduleRestorer.PutSTHAnchorSchedule(ctx, v); err != nil {
				return err
			}
			return markRestored()
		case entry.Name == "recovery/key-registry.tdkeys":
			data, err := decodeRawTrackedEntry(entry)
			if err != nil {
				return err
			}
			report.KeyRegistries++
			if err := writeFileAtomic(filepath.Join(opts.RecoveryDir, "key-registry.tdkeys"), data); err != nil {
				return trusterr.Wrap(trusterr.CodeDataLoss, "restore key registry audit evidence", err)
			}
			return markRestored()
		default:
			return trusterr.New(trusterr.CodeDataLoss, fmt.Sprintf("unknown backup entry %q", entry.Name))
		}
	})
	if err != nil {
		return Manifest{}, err
	}
	if restoredHeader.BackupID != verified.BackupID || restoredHeader.CryptoSuite != verified.CryptoSuite ||
		restoredHeader.FormatGeneration != verified.FormatGeneration || restoredHeader.NodeID != verified.NodeID ||
		restoredHeader.LogID != verified.LogID || restoredHeader.NamespaceID != verified.NamespaceID {
		return Manifest{}, trusterr.New(trusterr.CodeDataLoss, "backup envelope changed between verification and restore")
	}
	if len(batchLeaves) != 0 || len(batchNodes) != 0 {
		return Manifest{}, trusterr.New(trusterr.CodeDataLoss, "backup contains batch tree artifacts without a matching manifest")
	}
	if manager, ok := store.(proofstore.IdempotencyProjectionManager); ok {
		if err := manager.EnsureIdempotencyProjection(ctx); err != nil {
			return Manifest{}, trusterr.Wrap(trusterr.CodeDataLoss, "rebuild restored idempotency projection", err)
		}
	}
	return report, nil
}

func writeCBOR(tw *tar.Writer, name string, v any) error {
	data, err := cborx.Marshal(v)
	if err != nil {
		return err
	}
	return writeBytes(tw, name, data)
}

func writeCBORTracked(tw *tar.Writer, manifest *Manifest, ordinal *int64, name, typ string, v any) error {
	data, err := cborx.Marshal(v)
	if err != nil {
		return err
	}
	return writeBytesTracked(tw, manifest, ordinal, name, typ, data)
}

func writeBytes(tw *tar.Writer, name string, data []byte) error {
	header := &tar.Header{
		Name:    name,
		Mode:    0o600,
		Size:    int64(len(data)),
		ModTime: time.Unix(0, 0).UTC(),
	}
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

func writeBytesTracked(tw *tar.Writer, manifest *Manifest, ordinal *int64, name, typ string, data []byte) error {
	*ordinal = *ordinal + 1
	digest, err := digestBytes(manifest.CryptoSuite, manifest.DigestAlgorithm, data)
	if err != nil {
		return err
	}
	entry := Entry{
		Ordinal: *ordinal, Name: name, Type: typ, Size: int64(len(data)),
		CryptoSuite: manifest.CryptoSuite, DigestAlgorithm: manifest.DigestAlgorithm, Digest: digest,
	}
	header := &tar.Header{
		Name:    name,
		Mode:    0o600,
		Size:    int64(len(data)),
		ModTime: time.Unix(0, 0).UTC(),
		PAXRecords: map[string]string{
			paxBackupID:  manifest.BackupID,
			paxOrdinal:   strconv.FormatInt(entry.Ordinal, 10),
			paxDigest:    base64.RawURLEncoding.EncodeToString(entry.Digest),
			paxDigestAlg: entry.DigestAlgorithm,
			paxType:      typ,
			paxSuite:     string(manifest.CryptoSuite),
		},
	}
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	if _, err := tw.Write(data); err != nil {
		return err
	}
	manifest.Entries = append(manifest.Entries, entry)
	return nil
}

type archiveEntry struct {
	Name            string
	Size            int64
	Ordinal         int64
	BackupID        string
	DigestAlgorithm string
	Digest          []byte
	Type            string
	CryptoSuite     cryptosuite.ID
	Reader          io.Reader
}

func readArchiveStream(ctx context.Context, path string, providers []keyenvelope.KEKProvider, visit func(archiveEntry) error) (EnvelopeHeader, error) {
	archive, err := openEncryptedArchive(ctx, path, providers)
	if err != nil {
		return EnvelopeHeader{}, err
	}
	defer archive.Close()
	var in io.Reader = archive.frames
	var gz *gzip.Reader
	if archive.header.Compression == "gzip" {
		gz, err = gzip.NewReader(archive.frames)
		if err != nil {
			return EnvelopeHeader{}, trusterr.Wrap(trusterr.CodeDataLoss, "open encrypted backup gzip stream", err)
		}
		defer gz.Close()
		in = gz
	}
	in = &contextReader{ctx: ctx, reader: in}
	tr := tar.NewReader(in)
	var seq int64
	for {
		header, err := tr.Next()
		if err == io.EOF {
			if _, err := io.Copy(io.Discard, in); err != nil {
				return EnvelopeHeader{}, trusterr.Wrap(trusterr.CodeDataLoss, "authenticate encrypted backup trailer", err)
			}
			return archive.header, nil
		}
		if err != nil {
			return EnvelopeHeader{}, trusterr.Wrap(trusterr.CodeDataLoss, "read backup archive", err)
		}
		if header.Typeflag != tar.TypeReg {
			return EnvelopeHeader{}, trusterr.New(trusterr.CodeDataLoss, fmt.Sprintf("backup entry %q is not a regular file", header.Name))
		}
		if !validArchivePath(header.Name) {
			return EnvelopeHeader{}, trusterr.New(trusterr.CodeDataLoss, fmt.Sprintf("backup entry path %q is invalid", header.Name))
		}
		seq++
		if header.Name == "manifest.tdmanifest" {
			if len(header.PAXRecords) != 0 {
				return EnvelopeHeader{}, trusterr.New(trusterr.CodeDataLoss, "backup manifest has unexpected PAX control metadata")
			}
			if err := visit(archiveEntry{Name: header.Name, Size: header.Size, Ordinal: seq, Reader: tr}); err != nil {
				return EnvelopeHeader{}, err
			}
			continue
		}
		if err := validatePAXControlRecords(header); err != nil {
			return EnvelopeHeader{}, err
		}
		ordinal, err := strconv.ParseInt(header.PAXRecords[paxOrdinal], 10, 64)
		if err != nil || ordinal != seq {
			return EnvelopeHeader{}, trusterr.New(trusterr.CodeDataLoss, fmt.Sprintf("backup entry %q ordinal is invalid", header.Name))
		}
		digest, err := base64.RawURLEncoding.DecodeString(header.PAXRecords[paxDigest])
		if err != nil || len(digest) != cryptosuite.DigestSize {
			return EnvelopeHeader{}, trusterr.New(trusterr.CodeDataLoss, fmt.Sprintf("backup entry %q digest is invalid", header.Name))
		}
		entry := archiveEntry{
			Name: header.Name, Size: header.Size, Ordinal: ordinal,
			BackupID: header.PAXRecords[paxBackupID], DigestAlgorithm: header.PAXRecords[paxDigestAlg], Digest: digest,
			Type: header.PAXRecords[paxType], CryptoSuite: cryptosuite.ID(header.PAXRecords[paxSuite]), Reader: tr,
		}
		if entry.BackupID != archive.header.BackupID || entry.CryptoSuite != archive.header.CryptoSuite || entry.Type == "" {
			return EnvelopeHeader{}, trusterr.New(trusterr.CodeDataLoss, fmt.Sprintf("backup entry %q control metadata does not match the envelope", header.Name))
		}
		suite, _ := cryptosuite.RequireKnown(archive.header.CryptoSuite)
		if entry.DigestAlgorithm != suite.StorageIntegrityHash.Algorithm {
			return EnvelopeHeader{}, trusterr.New(trusterr.CodeDataLoss, fmt.Sprintf("backup entry %q digest algorithm does not match the suite", header.Name))
		}
		if err := visit(entry); err != nil {
			return EnvelopeHeader{}, err
		}
	}
}

func validatePAXControlRecords(header *tar.Header) error {
	allowed := map[string]struct{}{
		paxBackupID: {}, paxOrdinal: {}, paxDigest: {}, paxDigestAlg: {}, paxType: {}, paxSuite: {},
		"path": {},
	}
	for name := range header.PAXRecords {
		if _, ok := allowed[name]; !ok {
			return trusterr.New(trusterr.CodeDataLoss, fmt.Sprintf("backup entry %q has unknown PAX control field %q", header.Name, name))
		}
	}
	if path, ok := header.PAXRecords["path"]; ok && path != header.Name {
		return trusterr.New(trusterr.CodeDataLoss, fmt.Sprintf("backup entry %q has mismatched PAX path", header.Name))
	}
	for _, required := range []string{paxBackupID, paxOrdinal, paxDigest, paxDigestAlg, paxType, paxSuite} {
		if header.PAXRecords[required] == "" {
			return trusterr.New(trusterr.CodeDataLoss, fmt.Sprintf("backup entry %q is missing PAX control field %q", header.Name, required))
		}
	}
	return nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func decodeCBOREntry(entry archiveEntry, v any) error {
	return decodeEntry(entry, v, true)
}

func decodeCBORUntrackedEntry(entry archiveEntry, v any) error {
	return decodeEntry(entry, v, false)
}

func decodeRawTrackedEntry(entry archiveEntry) ([]byte, error) {
	if entry.Size < 0 || entry.Size > maxRecoveryArtifactBytes {
		return nil, trusterr.New(trusterr.CodeDataLoss, fmt.Sprintf("backup recovery entry %s too large: %d", entry.Name, entry.Size))
	}
	data := make([]byte, int(entry.Size))
	if _, err := io.ReadFull(entry.Reader, data); err != nil {
		return nil, trusterr.Wrap(trusterr.CodeDataLoss, fmt.Sprintf("read backup entry %s", entry.Name), err)
	}
	got, err := digestBytes(entry.CryptoSuite, entry.DigestAlgorithm, data)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(got, entry.Digest) {
		return nil, trusterr.New(trusterr.CodeDataLoss, fmt.Sprintf("backup entry %s digest mismatch", entry.Name))
	}
	return data, nil
}

func decodeEntry(entry archiveEntry, value any, tracked bool) error {
	if entry.Size < 0 || entry.Size > maxRestoreEntryBytes {
		return trusterr.New(trusterr.CodeDataLoss, fmt.Sprintf("backup entry %s too large: %d", entry.Name, entry.Size))
	}
	data := make([]byte, int(entry.Size))
	if _, err := io.ReadFull(entry.Reader, data); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, fmt.Sprintf("read backup entry %s", entry.Name), err)
	}
	if tracked {
		got, err := digestBytes(entry.CryptoSuite, entry.DigestAlgorithm, data)
		if err != nil {
			return err
		}
		if !bytes.Equal(got, entry.Digest) {
			return trusterr.New(trusterr.CodeDataLoss, fmt.Sprintf("backup entry %s digest mismatch", entry.Name))
		}
	}
	if err := cborx.UnmarshalLimit(data, value, int(maxRestoreEntryBytes)); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, fmt.Sprintf("decode backup entry %s", entry.Name), err)
	}
	canonical, err := cborx.Marshal(value)
	if err != nil || !bytes.Equal(canonical, data) {
		return trusterr.New(trusterr.CodeDataLoss, fmt.Sprintf("backup entry %s is not deterministic CBOR", entry.Name))
	}
	return nil
}

func validateStreamEntry(entry archiveEntry) error {
	switch {
	case strings.HasPrefix(entry.Name, "manifests/"):
		if err := requireEntryType(entry, "batch_manifest"); err != nil {
			return err
		}
		var v model.BatchManifest
		return decodeCBOREntry(entry, &v)
	case strings.HasPrefix(entry.Name, "bundles/"):
		if err := requireEntryType(entry, "proof_bundle"); err != nil {
			return err
		}
		var v model.ProofBundle
		return decodeCBOREntry(entry, &v)
	case strings.HasPrefix(entry.Name, "batch-tree/") && strings.Contains(entry.Name, "/leaves/"):
		if err := requireEntryType(entry, "batch_tree_leaf"); err != nil {
			return err
		}
		var v model.BatchTreeLeaf
		return decodeCBOREntry(entry, &v)
	case strings.HasPrefix(entry.Name, "batch-tree/") && strings.Contains(entry.Name, "/nodes/"):
		if err := requireEntryType(entry, "batch_tree_node"); err != nil {
			return err
		}
		var v model.BatchTreeNode
		return decodeCBOREntry(entry, &v)
	case strings.HasPrefix(entry.Name, "roots/"):
		if err := requireEntryType(entry, "batch_root"); err != nil {
			return err
		}
		var v model.BatchRoot
		return decodeCBOREntry(entry, &v)
	case strings.HasPrefix(entry.Name, "global/leaves/"):
		if err := requireEntryType(entry, "global_leaf"); err != nil {
			return err
		}
		var v model.GlobalLogLeaf
		return decodeCBOREntry(entry, &v)
	case strings.HasPrefix(entry.Name, "global/nodes/"):
		if err := requireEntryType(entry, "global_node"); err != nil {
			return err
		}
		var v model.GlobalLogNode
		return decodeCBOREntry(entry, &v)
	case entry.Name == "global/state.tdgstate":
		if err := requireEntryType(entry, "global_state"); err != nil {
			return err
		}
		var v model.GlobalLogState
		return decodeCBOREntry(entry, &v)
	case strings.HasPrefix(entry.Name, "global/sth/"):
		if err := requireEntryType(entry, "signed_tree_head"); err != nil {
			return err
		}
		var v model.SignedTreeHead
		return decodeCBOREntry(entry, &v)
	case strings.HasPrefix(entry.Name, "global/tiles/"):
		if err := requireEntryType(entry, "global_tile"); err != nil {
			return err
		}
		var v model.GlobalLogTile
		return decodeCBOREntry(entry, &v)
	case strings.HasPrefix(entry.Name, "global/outbox/"):
		if err := requireEntryType(entry, "global_log_outbox"); err != nil {
			return err
		}
		var v model.GlobalLogOutboxItem
		return decodeCBOREntry(entry, &v)
	case strings.HasPrefix(entry.Name, "anchors/sth-result/"):
		if err := requireEntryType(entry, "sth_anchor_result"); err != nil {
			return err
		}
		var v model.STHAnchorResult
		if err := decodeCBOREntry(entry, &v); err != nil {
			return err
		}
		key := model.STHAnchorScheduleKey{NodeID: v.NodeID, LogID: v.LogID, SinkName: v.SinkName}
		if err := anchorschedule.ValidateResult(key, v); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "invalid STH anchor result", err)
		}
		if v.SinkName == fiscobcos.SinkName {
			if len(v.Proof) > fiscobcos.MaxProofBytes {
				return trusterr.New(trusterr.CodeDataLoss, "FISCO BCOS proof exceeds nested size limit")
			}
			if err := fiscobcos.ValidateProofContainer(v.STH, v); err != nil {
				return trusterr.Wrap(trusterr.CodeDataLoss, "invalid nested FISCO BCOS proof", err)
			}
		}
		return nil
	case strings.HasPrefix(entry.Name, "anchors/schedules/"):
		if err := requireEntryType(entry, "sth_anchor_schedule"); err != nil {
			return err
		}
		var v model.STHAnchorSchedule
		if err := decodeCBOREntry(entry, &v); err != nil {
			return err
		}
		if err := anchorschedule.ValidateSchedule(v); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "invalid STH anchor schedule", err)
		}
		return validateBCOSScheduleProviderState(v)
	case entry.Name == "recovery/key-registry.tdkeys":
		if err := requireEntryType(entry, "key_registry_audit"); err != nil {
			return err
		}
		data, err := decodeRawTrackedEntry(entry)
		if err != nil {
			return err
		}
		summary, err := keystore.InspectEvidence(data)
		if err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "validate backup key registry audit evidence", err)
		}
		if summary.Manifest.CryptoSuite != entry.CryptoSuite {
			return trusterr.New(trusterr.CodeDataLoss, "backup key registry audit suite does not match the archive")
		}
		return nil
	default:
		return trusterr.New(trusterr.CodeDataLoss, fmt.Sprintf("unknown backup entry %q", entry.Name))
	}
}

func requireEntryType(entry archiveEntry, expected string) error {
	if entry.Type != expected {
		return trusterr.New(trusterr.CodeDataLoss, fmt.Sprintf("backup entry %q type=%q want=%q", entry.Name, entry.Type, expected))
	}
	return nil
}

func digestBytes(suiteID cryptosuite.ID, algorithm string, data []byte) ([]byte, error) {
	factory, err := trustcrypto.HashFactoryForSuite(suiteID, algorithm)
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeFailedPrecondition, "backup digest algorithm", err)
	}
	return factory.Sum(data), nil
}

func validateBCOSScheduleProviderState(schedule model.STHAnchorSchedule) error {
	if schedule.Key.SinkName != fiscobcos.SinkName ||
		schedule.InFlight == nil ||
		len(schedule.InFlight.ProviderState) == 0 {
		return nil
	}
	if len(schedule.InFlight.ProviderState) > fiscobcos.MaxAttemptJournalBytes {
		return trusterr.New(trusterr.CodeDataLoss, "FISCO BCOS attempt journal exceeds nested size limit")
	}
	journal, err := fiscobcos.UnmarshalAttemptJournal(schedule.InFlight.ProviderState)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "invalid nested FISCO BCOS attempt journal", err)
	}
	if journal.Generation != schedule.InFlight.Generation ||
		journal.NodeID != schedule.Key.NodeID || journal.LogID != schedule.Key.LogID ||
		journal.SinkName != schedule.Key.SinkName ||
		journal.TreeSize != schedule.InFlight.Target.TreeSize ||
		!bytes.Equal(journal.RootHash, schedule.InFlight.Target.RootHash) {
		return trusterr.New(trusterr.CodeDataLoss, "FISCO BCOS attempt journal does not bind restored schedule")
	}
	payload, err := fiscobcos.UnmarshalPayload(journal.CanonicalPayload)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "decode FISCO BCOS attempt journal payload", err)
	}
	if err := fiscobcos.ValidatePayloadAgainstSTH(payload, schedule.InFlight.Target); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "FISCO BCOS attempt journal payload does not bind complete Signed STH", err)
	}
	return nil
}

func readRestoreCheckpoint(path string) (RestoreCheckpoint, error) {
	if path == "" {
		return RestoreCheckpoint{}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return RestoreCheckpoint{}, nil
		}
		return RestoreCheckpoint{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxRestoreCheckpointBytes+1))
	if err != nil {
		return RestoreCheckpoint{}, err
	}
	if int64(len(data)) > maxRestoreCheckpointBytes {
		return RestoreCheckpoint{}, fmt.Errorf("backup restore checkpoint too large: %d bytes", len(data))
	}
	var cp RestoreCheckpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return RestoreCheckpoint{}, err
	}
	if cp.SchemaVersion != SchemaRestoreCheckpoint || cp.BackupID == "" || cp.CryptoSuite == "" ||
		cp.NodeID == "" || cp.LogID == "" || cp.SourceNamespaceID == "" || cp.TargetNamespaceID == "" ||
		cp.LastOrdinal <= 0 || cp.LastName == "" || cp.UpdatedAt == "" {
		return RestoreCheckpoint{}, fmt.Errorf("invalid restore checkpoint schema or binding")
	}
	return cp, nil
}

func writeRestoreCheckpoint(path string, cp RestoreCheckpoint) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeFileAtomic(path, data)
}

func readRecoveryArtifact(path string, maxBytes int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > maxBytes {
		return nil, fmt.Errorf("recovery artifact must be a regular file of 1..%d bytes", maxBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, fmt.Errorf("recovery artifact changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes || int64(len(data)) != after.Size() {
		return nil, fmt.Errorf("recovery artifact size changed while reading")
	}
	return data, nil
}

func normalizedOptionalPath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", trusterr.Wrap(trusterr.CodeInvalidArgument, "normalize recovery directory", err)
	}
	return filepath.Clean(abs), nil
}

func prepareRecoveryDirectory(path string, resume bool) error {
	normalized, err := normalizedOptionalPath(path)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(normalized)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return trusterr.Wrap(trusterr.CodeInvalidArgument, "inspect recovery directory", err)
	}
	if !resume && len(entries) != 0 {
		return trusterr.New(trusterr.CodeFailedPrecondition, "backup recovery directory is not empty")
	}
	if resume {
		for _, entry := range entries {
			if entry.Name() != "key-registry.tdkeys" || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
				return trusterr.New(trusterr.CodeFailedPrecondition, "backup recovery directory contains unexpected state")
			}
		}
	}
	return nil
}

func safeName(value string) string {
	if isPlainArchiveName(value) {
		return value
	}
	return encodedArchiveNamePrefix + base64.RawURLEncoding.EncodeToString([]byte(value))
}

func isPlainArchiveName(value string) bool {
	if value == "" || value == "." || value == ".." || strings.HasPrefix(value, ".") {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := renameReplace(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func renameReplace(src, dst string) error {
	if err := rejectDirectoryTarget(dst); err != nil {
		return err
	}
	if err := os.Rename(src, dst); err != nil {
		if os.IsExist(err) {
			if removeErr := os.Remove(dst); removeErr == nil {
				return os.Rename(src, dst)
			}
		}
		return err
	}
	return nil
}

func rejectDirectoryTarget(path string) error {
	info, err := os.Stat(path)
	if err == nil {
		if info.IsDir() {
			return fmt.Errorf("%s is a directory", path)
		}
		return nil
	}
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func normaliseCompression(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "gzip", "gz":
		return "gzip", nil
	case "none", "tar":
		return "none", nil
	default:
		return "", trusterr.New(trusterr.CodeInvalidArgument, "backup compression must be gzip or none")
	}
}

func validArchivePath(name string) bool {
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func validateManifestAgainstHeader(manifest Manifest, header EnvelopeHeader) error {
	if manifest.SchemaVersion != SchemaManifest {
		return trusterr.New(trusterr.CodeFailedPrecondition, fmt.Sprintf("unsupported backup schema %q", manifest.SchemaVersion))
	}
	if manifest.TargetNamespaceID != "" {
		return trusterr.New(trusterr.CodeDataLoss, "backup manifest must not declare a restore target namespace")
	}
	if manifest.BackupID != header.BackupID || manifest.CreatedAt != header.CreatedAt ||
		manifest.Compression != header.Compression || manifest.CryptoSuite != header.CryptoSuite ||
		manifest.FormatGeneration != header.FormatGeneration || manifest.NodeID != header.NodeID ||
		manifest.LogID != header.LogID || manifest.NamespaceID != header.NamespaceID ||
		manifest.Encryption != header.ContentAlgorithm || manifest.KEKProvider != header.KEKProvider ||
		manifest.KEKKeyID != header.KEKKeyID {
		return trusterr.New(trusterr.CodeDataLoss, "backup manifest identity does not match its authenticated envelope")
	}
	if _, err := time.Parse(time.RFC3339Nano, manifest.CreatedAt); err != nil {
		return trusterr.New(trusterr.CodeDataLoss, "backup creation time is invalid")
	}
	marker := proofstoremeta.Marker{
		SchemaVersion: proofstoremeta.MarkerSchema, StorageSchema: proofstoremeta.StorageSchemaV5,
		FormatGeneration: manifest.FormatGeneration, CryptoSuite: manifest.CryptoSuite,
		NodeID: manifest.NodeID, LogID: manifest.LogID, NamespaceID: manifest.NamespaceID,
	}
	if err := proofstoremeta.ValidateBinding(marker, manifest.CryptoSuite, manifest.NodeID, manifest.LogID, manifest.NamespaceID); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "backup manifest namespace binding", err)
	}
	suite, err := cryptosuite.RequireKnown(manifest.CryptoSuite)
	if err != nil || manifest.DigestAlgorithm != suite.StorageIntegrityHash.Algorithm {
		return trusterr.New(trusterr.CodeDataLoss, "backup manifest digest algorithm does not match the cryptographic suite")
	}
	for i, entry := range manifest.Entries {
		if entry.Ordinal != int64(i+1) || entry.CryptoSuite != manifest.CryptoSuite ||
			entry.DigestAlgorithm != manifest.DigestAlgorithm || len(entry.Digest) != cryptosuite.DigestSize ||
			entry.Size < 0 || entry.Size > maxRestoreEntryBytes || !validArchivePath(entry.Name) || entry.Type == "" {
			return trusterr.New(trusterr.CodeDataLoss, fmt.Sprintf("backup manifest entry %d is invalid", i+1))
		}
	}
	if manifest.KeyRegistries < 0 || manifest.KeyRegistries > 1 {
		return trusterr.New(trusterr.CodeDataLoss, "backup recovery inventory is incomplete")
	}
	expectedInventory := backupInventory(manifest.KEKProvider, manifest.KEKKeyID, manifest.KeyRegistries == 1)
	if !reflect.DeepEqual(manifest.Inventory, expectedInventory) {
		return trusterr.New(trusterr.CodeDataLoss, "backup recovery inventory is incomplete")
	}
	return nil
}

func backupInventory(kekProvider, kekKeyID string, includesKeyRegistry bool) Inventory {
	publicEvidence := []string{
		"proof-bundles", "batch-roots", "signed-tree-heads", "anchor-results", "anchor-scheduler-state",
	}
	if includesKeyRegistry {
		publicEvidence = append(publicEvidence, "key-registry-audit")
	}
	return Inventory{
		SecretReferences: []string{
			"backup-kek:" + kekProvider + ":" + kekKeyID,
			"signer-private-material:external-not-exported",
			"verifier-trust-roots:external-not-exported",
		},
		PublicEvidence: publicEvidence,
		DerivedIndexes: []string{
			"record-indexes", "latest-anchor-reference",
		},
		RebuildableCheckpoints: []string{
			"idempotency-projection", "l5-coverage-checkpoint",
		},
	}
}

func validateManifestCounts(manifest Manifest) error {
	counts := make(map[string]int)
	for _, entry := range manifest.Entries {
		counts[entry.Type]++
	}
	want := map[string]int{
		"batch_manifest": manifest.Manifests, "proof_bundle": manifest.Bundles,
		"batch_tree_leaf": manifest.BatchTreeLeaves, "batch_tree_node": manifest.BatchTreeNodes,
		"batch_root": manifest.Roots, "global_leaf": manifest.GlobalLeaves,
		"global_node": manifest.GlobalNodes, "signed_tree_head": manifest.STHs,
		"global_tile": manifest.GlobalTiles, "global_log_outbox": manifest.GlobalOutboxes,
		"sth_anchor_result": manifest.AnchorResults, "sth_anchor_schedule": manifest.AnchorSchedules,
		"key_registry_audit": manifest.KeyRegistries,
	}
	for typ, expected := range want {
		if counts[typ] != expected {
			return trusterr.New(trusterr.CodeDataLoss, fmt.Sprintf("backup manifest count for %s=%d want=%d", typ, counts[typ], expected))
		}
		delete(counts, typ)
	}
	stateCount := counts["global_state"]
	delete(counts, "global_state")
	if stateCount > 1 || manifest.GlobalState != (stateCount == 1) {
		return trusterr.New(trusterr.CodeDataLoss, "backup manifest global_state count is invalid")
	}
	if len(counts) != 0 {
		return trusterr.New(trusterr.CodeDataLoss, "backup manifest contains an unknown entry type")
	}
	return nil
}

func restoreDestinationEmpty(ctx context.Context, store proofstore.Store) (bool, error) {
	if values, err := store.ListManifestsAfter(ctx, "", 1); err != nil {
		return false, err
	} else if len(values) != 0 {
		return false, nil
	}
	if values, err := store.ListRecordIndexes(ctx, model.RecordListOptions{Limit: 1, Direction: model.RecordListDirectionAsc}); err != nil {
		return false, err
	} else if len(values) != 0 {
		return false, nil
	}
	if values, err := store.ListRootsPage(ctx, model.RootListOptions{Limit: 1, Direction: model.RecordListDirectionAsc}); err != nil {
		return false, err
	} else if len(values) != 0 {
		return false, nil
	}
	if values, err := store.ListGlobalLeavesRange(ctx, 0, 1); err != nil {
		return false, err
	} else if len(values) != 0 {
		return false, nil
	}
	if _, found, err := store.GetGlobalLogState(ctx); err != nil {
		return false, err
	} else if found {
		return false, nil
	}
	if values, err := store.ListSignedTreeHeadsAfter(ctx, 0, 1); err != nil {
		return false, err
	} else if len(values) != 0 {
		return false, nil
	}
	if values, err := store.ListGlobalLogNodesAfter(ctx, ^uint64(0), ^uint64(0), 1); err != nil {
		return false, err
	} else if len(values) != 0 {
		return false, nil
	}
	if values, err := store.ListGlobalLogTilesAfter(ctx, ^uint64(0), ^uint64(0), 1); err != nil {
		return false, err
	} else if len(values) != 0 {
		return false, nil
	}
	if values, err := store.ListGlobalLogOutboxItemsAfter(ctx, "", 1); err != nil {
		return false, err
	} else if len(values) != 0 {
		return false, nil
	}
	if lister, ok := store.(proofstore.STHAnchorResultLister); ok {
		if values, err := lister.ListSTHAnchorResultsAfter(ctx, model.STHAnchorResultKey{}, 1); err != nil {
			return false, err
		} else if len(values) != 0 {
			return false, nil
		}
	}
	if scheduler, ok := store.(proofstore.STHAnchorScheduleStore); ok {
		if values, err := scheduler.ListSTHAnchorSchedules(ctx); err != nil {
			return false, err
		} else if len(values) != 0 {
			return false, nil
		}
	}
	return true, nil
}
