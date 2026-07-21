// Package backup implements TrustDB's portable proofstore backup format.
// A .tdbackup archive is logical rather than backend-specific: it stores
// deterministic CBOR objects in a tar stream so file and Pebble stores can
// restore each other's data without copying implementation directories.
package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ryan-wong-coder/trustdb/internal/cborx"
	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/proofstore"
	"github.com/ryan-wong-coder/trustdb/internal/trusterr"
)

const SchemaManifest = "trustdb.backup.v2"
const SchemaRestoreCheckpoint = "trustdb.backup-restore-checkpoint.v1"
const scanPageSize = 1024
const maxRestoreEntryBytes int64 = 128 << 20
const maxRestoreCheckpointBytes int64 = 1 << 20

const (
	paxBackupID = "trustdb.backup_id"
	paxOrdinal  = "trustdb.ordinal"
	paxSHA256   = "trustdb.sha256"
	paxType     = "trustdb.type"

	encodedArchiveNamePrefix = "~"
)

type Entry struct {
	Ordinal int64  `json:"ordinal"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
}

type Manifest struct {
	SchemaVersion string `json:"schema_version"`
	BackupID      string `json:"backup_id"`
	CreatedAt     string `json:"created_at"`
	Compression   string `json:"compression"`

	Manifests      int     `json:"manifests"`
	Bundles        int     `json:"bundles"`
	Roots          int     `json:"roots"`
	GlobalLeaves   int     `json:"global_leaves"`
	GlobalNodes    int     `json:"global_nodes"`
	GlobalState    bool    `json:"global_state"`
	STHs           int     `json:"sths"`
	GlobalTiles    int     `json:"global_tiles"`
	GlobalOutboxes int     `json:"global_outboxes"`
	AnchorOutboxes int     `json:"anchor_outboxes"`
	AnchorResults  int     `json:"anchor_results"`
	Entries        []Entry `json:"entries,omitempty"`
}

type Options struct {
	Compression string
	Clock       func() time.Time
}

type RestoreOptions struct {
	Resume         bool
	CheckpointPath string
}

type RestoreCheckpoint struct {
	SchemaVersion string `json:"schema_version"`
	BackupID      string `json:"backup_id"`
	LastOrdinal   int64  `json:"last_ordinal"`
	LastName      string `json:"last_name"`
	UpdatedAt     string `json:"updated_at"`
}

func Create(ctx context.Context, store proofstore.Store, path string, opts Options) (Manifest, error) {
	if store == nil {
		return Manifest{}, trusterr.New(trusterr.CodeInvalidArgument, "backup store is required")
	}
	if path == "" {
		return Manifest{}, trusterr.New(trusterr.CodeInvalidArgument, "backup output path is required")
	}
	compression := normaliseCompression(opts.Compression)
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

	var out io.Writer = f
	var gz *gzip.Writer
	if compression == "gzip" {
		gz = gzip.NewWriter(f)
		out = gz
	}
	tw := tar.NewWriter(out)
	closeArchive := func() error {
		if err := tw.Close(); err != nil {
			return err
		}
		if gz != nil {
			return gz.Close()
		}
		return nil
	}

	report := Manifest{
		SchemaVersion: SchemaManifest,
		BackupID:      fmt.Sprintf("tdb-%d", clock().UTC().UnixNano()),
		CreatedAt:     clock().UTC().Format(time.RFC3339Nano),
		Compression:   compression,
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
						continue
					}
					return Manifest{}, err
				}
				if err := writeCBORTracked(tw, &report, &ordinal, "bundles/"+safeName(recordID)+".tdproof", "proof_bundle", bundle); err != nil {
					return Manifest{}, err
				}
				report.Bundles++
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

	afterAnchorTreeSize := uint64(0)
	for {
		items, err := store.ListSTHAnchorOutboxItemsAfter(ctx, afterAnchorTreeSize, scanPageSize)
		if err != nil {
			return Manifest{}, err
		}
		if len(items) == 0 {
			break
		}
		for _, item := range items {
			name := fmt.Sprintf("anchors/sth-outbox/%020d.tdsth-anchor", item.TreeSize)
			if err := writeCBORTracked(tw, &report, &ordinal, name, "sth_anchor_outbox", item); err != nil {
				return Manifest{}, err
			}
			report.AnchorOutboxes++
			afterAnchorTreeSize = item.TreeSize

			result, ok, err := store.GetSTHAnchorResult(ctx, item.TreeSize)
			if err != nil {
				return Manifest{}, err
			}
			if !ok {
				continue
			}
			resultName := fmt.Sprintf("anchors/sth-result/%020d.tdsth-anchor-result", result.TreeSize)
			if err := writeCBORTracked(tw, &report, &ordinal, resultName, "sth_anchor_result", result); err != nil {
				return Manifest{}, err
			}
			report.AnchorResults++
		}
	}

	if err := writeJSONTracked(tw, &report, &ordinal, "manifest.json", "manifest", report); err != nil {
		return Manifest{}, err
	}
	if err := writeJSONTracked(tw, &report, &ordinal, "summary.json", "summary", report); err != nil {
		return Manifest{}, err
	}
	if err := closeArchive(); err != nil {
		return Manifest{}, trusterr.Wrap(trusterr.CodeDataLoss, "close backup archive", err)
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

func Verify(ctx context.Context, path string) (Manifest, error) {
	manifest := Manifest{}
	err := readArchiveStream(path, func(entry archiveEntry) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.Name == "summary.json" {
			return decodeJSONEntry(entry, &manifest)
		}
		if entry.Name == "manifest.json" {
			var start Manifest
			return decodeJSONEntry(entry, &start)
		}
		return validateStreamEntry(entry)
	})
	if err != nil {
		return Manifest{}, err
	}
	if manifest.SchemaVersion == "" {
		return Manifest{}, trusterr.New(trusterr.CodeDataLoss, "backup summary.json is missing")
	}
	return manifest, nil
}

func Restore(ctx context.Context, store proofstore.Store, path string) (Manifest, error) {
	return RestoreWithOptions(ctx, store, path, RestoreOptions{})
}

func RestoreWithOptions(ctx context.Context, store proofstore.Store, path string, opts RestoreOptions) (Manifest, error) {
	if store == nil {
		return Manifest{}, trusterr.New(trusterr.CodeInvalidArgument, "restore store is required")
	}
	report := Manifest{SchemaVersion: SchemaManifest}
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
	}
	err := readArchiveStream(path, func(entry archiveEntry) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if opts.Resume && restoreCP.BackupID != "" && entry.BackupID == restoreCP.BackupID && entry.Ordinal <= restoreCP.LastOrdinal {
			_, _ = io.Copy(io.Discard, entry.Reader)
			return nil
		}
		markRestored := func() error {
			if !opts.Resume {
				return nil
			}
			return writeRestoreCheckpoint(checkpointPath, RestoreCheckpoint{
				SchemaVersion: SchemaRestoreCheckpoint,
				BackupID:      entry.BackupID,
				LastOrdinal:   entry.Ordinal,
				LastName:      entry.Name,
				UpdatedAt:     time.Now().UTC().Format(time.RFC3339Nano),
			})
		}
		switch {
		case entry.Name == "manifest.json" || entry.Name == "summary.json":
			if entry.Name == "summary.json" {
				var summary Manifest
				if err := decodeJSONEntry(entry, &summary); err != nil {
					return err
				}
			} else {
				var start Manifest
				if err := decodeJSONEntry(entry, &start); err != nil {
					return err
				}
			}
			return markRestored()
		case strings.HasPrefix(entry.Name, "manifests/"):
			var v model.BatchManifest
			if err := decodeCBOREntry(entry, &v); err != nil {
				return err
			}
			report.Manifests++
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
		case strings.HasPrefix(entry.Name, "anchors/sth-outbox/"):
			var v model.STHAnchorOutboxItem
			if err := decodeCBOREntry(entry, &v); err != nil {
				return err
			}
			report.AnchorOutboxes++
			if err := store.EnqueueSTHAnchor(ctx, v); err != nil && trusterr.CodeOf(err) != trusterr.CodeAlreadyExists {
				return err
			}
			return markRestored()
		case strings.HasPrefix(entry.Name, "anchors/sth-result/"):
			var v model.STHAnchorResult
			if err := decodeCBOREntry(entry, &v); err != nil {
				return err
			}
			report.AnchorResults++
			if err := store.MarkSTHAnchorPublished(ctx, v); err != nil {
				return err
			}
			return markRestored()
		default:
			_, _ = io.Copy(io.Discard, entry.Reader)
			return nil
		}
	})
	if err != nil {
		return Manifest{}, err
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

func writeJSON(tw *tar.Writer, name string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeBytes(tw, name, data)
}

func writeJSONTracked(tw *tar.Writer, manifest *Manifest, ordinal *int64, name, typ string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
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
	sum := sha256.Sum256(data)
	entry := Entry{
		Ordinal: *ordinal,
		Name:    name,
		Type:    typ,
		Size:    int64(len(data)),
		SHA256:  hex.EncodeToString(sum[:]),
	}
	header := &tar.Header{
		Name:    name,
		Mode:    0o600,
		Size:    int64(len(data)),
		ModTime: time.Unix(0, 0).UTC(),
		PAXRecords: map[string]string{
			paxBackupID: manifest.BackupID,
			paxOrdinal:  strconv.FormatInt(entry.Ordinal, 10),
			paxSHA256:   entry.SHA256,
			paxType:     typ,
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
	Name     string
	Size     int64
	Ordinal  int64
	BackupID string
	SHA256   string
	Type     string
	Reader   io.Reader
}

func readArchiveStream(path string, visit func(archiveEntry) error) error {
	f, err := os.Open(path)
	if err != nil {
		return trusterr.Wrap(trusterr.CodeInternal, "open backup file", err)
	}
	defer f.Close()
	var in io.Reader = f
	if strings.HasSuffix(strings.ToLower(path), ".gz") || strings.HasSuffix(strings.ToLower(path), ".tdbackup") {
		gz, err := gzip.NewReader(f)
		if err == nil {
			defer gz.Close()
			in = gz
		} else {
			if _, seekErr := f.Seek(0, io.SeekStart); seekErr != nil {
				return seekErr
			}
			in = f
		}
	}
	tr := tar.NewReader(in)
	var seq int64
	for {
		header, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "read backup archive", err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		seq++
		ordinal := seq
		if raw := header.PAXRecords[paxOrdinal]; raw != "" {
			if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil {
				ordinal = parsed
			}
		}
		entry := archiveEntry{
			Name:     header.Name,
			Size:     header.Size,
			Ordinal:  ordinal,
			BackupID: header.PAXRecords[paxBackupID],
			SHA256:   header.PAXRecords[paxSHA256],
			Type:     header.PAXRecords[paxType],
			Reader:   tr,
		}
		if err := visit(entry); err != nil {
			return err
		}
	}
}

type countingReader struct {
	r io.Reader
	n int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.n += int64(n)
	return n, err
}

func decodeCBOREntry(entry archiveEntry, v any) error {
	return decodeEntry(entry, func(r io.Reader) error {
		return cborx.DecodeReaderLimit(r, v, entry.Size)
	})
}

func decodeJSONEntry(entry archiveEntry, v any) error {
	return decodeEntry(entry, func(r io.Reader) error {
		decoder := json.NewDecoder(r)
		if err := decoder.Decode(v); err != nil {
			return err
		}
		var extra any
		if err := decoder.Decode(&extra); err == nil {
			return fmt.Errorf("backup entry %s has trailing JSON data", entry.Name)
		} else if err != io.EOF {
			return err
		}
		return nil
	})
}

func decodeEntry(entry archiveEntry, decode func(io.Reader) error) error {
	if entry.Size < 0 || entry.Size > maxRestoreEntryBytes {
		return trusterr.New(trusterr.CodeDataLoss, fmt.Sprintf("backup entry %s too large: %d", entry.Name, entry.Size))
	}
	h := sha256.New()
	limited := io.LimitReader(entry.Reader, entry.Size)
	counting := &countingReader{r: limited}
	tee := io.TeeReader(counting, h)
	if err := decode(tee); err != nil {
		_, _ = io.Copy(io.Discard, tee)
		return err
	}
	if _, err := io.Copy(io.Discard, tee); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "drain backup entry", err)
	}
	if counting.n != entry.Size {
		return trusterr.New(trusterr.CodeDataLoss, fmt.Sprintf("backup entry %s size mismatch: read %d want %d", entry.Name, counting.n, entry.Size))
	}
	if entry.SHA256 != "" {
		got := hex.EncodeToString(h.Sum(nil))
		if got != entry.SHA256 {
			return trusterr.New(trusterr.CodeDataLoss, fmt.Sprintf("backup entry %s sha256 mismatch", entry.Name))
		}
	}
	return nil
}

func validateStreamEntry(entry archiveEntry) error {
	switch {
	case entry.Name == "manifest.json" || entry.Name == "summary.json":
		var v Manifest
		return decodeJSONEntry(entry, &v)
	case strings.HasPrefix(entry.Name, "manifests/"):
		var v model.BatchManifest
		return decodeCBOREntry(entry, &v)
	case strings.HasPrefix(entry.Name, "bundles/"):
		var v model.ProofBundle
		return decodeCBOREntry(entry, &v)
	case strings.HasPrefix(entry.Name, "roots/"):
		var v model.BatchRoot
		return decodeCBOREntry(entry, &v)
	case strings.HasPrefix(entry.Name, "global/leaves/"):
		var v model.GlobalLogLeaf
		return decodeCBOREntry(entry, &v)
	case strings.HasPrefix(entry.Name, "global/nodes/"):
		var v model.GlobalLogNode
		return decodeCBOREntry(entry, &v)
	case entry.Name == "global/state.tdgstate":
		var v model.GlobalLogState
		return decodeCBOREntry(entry, &v)
	case strings.HasPrefix(entry.Name, "global/sth/"):
		var v model.SignedTreeHead
		return decodeCBOREntry(entry, &v)
	case strings.HasPrefix(entry.Name, "global/tiles/"):
		var v model.GlobalLogTile
		return decodeCBOREntry(entry, &v)
	case strings.HasPrefix(entry.Name, "global/outbox/"):
		var v model.GlobalLogOutboxItem
		return decodeCBOREntry(entry, &v)
	case strings.HasPrefix(entry.Name, "anchors/sth-outbox/"):
		var v model.STHAnchorOutboxItem
		return decodeCBOREntry(entry, &v)
	case strings.HasPrefix(entry.Name, "anchors/sth-result/"):
		var v model.STHAnchorResult
		return decodeCBOREntry(entry, &v)
	default:
		_, _ = io.Copy(io.Discard, entry.Reader)
		return nil
	}
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

func normaliseCompression(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "gzip", "gz":
		return "gzip"
	case "none", "tar":
		return "none"
	default:
		return "gzip"
	}
}
