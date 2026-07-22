package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/claim"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"github.com/wowtrust/trustdb/internal/verify"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

var (
	desktopVersion = "dev"
	desktopCommit  = "none"
	desktopDate    = "unknown"
)

// App is the bridge Wails exposes to the frontend: every exported
// method here becomes a TypeScript-callable RPC. We collect them on
// one struct so state (store, ctx) is shared without globals.
type App struct {
	ctx        context.Context
	storeMu    sync.Mutex
	store      *store
	hashJobs   *hashJobManager
	savePathMu sync.Mutex
	savePaths  map[string]string
}

func NewApp() *App {
	return &App{
		hashJobs:  newHashJobManager(),
		savePaths: make(map[string]string),
	}
}

// Version returns a short string the UI puts in the footer so users
// know which desktop build they are running when filing bugs.
func (a *App) Version() string {
	if desktopVersion != "" && desktopVersion != "dev" {
		return desktopVersion
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Version != "" && info.Main.Version != "(devel)" {
			return info.Main.Version
		}
	}
	return "dev"
}

// startup is invoked by Wails after the WebView is ready. We open
// the config store here — not in NewApp — because the user-data
// directory is only meaningful once the runtime is wired up.
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	if err := a.ensureStore(); err != nil {
		wailsruntime.LogErrorf(ctx, "load store: %v", err)
		return
	}
}

func (a *App) shutdown(ctx context.Context) {
	a.storeMu.Lock()
	defer a.storeMu.Unlock()
	if a.store == nil {
		return
	}
	if err := a.store.close(); err != nil && ctx != nil {
		wailsruntime.LogErrorf(ctx, "close store: %v", err)
	}
	a.store = nil
}

func (a *App) prepareConfigDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	root, err := openUserConfigRoot(base)
	if err != nil {
		return "", err
	}
	defer root.Close()
	const appDir = "TrustDB-Desktop"
	if err := root.MkdirAll(appDir, 0o755); err != nil {
		return "", err
	}
	appRoot, err := root.OpenRoot(appDir)
	if err != nil {
		return "", err
	}
	defer appRoot.Close()
	return appRoot.Name(), nil
}

func openUserConfigRoot(base string) (*os.Root, error) {
	root, err := os.OpenRoot(base)
	if err == nil || !os.IsNotExist(err) {
		return root, err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	homeRoot, err := os.OpenRoot(home)
	if err != nil {
		return nil, err
	}
	defer homeRoot.Close()
	rel, err := filepath.Rel(home, base)
	if err != nil {
		return nil, err
	}
	rel, err = cleanRootRelativePath(rel)
	if err != nil {
		return nil, fmt.Errorf("user config directory is outside the user home: %w", err)
	}
	if err := homeRoot.MkdirAll(rel, 0o755); err != nil {
		return nil, err
	}
	return homeRoot.OpenRoot(rel)
}

func (a *App) ensureStore() error {
	a.storeMu.Lock()
	defer a.storeMu.Unlock()
	if a.store != nil {
		return nil
	}
	dir, err := a.prepareConfigDir()
	if err != nil {
		return fmt.Errorf("resolve config dir: %w", err)
	}
	s, err := newStore(filepath.Join(dir, "config.json"))
	if err != nil {
		return err
	}
	a.store = s
	return nil
}

func (a *App) requireStore() (*store, error) {
	if err := a.ensureStore(); err != nil {
		return nil, err
	}
	return a.store, nil
}

// --- Identity -------------------------------------------------------

type IdentityView struct {
	TenantID     string `json:"tenant_id"`
	ClientID     string `json:"client_id"`
	KeyID        string `json:"key_id"`
	PublicKeyB64 string `json:"public_key_b64"`
	HasPrivate   bool   `json:"has_private"`
}

func identityView(id *Identity) *IdentityView {
	if id == nil {
		return nil
	}
	return &IdentityView{
		TenantID:     id.TenantID,
		ClientID:     id.ClientID,
		KeyID:        id.KeyID,
		PublicKeyB64: id.PublicKeyB64,
		HasPrivate:   id.PrivateKeyB64 != "",
	}
}

func (a *App) GetIdentity() *IdentityView {
	s, err := a.requireStore()
	if err != nil {
		return nil
	}
	return identityView(s.getIdentity())
}

// GenerateIdentity creates a brand-new Ed25519 keypair. If an
// identity already exists we refuse rather than silently replacing
// it — the user loses access to anything they signed with the old
// key, so this must be a deliberate action (UI should route to
// "Rotate key" instead).
func (a *App) GenerateIdentity(tenantID, clientID, keyID string) (*IdentityView, error) {
	s, err := a.requireStore()
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(clientID) == "" || strings.TrimSpace(keyID) == "" {
		return nil, errors.New("tenant_id, client_id, key_id are required")
	}
	if s.getIdentity() != nil {
		return nil, errors.New("identity already exists; rotate instead of regenerating")
	}
	id, err := generateIdentity(tenantID, clientID, keyID)
	if err != nil {
		return nil, err
	}
	if err := s.setIdentity(id); err != nil {
		return nil, err
	}
	return identityView(&id), nil
}

// RotateIdentity replaces the current private key but preserves the
// tenant/client identity so downstream servers still see the same
// client; only the key_id changes.
func (a *App) RotateIdentity(newKeyID string) (*IdentityView, error) {
	s, err := a.requireStore()
	if err != nil {
		return nil, err
	}
	current := s.getIdentity()
	if current == nil {
		return nil, errors.New("no existing identity to rotate")
	}
	if strings.TrimSpace(newKeyID) == "" {
		return nil, errors.New("new key_id is required")
	}
	id, err := generateIdentity(current.TenantID, current.ClientID, newKeyID)
	if err != nil {
		return nil, err
	}
	if err := s.setIdentity(id); err != nil {
		return nil, err
	}
	return identityView(&id), nil
}

// ImportIdentity replaces whatever is in the store with a user-supplied
// private key. We re-derive the public key rather than trusting the
// provided public key so the two halves can never diverge.
func (a *App) ImportIdentity(tenantID, clientID, keyID, privateKeyB64 string) (*IdentityView, error) {
	s, err := a.requireStore()
	if err != nil {
		return nil, err
	}
	raw, err := decodeKeyField(privateKeyB64)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key wrong size %d (want %d)", len(raw), ed25519.PrivateKeySize)
	}
	id, err := identityFromPrivate(ed25519.PrivateKey(raw), tenantID, clientID, keyID)
	if err != nil {
		return nil, err
	}
	if err := s.setIdentity(id); err != nil {
		return nil, err
	}
	return identityView(&id), nil
}

// ExportPrivateKey returns the base64 private key. The UI gates this
// behind an explicit confirm step because once copied it cannot be
// revoked; the desktop merely trusts that the user really meant it.
func (a *App) ExportPrivateKey() (string, error) {
	s, err := a.requireStore()
	if err != nil {
		return "", err
	}
	id := s.getIdentity()
	if id == nil {
		return "", errors.New("no identity")
	}
	return id.PrivateKeyB64, nil
}

func (a *App) ClearIdentity() error {
	s, err := a.requireStore()
	if err != nil {
		return err
	}
	return s.clearIdentity()
}

// --- Settings -------------------------------------------------------

func (a *App) GetSettings() Settings {
	s, err := a.requireStore()
	if err != nil {
		return defaultSettings()
	}
	return s.getSettings()
}

func (a *App) SaveSettings(s Settings) error {
	store, err := a.requireStore()
	if err != nil {
		return err
	}
	if !validServerTransport(s.ServerTransport) {
		return fmt.Errorf("unsupported server transport: %s", s.ServerTransport)
	}
	if s.ServerPubKeyB64 != "" {
		raw, err := decodeKeyField(s.ServerPubKeyB64)
		if err != nil {
			return fmt.Errorf("server public key: %w", err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return fmt.Errorf("server public key wrong size %d", len(raw))
		}
		// Normalise to raw base64-url so the UI has a stable
		// representation regardless of how the user pasted it.
		s.ServerPubKeyB64 = encodeKey(raw)
	}
	return store.setSettings(s)
}

// --- File dialogs & hashing ----------------------------------------

type FileInfo struct {
	Path        string `json:"path"`
	Name        string `json:"name"`
	Size        int64  `json:"size"`
	ContentHash string `json:"content_hash_hex"`
	MediaType   string `json:"media_type"`
}

// ChooseFiles opens the native multi-file picker and returns the raw
// selected paths. Hashing is deliberately separated into StartHashing
// so the UI can render a progress bar instead of freezing on multi-GiB
// inputs; the caller is expected to pass these paths straight into
// StartHashing (or DescribeFiles for small inline cases).
func (a *App) ChooseFiles() ([]string, error) {
	if a.ctx == nil {
		return nil, errors.New("runtime not ready")
	}
	return wailsruntime.OpenMultipleFilesDialog(a.ctx, wailsruntime.OpenDialogOptions{
		Title: "Select files to attest",
	})
}

// DescribeFiles is the synchronous "hash now, return everything" entry
// point. Kept for unit tests and tiny CLI-style scenarios — the UI
// should prefer StartHashing so progress and cancellation work.
func (a *App) DescribeFiles(paths []string) ([]FileInfo, error) {
	return a.describeFiles(paths)
}

func (a *App) describeFiles(paths []string) ([]FileInfo, error) {
	out := make([]FileInfo, 0, len(paths))
	for _, p := range paths {
		if p == "" {
			continue
		}
		f, err := os.Open(p)
		if err != nil {
			return nil, err
		}
		sum, n, err := trustcrypto.HashReader(model.DefaultHashAlg, f)
		_ = f.Close()
		if err != nil {
			return nil, err
		}
		out = append(out, FileInfo{
			Path:        p,
			Name:        filepath.Base(p),
			Size:        n,
			ContentHash: hex.EncodeToString(sum),
			MediaType:   guessMedia(p),
		})
	}
	return out, nil
}

// StartHashing kicks off an async sha256 pass over the given paths and
// returns a job id the frontend uses to correlate progress events and
// (optionally) cancel. Emitted Wails events:
//
//   - hash:begin         { job_id, total_files, total_bytes }
//   - hash:file-progress { job_id, index, path, name, bytes_hashed, bytes_total }
//   - hash:file-done     { job_id, index, info }
//   - hash:done          { job_id, infos }
//   - hash:error         { job_id, index, path, error }  (index=-1 => job-wide)
//   - hash:cancelled     { job_id }
//
// The job holds no lock on the App and removes itself from hashJobs
// when finished, so there is no leak even if the user closes the
// Attest page mid-hash.
func (a *App) StartHashing(paths []string) (string, error) {
	if a.ctx == nil {
		return "", errors.New("runtime not ready")
	}
	cleaned := make([]string, 0, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p != "" {
			cleaned = append(cleaned, p)
		}
	}
	if len(cleaned) == 0 {
		return "", errors.New("no files to hash")
	}
	// Pre-stat so the UI can show the grand total immediately. Any
	// unreadable file is fatal for the whole job — we prefer to fail
	// fast at the picker rather than mid-hash after 4 GiB of work.
	sizes := make([]int64, len(cleaned))
	var total int64
	for i, p := range cleaned {
		fi, err := os.Stat(p)
		if err != nil {
			return "", fmt.Errorf("stat %s: %w", p, err)
		}
		sizes[i] = fi.Size()
		total += fi.Size()
	}

	jobID := newJobID()
	job := a.hashJobs.register(a.ctx, jobID)

	wailsruntime.EventsEmit(a.ctx, "hash:begin", HashJobEvent{
		JobID:      jobID,
		TotalFiles: len(cleaned),
		TotalBytes: total,
	})

	go func() {
		defer a.hashJobs.remove(jobID)
		infos := make([]FileInfo, 0, len(cleaned))
		for i, p := range cleaned {
			if err := job.ctx.Err(); err != nil {
				wailsruntime.EventsEmit(a.ctx, "hash:cancelled", HashJobEvent{JobID: jobID})
				return
			}
			name := filepath.Base(p)
			// Emit a zero-progress tick so the UI can render an empty
			// bar the moment a file becomes "current", even before any
			// bytes have been read.
			wailsruntime.EventsEmit(a.ctx, "hash:file-progress", HashJobEvent{
				JobID:      jobID,
				Index:      i,
				Path:       p,
				Name:       name,
				BytesTotal: sizes[i],
			})
			info, err := hashFileStream(job.ctx, p, func(read, fileTotal int64) {
				wailsruntime.EventsEmit(a.ctx, "hash:file-progress", HashJobEvent{
					JobID:       jobID,
					Index:       i,
					Path:        p,
					Name:        name,
					BytesHashed: read,
					BytesTotal:  fileTotal,
				})
			})
			if err != nil {
				if errors.Is(err, context.Canceled) {
					wailsruntime.EventsEmit(a.ctx, "hash:cancelled", HashJobEvent{JobID: jobID})
					return
				}
				wailsruntime.EventsEmit(a.ctx, "hash:error", HashJobEvent{
					JobID: jobID,
					Index: i,
					Path:  p,
					Name:  name,
					Error: err.Error(),
				})
				return
			}
			infos = append(infos, info)
			wailsruntime.EventsEmit(a.ctx, "hash:file-done", HashJobEvent{
				JobID: jobID,
				Index: i,
				Path:  p,
				Name:  name,
				Info:  &info,
			})
		}
		wailsruntime.EventsEmit(a.ctx, "hash:done", HashJobEvent{
			JobID: jobID,
			Infos: infos,
		})
	}()

	return jobID, nil
}

// CancelHashing tells a running job to abort at the next progress
// tick. Already-completed or unknown jobs return false so the UI can
// decide whether to warn.
func (a *App) CancelHashing(jobID string) bool {
	return a.hashJobs.cancel(jobID)
}

func guessMedia(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".pdf":
		return "application/pdf"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".json":
		return "application/json"
	case ".txt", ".md", ".log":
		return "text/plain"
	case ".zip":
		return "application/zip"
	case ".wav":
		return "audio/wav"
	case ".mp4":
		return "video/mp4"
	}
	return "application/octet-stream"
}

// ChooseSavePath wraps the native save dialog so "export proof" has
// the same look and feel as every other Save-As dialog the user is
// used to.
func (a *App) ChooseSavePath(title, defaultFile string) (string, error) {
	if a.ctx == nil {
		return "", errors.New("runtime not ready")
	}
	selected, err := wailsruntime.SaveFileDialog(a.ctx, wailsruntime.SaveDialogOptions{
		Title:           title,
		DefaultFilename: defaultFile,
	})
	if err != nil || strings.TrimSpace(selected) == "" {
		return selected, err
	}
	return a.rememberSavePath(selected)
}

func (a *App) ChooseOpenPath(title string) (string, error) {
	if a.ctx == nil {
		return "", errors.New("runtime not ready")
	}
	return wailsruntime.OpenFileDialog(a.ctx, wailsruntime.OpenDialogOptions{
		Title: title,
	})
}

// --- Records --------------------------------------------------------

func (a *App) ListRecords() []LocalRecord {
	s, err := a.requireStore()
	if err != nil {
		return nil
	}
	return s.listRecords()
}

func (a *App) ListRecordsPage(opts RecordPageOptions) RecordPage {
	s, err := a.requireStore()
	if err != nil {
		return RecordPage{}
	}
	return s.listRecordsPage(opts)
}

func (a *App) ListRemoteRecordsPage(opts RecordPageOptions) (RecordPage, error) {
	c, err := a.serverClient()
	if err != nil {
		return RecordPage{}, err
	}
	defer c.close()
	return c.listRecordIndexes(a.ensureCtx(), opts)
}

func (a *App) DeleteRecord(recordID string) error {
	s, err := a.requireStore()
	if err != nil {
		return err
	}
	return s.deleteRecord(recordID)
}

// --- Server health & roots -----------------------------------------

func (a *App) ServerHealth() HealthStatus {
	c, err := a.serverClient()
	if err != nil {
		return HealthStatus{Error: err.Error()}
	}
	defer c.close()
	return c.health(a.ensureCtx())
}

func (a *App) LatestRoot() (model.BatchRoot, error) {
	c, err := a.serverClient()
	if err != nil {
		return model.BatchRoot{}, err
	}
	defer c.close()
	return c.latestRoot(a.ensureCtx())
}

func (a *App) ListRoots(limit int) ([]model.BatchRoot, error) {
	c, err := a.serverClient()
	if err != nil {
		return nil, err
	}
	defer c.close()
	return c.listRoots(a.ensureCtx(), limit)
}

// --- Metrics --------------------------------------------------------

func (a *App) ServerMetrics() ([]Metric, error) {
	c, err := a.serverClient()
	if err != nil {
		return nil, err
	}
	defer c.close()
	raw, err := c.metricsRaw(a.ensureCtx())
	if err != nil {
		return nil, err
	}
	return parseMetricsText(raw), nil
}

// --- Helpers --------------------------------------------------------

func (a *App) ensureCtx() context.Context {
	if a.ctx != nil {
		return a.ctx
	}
	return context.Background()
}

func (a *App) serverClient() (*serverClient, error) {
	s, err := a.requireStore()
	if err != nil {
		return nil, err
	}
	cfg := s.getSettings()
	return newServerClient(cfg.ServerTransport, cfg.ServerURL)
}

// serverPublicKey decodes the configured server public key, or returns
// a friendly error telling the UI to prompt for it. Kept central so
// any verify/submit code path has the same error message.
func (a *App) serverPublicKey() (ed25519.PublicKey, error) {
	s, err := a.requireStore()
	if err != nil {
		return nil, err
	}
	cfg := s.getSettings()
	if cfg.ServerPubKeyB64 == "" {
		return nil, errors.New("server public key is not configured — add it in Settings")
	}
	raw, err := decodeKeyField(cfg.ServerPubKeyB64)
	if err != nil {
		return nil, fmt.Errorf("server public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("server public key wrong size: %d", len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// claimFromFile builds a signed claim for a single file path using
// the caller-supplied identity. It is the one-stop helper shared by
// single and batch submit paths so idempotency + nonce generation
// only live in one place.
func buildSignedClaim(priv ed25519.PrivateKey, id Identity, info FileInfo, mediaType, eventType, source string) (model.SignedClaim, string, error) {
	sum, err := hex.DecodeString(info.ContentHash)
	if err != nil {
		return model.SignedClaim{}, "", fmt.Errorf("content hash hex: %w", err)
	}
	nonce, err := trustcrypto.NewNonce(16)
	if err != nil {
		return model.SignedClaim{}, "", err
	}
	idemBytes, err := trustcrypto.NewNonce(16)
	if err != nil {
		return model.SignedClaim{}, "", err
	}
	idempotency := base64.RawURLEncoding.EncodeToString(idemBytes)
	if mediaType == "" {
		mediaType = info.MediaType
	}
	if mediaType == "" {
		mediaType = "application/octet-stream"
	}
	if eventType == "" {
		eventType = "file.snapshot"
	}
	if source == "" {
		source = id.ClientID
	}
	c, err := claim.NewFileClaim(
		id.TenantID,
		id.ClientID,
		id.KeyID,
		time.Now().UTC(),
		nonce,
		idempotency,
		model.Content{
			HashAlg:       model.DefaultHashAlg,
			ContentHash:   sum,
			ContentLength: info.Size,
			MediaType:     mediaType,
			StorageURI:    "file://" + filepath.ToSlash(info.Path),
		},
		model.Metadata{
			EventType: eventType,
			Source:    source,
			Custom: map[string]string{
				"file_name": info.Name,
			},
		},
	)
	if err != nil {
		return model.SignedClaim{}, "", err
	}
	signed, err := claim.Sign(c, priv)
	if err != nil {
		return model.SignedClaim{}, "", err
	}
	return signed, idempotency, nil
}

// marshalClaim is a thin helper so callers can keep the CBOR
// encoding implementation detail out of the submit flow.
func marshalClaim(signed model.SignedClaim) ([]byte, error) {
	return cborx.Marshal(signed)
}

// assertAnchorConsistency is a tiny wrapper so the frontend-facing
// verify code and the record-detail "re-check" flow share the same
// tolerance: an empty STHAnchorResult means "skip L5" rather than an
// error. L5 requires the global inclusion proof because batch roots are
// never directly anchored.
func assertAnchorConsistency(global *model.GlobalLogProof, ar *model.STHAnchorResult) error {
	if ar == nil {
		return nil
	}
	if global == nil {
		return errors.New("anchor verification requires a global log proof")
	}
	return verify.AnchorConsistency(*global, *ar)
}
