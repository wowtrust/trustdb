package main

import (
	"context"
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
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/keydescriptor"
	"github.com/wowtrust/trustdb/internal/keyenvelope"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"github.com/wowtrust/trustdb/internal/verify"
	"github.com/wowtrust/trustdb/sdk"

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
	identityMu sync.RWMutex
	unlocked   *resolvedDesktopIdentity
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
	a.lockIdentity()
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
	TenantID          string                              `json:"tenant_id"`
	ClientID          string                              `json:"client_id"`
	KeyID             string                              `json:"key_id,omitempty"`
	CryptoSuite       string                              `json:"crypto_suite,omitempty"`
	Provider          string                              `json:"provider,omitempty"`
	Algorithm         string                              `json:"algorithm,omitempty"`
	PublicKeyEncoding string                              `json:"public_key_encoding,omitempty"`
	PublicKeyB64      string                              `json:"public_key_b64,omitempty"`
	PublicFingerprint string                              `json:"public_fingerprint,omitempty"`
	SM2UserID         string                              `json:"sm2_user_id,omitempty"`
	Protection        string                              `json:"protection,omitempty"`
	CertificateCount  int                                 `json:"certificate_count"`
	Certificates      []keydescriptor.CertificateMetadata `json:"certificates,omitempty"`
	HasPrivate        bool                                `json:"has_private"`
	Exportable        bool                                `json:"exportable"`
	Unlocked          bool                                `json:"unlocked"`
	State             string                              `json:"state"`
	Error             string                              `json:"error,omitempty"`
}

func identityView(id *Identity, unlocked bool) *IdentityView {
	if id == nil {
		return nil
	}
	view := &IdentityView{
		TenantID: id.TenantID,
		ClientID: id.ClientID,
		Unlocked: unlocked,
		State:    "invalid",
	}
	descriptor, err := loadDesktopIdentityDescriptor(*id)
	if err != nil {
		view.Error = err.Error()
		return view
	}
	suite, err := cryptosuite.RequireKnown(descriptor.CryptoSuite)
	if err != nil {
		view.Error = err.Error()
		return view
	}
	fingerprint, err := trustcrypto.HashBytesForSuite(
		descriptor.CryptoSuite,
		suite.KeyFingerprintHash.Algorithm,
		descriptor.PublicKey.Bytes,
	)
	if err != nil {
		view.Error = err.Error()
		return view
	}
	certificates, err := descriptor.CertificateMetadata()
	if err != nil {
		view.Error = err.Error()
		return view
	}
	view.KeyID = descriptor.KeyID
	view.CryptoSuite = string(descriptor.CryptoSuite)
	view.Provider = descriptor.Provider
	view.Algorithm = descriptor.Algorithm
	view.PublicKeyEncoding = descriptor.PublicKey.Encoding
	view.PublicKeyB64 = encodeKey(descriptor.PublicKey.Bytes)
	view.PublicFingerprint = encodeKey(fingerprint)
	view.SM2UserID = descriptor.SM2UserID
	view.CertificateCount = len(descriptor.CertificateChain)
	view.Certificates = certificates
	view.HasPrivate = descriptor.Kind == keydescriptor.KindSigner
	view.Exportable = false
	if descriptor.Software != nil {
		view.Protection = descriptor.Software.Protection
	}
	view.State = "ready"
	if !unlocked {
		view.State = "locked"
	}
	return view
}

func (a *App) GetIdentity() *IdentityView {
	s, err := a.requireStore()
	if err != nil {
		return nil
	}
	return identityView(s.getIdentity(), a.identityUnlocked())
}

// GenerateIdentity creates a suite-bound software identity and persists only
// its canonical descriptor plus SM4-encrypted private material.
func (a *App) GenerateIdentity(req GenerateIdentityRequest) (*IdentityView, error) {
	s, err := a.requireStore()
	if err != nil {
		return nil, err
	}
	if s.getIdentity() != nil {
		return nil, errors.New("identity already exists; rotate instead of regenerating")
	}
	managedDir := filepath.Join(s.root.Name(), "identities")
	id, resolved, err := generateSoftwareIdentity(a.ensureCtx(), managedDir, req)
	if err != nil {
		return nil, err
	}
	if err := s.setIdentity(id); err != nil {
		_ = resolved.close()
		removeManagedIdentityMaterial(managedDir, id)
		return nil, err
	}
	a.setUnlockedIdentity(resolved)
	return identityView(&id, true), nil
}

// RotateIdentity replaces one managed software identity with a fresh key in
// the same suite. External-provider rotation is performed by referencing a new
// provider descriptor so provider custody remains authoritative.
func (a *App) RotateIdentity(req RotateIdentityRequest) (*IdentityView, error) {
	s, err := a.requireStore()
	if err != nil {
		return nil, err
	}
	current := s.getIdentity()
	if current == nil {
		return nil, errors.New("no existing identity to rotate")
	}
	if strings.TrimSpace(req.KeyID) == "" {
		return nil, errors.New("new key_id is required")
	}
	descriptor, err := loadDesktopIdentityDescriptor(*current)
	if err != nil {
		return nil, err
	}
	if descriptor.Provider != keydescriptor.ProviderSoftware || !current.ManagedMaterial {
		return nil, errors.New("provider identity rotation requires referencing a new signer descriptor")
	}
	managedDir := filepath.Join(s.root.Name(), "identities")
	id, resolved, err := generateSoftwareIdentity(a.ensureCtx(), managedDir, GenerateIdentityRequest{
		TenantID:    current.TenantID,
		ClientID:    current.ClientID,
		KeyID:       req.KeyID,
		CryptoSuite: string(descriptor.CryptoSuite),
		Passphrase:  req.Passphrase,
	})
	if err != nil {
		return nil, err
	}
	if err := s.setIdentity(id); err != nil {
		_ = resolved.close()
		removeManagedIdentityMaterial(managedDir, id)
		return nil, err
	}
	a.setUnlockedIdentity(resolved)
	removeManagedIdentityMaterial(managedDir, *current)
	return identityView(&id, true), nil
}

// ImportIdentity accepts private bytes only as a one-shot input and immediately
// seals them into the same encrypted V2 storage used by generated identities.
func (a *App) ImportIdentity(req ImportIdentityRequest) (*IdentityView, error) {
	s, err := a.requireStore()
	if err != nil {
		return nil, err
	}
	managedDir := filepath.Join(s.root.Name(), "identities")
	id, resolved, err := importSoftwareIdentity(a.ensureCtx(), managedDir, req)
	if err != nil {
		return nil, err
	}
	old := s.getIdentity()
	if err := s.setIdentity(id); err != nil {
		_ = resolved.close()
		removeManagedIdentityMaterial(managedDir, id)
		return nil, err
	}
	a.setUnlockedIdentity(resolved)
	if old != nil {
		removeManagedIdentityMaterial(managedDir, *old)
	}
	return identityView(&id, true), nil
}

// ReferenceIdentity binds an existing canonical signer descriptor. Software
// references must use an SM4 envelope; PKCS#11/SDF/remote references execute
// only through the generic supervised signer-plugin protocol.
func (a *App) ReferenceIdentity(req ReferenceIdentityRequest) (*IdentityView, error) {
	s, err := a.requireStore()
	if err != nil {
		return nil, err
	}
	id, resolved, err := referenceDesktopIdentity(a.ensureCtx(), req)
	if err != nil {
		return nil, err
	}
	old := s.getIdentity()
	if err := s.setIdentity(id); err != nil {
		_ = resolved.close()
		return nil, err
	}
	a.setUnlockedIdentity(resolved)
	if old != nil {
		removeManagedIdentityMaterial(filepath.Join(s.root.Name(), "identities"), *old)
	}
	return identityView(&id, true), nil
}

func (a *App) UnlockIdentity(passphrase string) (*IdentityView, error) {
	s, err := a.requireStore()
	if err != nil {
		return nil, err
	}
	id := s.getIdentity()
	if id == nil {
		return nil, errors.New("no identity")
	}
	resolved, err := resolveDesktopIdentity(a.ensureCtx(), *id, passphrase)
	if err != nil {
		return nil, err
	}
	a.setUnlockedIdentity(resolved)
	return identityView(id, true), nil
}

func (a *App) LockIdentity() {
	a.lockIdentity()
}

func (a *App) ExportVerifierDescriptor(outPath string) error {
	if strings.TrimSpace(outPath) == "" {
		return errors.New("output path is required")
	}
	store, err := a.requireStore()
	if err != nil {
		return err
	}
	id := store.getIdentity()
	if id == nil {
		return errors.New("no identity")
	}
	descriptor, err := loadDesktopIdentityDescriptor(*id)
	if err != nil {
		return err
	}
	descriptor.Kind = keydescriptor.KindVerifier
	descriptor.Provider = keydescriptor.ProviderPublic
	descriptor.Software = nil
	descriptor.PKCS11 = nil
	descriptor.SDF = nil
	descriptor.Remote = nil
	data, err := keydescriptor.Marshal(descriptor)
	if err != nil {
		return err
	}
	return a.writeAuthorizedFile(outPath, data, 0o644)
}

func (a *App) ClearIdentity() error {
	s, err := a.requireStore()
	if err != nil {
		return err
	}
	id := s.getIdentity()
	if err := s.clearIdentity(); err != nil {
		return err
	}
	a.lockIdentity()
	if id != nil {
		removeManagedIdentityMaterial(filepath.Join(s.root.Name(), "identities"), *id)
	}
	return nil
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
	suite, err := requireDesktopSuite(s.ServerCryptoSuite)
	if err != nil {
		return err
	}
	s.ServerCryptoSuite = string(suite.ID)
	if s.ServerPubKeyB64 != "" {
		raw, err := decodeKeyField(s.ServerPubKeyB64)
		if err != nil {
			return fmt.Errorf("server public key: %w", err)
		}
		if _, err := desktopPublicKeyDescriptor(suite.ID, "desktop-settings-server-key", raw); err != nil {
			return fmt.Errorf("server public key: %w", err)
		}
		// Normalise to raw base64-url so the UI has a stable
		// representation regardless of how the user pasted it.
		s.ServerPubKeyB64 = encodeKey(raw)
	}
	s.ServerCAFile = strings.TrimSpace(s.ServerCAFile)
	s.ServerName = strings.TrimSpace(s.ServerName)
	s.ServerCAPinsSHA256 = strings.TrimSpace(s.ServerCAPinsSHA256)
	s.ClientTLSCertFile = strings.TrimSpace(s.ClientTLSCertFile)
	s.ClientTLSKeyFile = strings.TrimSpace(s.ClientTLSKeyFile)
	s.ClientVerifierDescriptor = strings.TrimSpace(s.ClientVerifierDescriptor)
	s.ServerVerifierDescriptor = strings.TrimSpace(s.ServerVerifierDescriptor)
	s.RegistryVerifierDescriptor = strings.TrimSpace(s.RegistryVerifierDescriptor)
	s.ClientCertificateRoots = strings.TrimSpace(s.ClientCertificateRoots)
	s.ServerCertificateRoots = strings.TrimSpace(s.ServerCertificateRoots)
	if (s.ClientTLSCertFile == "") != (s.ClientTLSKeyFile == "") {
		return errors.New("client TLS certificate and key must be configured together")
	}
	if strings.TrimSpace(s.TLSReloadInterval) == "" {
		s.TLSReloadInterval = "1m"
	}
	if _, err := time.ParseDuration(s.TLSReloadInterval); err != nil {
		return errors.New("TLS reload interval must be a valid duration")
	}
	if err := tlsConfigFromSettings(s).Validate(); err != nil && (strings.EqualFold(parsedScheme(s.ServerURL), "https") || hasTLSInputs(tlsConfigFromSettings(s))) {
		return fmt.Errorf("transport TLS settings: %w", err)
	}
	return store.setSettings(s)
}

// --- File dialogs & hashing ----------------------------------------

type FileInfo struct {
	Path        string `json:"path"`
	Name        string `json:"name"`
	Size        int64  `json:"size"`
	CryptoSuite string `json:"crypto_suite"`
	HashAlg     string `json:"hash_alg"`
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
	suiteID, err := a.activeIdentitySuite()
	if err != nil {
		return nil, err
	}
	suite, err := cryptosuite.RequireAvailable(suiteID)
	if err != nil {
		return nil, err
	}
	out := make([]FileInfo, 0, len(paths))
	for _, p := range paths {
		if p == "" {
			continue
		}
		f, err := os.Open(p)
		if err != nil {
			return nil, err
		}
		sum, n, err := trustcrypto.HashReaderForSuite(suite.ID, suite.ContentHash.Algorithm, f)
		_ = f.Close()
		if err != nil {
			return nil, err
		}
		out = append(out, FileInfo{
			Path:        p,
			Name:        filepath.Base(p),
			Size:        n,
			CryptoSuite: string(suite.ID),
			HashAlg:     suite.ContentHash.Algorithm,
			ContentHash: hex.EncodeToString(sum),
			MediaType:   guessMedia(p),
		})
	}
	return out, nil
}

// StartHashing kicks off an asynchronous suite-selected content-hash pass over
// the given paths. It returns a job id the frontend uses to correlate progress events and
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
	suiteID, err := a.activeIdentitySuite()
	if err != nil {
		return "", err
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
			info, err := hashFileStreamForSuite(job.ctx, p, suiteID, func(read, fileTotal int64) {
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

func (a *App) ListAnchorSystems() ([]model.AnchorSystem, error) {
	c, err := a.serverClient()
	if err != nil {
		return nil, err
	}
	defer c.close()
	return c.listAnchorSystems(a.ensureCtx())
}

func (a *App) GetAnchorSystemStatus(systemID string) (model.AnchorSystemStatus, error) {
	c, err := a.serverClient()
	if err != nil {
		return model.AnchorSystemStatus{}, err
	}
	defer c.close()
	return c.getAnchorSystemStatus(a.ensureCtx(), systemID)
}

func (a *App) ListAnchorSystemResources(systemID, kind string, limit int, cursor string) (model.AnchorSystemResourcePage, error) {
	c, err := a.serverClient()
	if err != nil {
		return model.AnchorSystemResourcePage{}, err
	}
	defer c.close()
	return c.listAnchorSystemResources(a.ensureCtx(), systemID, kind, limit, cursor)
}

func (a *App) GetAnchorSystemResource(systemID, kind, resourceID string) (model.AnchorSystemResource, error) {
	c, err := a.serverClient()
	if err != nil {
		return model.AnchorSystemResource{}, err
	}
	defer c.close()
	return c.getAnchorSystemResource(a.ensureCtx(), systemID, kind, resourceID)
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

func (a *App) identityUnlocked() bool {
	a.identityMu.RLock()
	defer a.identityMu.RUnlock()
	return a.unlocked != nil
}

func (a *App) unlockedSDKIdentity() (sdk.Identity, error) {
	a.identityMu.RLock()
	defer a.identityMu.RUnlock()
	if a.unlocked == nil {
		return sdk.Identity{}, errors.New("identity is locked; unlock it before signing")
	}
	return a.unlocked.identity, nil
}

func (a *App) activeIdentitySuite() (cryptosuite.ID, error) {
	store, err := a.requireStore()
	if err != nil {
		return "", err
	}
	id := store.getIdentity()
	if id == nil {
		suite, err := requireDesktopSuite(store.getSettings().ServerCryptoSuite)
		if err != nil {
			return "", err
		}
		return suite.ID, nil
	}
	descriptor, err := loadDesktopIdentityDescriptor(*id)
	if err != nil {
		return "", err
	}
	return descriptor.CryptoSuite, nil
}

func (a *App) setUnlockedIdentity(resolved *resolvedDesktopIdentity) {
	a.identityMu.Lock()
	previous := a.unlocked
	a.unlocked = resolved
	a.identityMu.Unlock()
	if previous != nil {
		_ = previous.close()
	}
}

func (a *App) lockIdentity() {
	a.identityMu.Lock()
	previous := a.unlocked
	a.unlocked = nil
	a.identityMu.Unlock()
	if previous != nil {
		_ = previous.close()
	}
}

func removeManagedIdentityMaterial(managedDir string, id Identity) {
	if !id.ManagedMaterial {
		return
	}
	descriptorPath, ok := pathWithinDirectory(managedDir, id.DescriptorPath)
	if !ok {
		return
	}
	descriptor, err := keydescriptor.ReadFile(descriptorPath)
	if err == nil && descriptor.Software != nil {
		materialPath := filepath.Join(filepath.Dir(descriptorPath), filepath.FromSlash(descriptor.Software.MaterialPath))
		if materialPath, withinManagedDir := pathWithinDirectory(managedDir, materialPath); withinManagedDir {
			_ = keyenvelope.RemoveFile(context.Background(), materialPath)
		}
	}
	_ = os.Remove(descriptorPath)
}

func pathWithinDirectory(directory, path string) (string, bool) {
	root, err := filepath.Abs(directory)
	if err != nil {
		return "", false
	}
	target, err := filepath.Abs(path)
	if err != nil {
		return "", false
	}
	relative, err := filepath.Rel(root, target)
	if err != nil || relative == "." || filepath.IsAbs(relative) ||
		relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", false
	}
	return target, true
}

func (a *App) serverClient() (*serverClient, error) {
	s, err := a.requireStore()
	if err != nil {
		return nil, err
	}
	cfg := s.getSettings()
	suite, err := requireDesktopSuite(cfg.ServerCryptoSuite)
	if err != nil {
		return nil, err
	}
	return newServerClientWithTLSForSuite(cfg.ServerTransport, cfg.ServerURL, tlsConfigFromSettings(cfg), suite.ID)
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
