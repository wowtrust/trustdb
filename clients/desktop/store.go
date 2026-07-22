package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/wowtrust/trustdb/internal/model"
)

// Identity is the signing persona the desktop client uses. Keys are
// stored base64-url-raw (no padding) to stay friendly for hand-editing
// the config file without shelling out to a helper.
type Identity struct {
	TenantID      string `json:"tenant_id"`
	ClientID      string `json:"client_id"`
	KeyID         string `json:"key_id"`
	PrivateKeyB64 string `json:"private_key_b64"`
	PublicKeyB64  string `json:"public_key_b64"`
}

// Settings captures everything that is not a secret but should still
// survive restarts: the target server, the server's signing key so
// we can verify responses, and UI preferences.
type Settings struct {
	ServerURL       string `json:"server_url"`
	ServerTransport string `json:"server_transport"`
	ServerPubKeyB64 string `json:"server_public_key_b64"`
	DefaultMedia    string `json:"default_media_type"`
	DefaultEvent    string `json:"default_event_type"`
	Theme           string `json:"theme"`
}

const (
	serverTransportHTTP = "http"
	serverTransportGRPC = "grpc"
)

// LocalRecord is everything we remember about a submission we sent
// from this workstation: enough to show a rich Record detail page
// (timestamps, sizes, proof level) and to resume status tracking
// across app restarts without having to re-fetch from the server.
type LocalRecord struct {
	RecordID          string                  `json:"record_id"`
	SubmittedAt       string                  `json:"submitted_at"`
	SubmittedAtUnixN  int64                   `json:"submitted_at_unix_nano"`
	FilePath          string                  `json:"file_path"`
	FileName          string                  `json:"file_name"`
	ContentHashHex    string                  `json:"content_hash_hex"`
	ContentLength     int64                   `json:"content_length"`
	MediaType         string                  `json:"media_type"`
	EventType         string                  `json:"event_type"`
	Source            string                  `json:"source"`
	IdempotencyKey    string                  `json:"idempotency_key"`
	TenantID          string                  `json:"tenant_id"`
	ClientID          string                  `json:"client_id"`
	KeyID             string                  `json:"key_id"`
	ProofLevel        string                  `json:"proof_level"`
	BatchID           string                  `json:"batch_id"`
	AnchorStatus      string                  `json:"anchor_status"`
	AnchorSink        string                  `json:"anchor_sink,omitempty"`
	AnchorID          string                  `json:"anchor_id,omitempty"`
	LastError         string                  `json:"last_error,omitempty"`
	LastSyncedAt      string                  `json:"last_synced_at,omitempty"`
	LastSyncedAtUnixN int64                   `json:"last_synced_at_unix_nano,omitempty"`
	ServerRecord      *model.ServerRecord     `json:"server_record,omitempty"`
	AcceptedReceipt   *model.AcceptedReceipt  `json:"accepted_receipt,omitempty"`
	CommittedReceipt  *model.CommittedReceipt `json:"committed_receipt,omitempty"`
	GlobalProof       *model.GlobalLogProof   `json:"global_proof,omitempty"`
	AnchorResult      *model.STHAnchorResult  `json:"anchor_result,omitempty"`
}

func setLocalRecordSubmittedAt(rec *LocalRecord, at time.Time) {
	rec.SubmittedAtUnixN = at.UTC().UnixNano()
	rec.SubmittedAt = at.UTC().Format(time.RFC3339Nano)
}

func setLocalRecordLastSyncedAt(rec *LocalRecord, at time.Time) {
	rec.LastSyncedAtUnixN = at.UTC().UnixNano()
	rec.LastSyncedAt = at.UTC().Format(time.RFC3339Nano)
}

func localRecordTimeUnixN(unixNano int64, iso string) int64 {
	if unixNano != 0 {
		return unixNano
	}
	if iso == "" {
		return 0
	}
	at, err := time.Parse(time.RFC3339Nano, iso)
	if err != nil {
		return 0
	}
	return at.UTC().UnixNano()
}

type RecordPageOptions struct {
	Limit     int    `json:"limit"`
	Offset    int    `json:"offset"`
	Cursor    string `json:"cursor,omitempty"`
	Direction string `json:"direction,omitempty"`
	Query     string `json:"query,omitempty"`
	Level     string `json:"level,omitempty"`
	BatchID   string `json:"batch_id,omitempty"`
	TenantID  string `json:"tenant_id,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
}

type RecordPage struct {
	Items      []LocalRecord `json:"items"`
	Total      int           `json:"total"`
	Limit      int           `json:"limit"`
	Offset     int           `json:"offset"`
	HasMore    bool          `json:"has_more"`
	NextCursor string        `json:"next_cursor,omitempty"`
	Source     string        `json:"source,omitempty"`
	TotalExact bool          `json:"total_exact"`
	Error      string        `json:"error,omitempty"`
}

// configFile is the root JSON document persisted in the app data dir.
// It intentionally contains identity/settings only. Records live in
// a local Pebble store so list/search paths don't load every record
// into memory on startup.
type configFile struct {
	Identity *Identity     `json:"identity,omitempty"`
	Settings Settings      `json:"settings"`
	Records  []LocalRecord `json:"records"`
}

type recordEvent struct {
	Op       string      `json:"op"`
	RecordID string      `json:"record_id,omitempty"`
	Record   LocalRecord `json:"record,omitempty"`
}

// store serialises config and record mutations through a mutex. Config
// remains a tiny JSON file; records use a Pebble-backed local index.
type store struct {
	mu          sync.Mutex
	root        *os.Root
	configName  string
	recordsName string
	data        configFile
	records     *localRecordDB
}

func defaultSettings() Settings {
	return Settings{
		ServerURL:       "http://127.0.0.1:8080",
		ServerTransport: serverTransportHTTP,
		DefaultMedia:    "application/octet-stream",
		DefaultEvent:    "file.snapshot",
		Theme:           "auto",
	}
}

func newStore(path string) (*store, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(filepath.Dir(abs))
	if err != nil {
		return nil, err
	}
	configName, err := cleanRootRelativePath(filepath.Base(abs))
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	recordsDBPath := filepath.Join(root.Name(), configName+".records.pebble")
	records, err := openLocalRecordDB(recordsDBPath)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	s := &store{
		root:        root,
		configName:  configName,
		recordsName: configName + ".records.jsonl",
		data:        configFile{Settings: defaultSettings()},
		records:     records,
	}
	if err := s.load(); err != nil {
		_ = records.close()
		_ = root.Close()
		return nil, err
	}
	return s, nil
}

func (s *store) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	loaded := configFile{Settings: defaultSettings()}
	raw, err := s.root.ReadFile(s.configName)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	} else if len(raw) > 0 {
		originalRaw := raw
		raw = bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &loaded); err != nil {
				s.quarantineCorruptLocked(originalRaw)
				loaded = configFile{Settings: defaultSettings()}
			}
		}
	}
	if loaded.Settings.ServerURL == "" {
		defaults := defaultSettings()
		loaded.Settings.ServerURL = defaults.ServerURL
	}
	loaded.Settings.ServerTransport = normalizeServerTransport(loaded.Settings.ServerTransport)
	if loaded.Settings.DefaultMedia == "" {
		loaded.Settings.DefaultMedia = "application/octet-stream"
	}
	if loaded.Settings.DefaultEvent == "" {
		loaded.Settings.DefaultEvent = "file.snapshot"
	}
	if loaded.Settings.Theme == "" {
		loaded.Settings.Theme = "auto"
	}
	s.data = loaded
	if err := s.migrateLegacyRecordsLocked(loaded.Records); err != nil {
		return err
	}
	s.data.Records = nil
	return nil
}

func (s *store) quarantineCorruptLocked(raw []byte) {
	if len(raw) == 0 {
		return
	}
	backup := fmt.Sprintf("%s.bad-%s", s.configName, time.Now().UTC().Format("20060102T150405.000000000Z"))
	if err := s.root.Rename(s.configName, backup); err == nil {
		return
	}
	_ = s.root.WriteFile(backup, raw, 0o600)
}

func (s *store) persistLocked() error {
	cfg := s.data
	cfg.Records = nil
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomicRoot(s.root, s.configName, raw, 0o600)
}

func (s *store) close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return errors.Join(s.records.close(), s.root.Close())
}

func (s *store) snapshot() configFile {
	s.mu.Lock()
	defer s.mu.Unlock()
	records, _ := s.records.listAll()
	out := configFile{
		Settings: s.data.Settings,
		Records:  records,
	}
	if s.data.Identity != nil {
		id := *s.data.Identity
		out.Identity = &id
	}
	return out
}

func (s *store) getIdentity() *Identity {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Identity == nil {
		return nil
	}
	id := *s.data.Identity
	return &id
}

func (s *store) setIdentity(id Identity) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := id
	s.data.Identity = &cp
	return s.persistLocked()
}

func (s *store) clearIdentity() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Identity = nil
	return s.persistLocked()
}

func (s *store) getSettings() Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.Settings
}

func (s *store) setSettings(cfg Settings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg.ServerTransport = normalizeServerTransport(cfg.ServerTransport)
	if cfg.DefaultMedia == "" {
		cfg.DefaultMedia = "application/octet-stream"
	}
	if cfg.DefaultEvent == "" {
		cfg.DefaultEvent = "file.snapshot"
	}
	if cfg.Theme == "" {
		cfg.Theme = "auto"
	}
	s.data.Settings = cfg
	return s.persistLocked()
}

func (s *store) listRecords() []LocalRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	records, err := s.records.listAll()
	if err != nil {
		return nil
	}
	return records
}

func (s *store) listRecordsPage(opts RecordPageOptions) RecordPage {
	s.mu.Lock()
	defer s.mu.Unlock()
	page, err := s.records.listPage(opts)
	if err != nil {
		return RecordPage{Limit: opts.Limit, Offset: opts.Offset, Source: "local", Error: err.Error()}
	}
	return page
}

func (s *store) getRecord(recordID string) (LocalRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok, err := s.records.get(recordID)
	if err != nil || !ok {
		return LocalRecord{}, false
	}
	return rec, true
}

// upsertRecord replaces an existing record (by record_id) or prepends
// a new one so the UI naturally shows the most recent submissions at
// the top of the list without needing a separate sort step.
func (s *store) upsertRecord(r LocalRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.records.upsert(r)
}

func (s *store) deleteRecord(recordID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.records.delete(recordID)
}

func (s *store) migrateLegacyRecordsLocked(configRecords []LocalRecord) error {
	migrated, err := s.records.migrated()
	if err != nil || migrated {
		return err
	}
	byID := make(map[string]LocalRecord, len(configRecords))
	for _, rec := range configRecords {
		if rec.RecordID != "" {
			byID[rec.RecordID] = rec
		}
	}
	if err := s.loadLegacyRecordLogLocked(byID); err != nil {
		return err
	}
	records := make([]LocalRecord, 0, len(byID))
	for _, rec := range byID {
		records = append(records, rec)
	}
	if len(records) > 0 {
		if err := s.records.upsertMany(records); err != nil {
			return err
		}
	}
	return s.records.markMigrated()
}

func (s *store) loadLegacyRecordLogLocked(records map[string]LocalRecord) error {
	f, err := s.root.Open(s.recordsName)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer f.Close()
	reader := bufio.NewReader(f)
	for {
		line, err := reader.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 {
			var ev recordEvent
			if unmarshalErr := json.Unmarshal(bytes.TrimSpace(line), &ev); unmarshalErr == nil {
				switch ev.Op {
				case "upsert":
					if ev.Record.RecordID != "" {
						records[ev.Record.RecordID] = ev.Record
					}
				case "delete":
					delete(records, ev.RecordID)
				}
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func recordMatchesQuery(r LocalRecord, q string) bool {
	return strings.Contains(strings.ToLower(r.FileName), q) ||
		strings.Contains(strings.ToLower(r.FilePath), q) ||
		strings.Contains(strings.ToLower(r.RecordID), q) ||
		strings.Contains(strings.ToLower(r.ContentHashHex), q) ||
		strings.Contains(strings.ToLower(r.BatchID), q) ||
		strings.Contains(strings.ToLower(r.EventType), q)
}
