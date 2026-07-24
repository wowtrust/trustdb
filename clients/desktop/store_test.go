package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestStoreLoadMissingConfigUsesDefaults(t *testing.T) {
	t.Parallel()

	store, err := newStore(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatalf("newStore missing config: %v", err)
	}
	defer store.close()
	cfg := store.getSettings()
	if cfg.ServerURL != "http://127.0.0.1:8080" {
		t.Fatalf("ServerURL = %q, want default", cfg.ServerURL)
	}
	if cfg.ServerTransport != serverTransportHTTP {
		t.Fatalf("ServerTransport = %q, want http", cfg.ServerTransport)
	}
}

func TestOpenUserConfigRootCreatesMissingDirectoryUnderHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	base := filepath.Join(home, ".config", "trustdb-test")
	root, err := openUserConfigRoot(base)
	if err != nil {
		t.Fatalf("openUserConfigRoot() error = %v", err)
	}
	defer root.Close()
	if root.Name() != base {
		t.Fatalf("root.Name() = %q, want %q", root.Name(), base)
	}
}

func TestWriteFileAtomicIgnoresStaleFixedTempPath(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "proof.tdproof")
	staleFixedTmp := path + ".tmp"
	if err := os.Mkdir(staleFixedTmp, 0o755); err != nil {
		t.Fatalf("Mkdir(stale tmp): %v", err)
	}

	if err := writeFileAtomic(path, []byte("proof"), 0o644); err != nil {
		t.Fatalf("writeFileAtomic() error = %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != "proof" {
		t.Fatalf("file content = %q, want proof", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(path) error = %v", err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("file mode = %v, want 0644", info.Mode().Perm())
	}
	staleInfo, err := os.Stat(staleFixedTmp)
	if err != nil {
		t.Fatalf("stale fixed temp path missing: %v", err)
	}
	if !staleInfo.IsDir() {
		t.Fatalf("stale fixed temp path was modified; isDir=false")
	}
}

func TestWriteFileAtomicRejectsDirectoryTarget(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "proof.tdproof")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("Mkdir(target) error = %v", err)
	}

	if err := writeFileAtomic(path, []byte("proof"), 0o644); err == nil {
		t.Fatalf("writeFileAtomic() error = nil, want directory target error")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(target) error = %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("target directory was replaced")
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp"))
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files were not cleaned up: %v", matches)
	}
}

func TestWriteFileAtomicRejectsSymlinkOutsideParent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.tdproof")
	if err := os.WriteFile(outside, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "proof.tdproof")
	if err := os.Symlink(outside, target); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := writeFileAtomic(target, []byte("replaced"), 0o644); err == nil {
		t.Fatal("writeFileAtomic() error = nil, want symlink escape error")
	}
	got, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "original" {
		t.Fatalf("outside file = %q, want original", got)
	}
}

func TestWriteAuthorizedFileRequiresNativeSelection(t *testing.T) {
	t.Parallel()

	app := NewApp()
	path := filepath.Join(t.TempDir(), "proof.tdproof")
	if err := app.writeAuthorizedFile(path, []byte("proof"), 0o644); err == nil {
		t.Fatal("writeAuthorizedFile() accepted an unselected path")
	}
	authorized, err := app.rememberSavePath(path)
	if err != nil {
		t.Fatalf("rememberSavePath() error = %v", err)
	}
	if err := app.writeAuthorizedFile(authorized, []byte("proof"), 0o644); err != nil {
		t.Fatalf("writeAuthorizedFile() error = %v", err)
	}
	if err := app.writeAuthorizedFile(authorized, []byte("again"), 0o644); err == nil {
		t.Fatal("writeAuthorizedFile() reused a consumed path authorization")
	}
}

func TestStorePersistIgnoresStaleFixedTempPath(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.json")
	staleFixedTmp := path + ".tmp"
	if err := os.Mkdir(staleFixedTmp, 0o755); err != nil {
		t.Fatalf("Mkdir(stale tmp): %v", err)
	}

	store, err := newStore(path)
	if err != nil {
		t.Fatalf("newStore: %v", err)
	}
	defer store.close()
	settings := defaultSettings()
	settings.ServerURL = "http://127.0.0.1:9090"
	if err := store.setSettings(settings); err != nil {
		t.Fatalf("setSettings() error = %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(config): %v", err)
	}
	if !bytes.Contains(raw, []byte(`"server_url": "http://127.0.0.1:9090"`)) {
		t.Fatalf("persisted config missing server_url: %s", raw)
	}
	staleInfo, err := os.Stat(staleFixedTmp)
	if err != nil {
		t.Fatalf("stale fixed temp path missing: %v", err)
	}
	if !staleInfo.IsDir() {
		t.Fatalf("stale fixed temp path was modified; isDir=false")
	}
}

func TestStoreRejectsConfigSymlinkOutsideRoot(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(outside, []byte(`{"settings":{"server_url":"http://outside.invalid"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	if err := os.Symlink(outside, path); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	store, err := newStore(path)
	if err == nil {
		_ = store.close()
		t.Fatal("newStore() followed a config symlink outside its root")
	}
}

func TestWailsRecordDTOsDoNotExposeTimeTime(t *testing.T) {
	t.Parallel()

	timeType := reflect.TypeOf(time.Time{})
	for _, typ := range []reflect.Type{
		reflect.TypeOf(LocalRecord{}),
		reflect.TypeOf(RecordPage{}),
		reflect.TypeOf(SubmitResult{}),
	} {
		assertNoTimeTimeFields(t, typ, timeType)
	}
}

func assertNoTimeTimeFields(t *testing.T, typ, timeType reflect.Type) {
	t.Helper()
	if typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ == timeType {
		t.Fatalf("%s exposes time.Time to Wails bindings", typ)
	}
	if typ.Kind() != reflect.Struct {
		return
	}
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		ft := field.Type
		for ft.Kind() == reflect.Pointer || ft.Kind() == reflect.Slice {
			ft = ft.Elem()
		}
		if ft == timeType {
			t.Fatalf("%s.%s exposes time.Time to Wails bindings", typ, field.Name)
		}
	}
}

func TestStoreLoadAcceptsUTF8BOM(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.json")
	raw := append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{
		"settings": {
			"server_url": "http://127.0.0.1:8081",
			"server_public_key_b64": "scLtBGCbub07etjZBg5VSAjung1pO1UZLtXHwILIdEM",
			"default_media_type": "application/octet-stream",
			"default_event_type": "file.snapshot",
			"theme": "auto"
		},
		"records": []
	}`)...)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	store, err := newStore(path)
	if err != nil {
		t.Fatalf("newStore: %v", err)
	}
	defer store.close()
	cfg := store.getSettings()
	if cfg.ServerURL != "http://127.0.0.1:8081" {
		t.Fatalf("ServerURL = %q, want 8081", cfg.ServerURL)
	}
	if cfg.ServerTransport != serverTransportHTTP {
		t.Fatalf("ServerTransport = %q, want http", cfg.ServerTransport)
	}
}

func TestStoreLoadCorruptConfigQuarantinesAndUsesDefaults(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte("{not-json"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	store, err := newStore(path)
	if err != nil {
		t.Fatalf("newStore corrupt config: %v", err)
	}
	defer store.close()
	cfg := store.getSettings()
	if cfg.ServerURL != "http://127.0.0.1:8080" {
		t.Fatalf("ServerURL = %q, want default", cfg.ServerURL)
	}
	backups, err := filepath.Glob(path + ".bad-*")
	if err != nil {
		t.Fatalf("glob backups: %v", err)
	}
	if len(backups) != 1 {
		t.Fatalf("backup count = %d, want 1", len(backups))
	}
}

func TestStoreRecordsUsePebblePaginationAndPersistence(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.json")
	store, err := newStore(path)
	if err != nil {
		t.Fatalf("newStore: %v", err)
	}
	for _, rec := range []LocalRecord{
		testLocalRecord("rec-1", 100, "L3", "notes.txt"),
		testLocalRecord("rec-2", 200, "L4", "payload-2.txt"),
		testLocalRecord("rec-3", 300, "L5", "screenshot-final.png"),
	} {
		if err := store.upsertRecord(rec); err != nil {
			t.Fatalf("upsert %s: %v", rec.RecordID, err)
		}
	}
	first := store.listRecordsPage(RecordPageOptions{Limit: 2})
	if len(first.Items) != 2 || first.Items[0].RecordID != "rec-3" || first.Items[1].RecordID != "rec-2" || first.NextCursor == "" {
		t.Fatalf("first page = %+v", first)
	}
	next := store.listRecordsPage(RecordPageOptions{Limit: 2, Offset: 2, Cursor: first.NextCursor})
	if len(next.Items) != 1 || next.Items[0].RecordID != "rec-1" || next.HasMore {
		t.Fatalf("next page = %+v", next)
	}
	search := store.listRecordsPage(RecordPageOptions{Limit: 10, Query: "shot-final"})
	if len(search.Items) != 1 || search.Items[0].RecordID != "rec-3" {
		t.Fatalf("search page = %+v", search)
	}
	if err := store.close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := newStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.close()
	got, ok := reopened.getRecord("rec-2")
	if !ok || got.FileName != "payload-2.txt" {
		t.Fatalf("reopened record ok=%v got=%+v", ok, got)
	}
}

func TestStoreMigratesLegacyRecordsJSONLIntoPebble(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	cfg := configFile{
		Settings: defaultSettings(),
		Records:  []LocalRecord{testLocalRecord("rec-old", 100, "L3", "old.txt")},
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	legacyEvents := []recordEvent{
		{Op: "upsert", RecordID: "rec-new", Record: testLocalRecord("rec-new", 200, "L5", "legacy-payload.txt")},
		{Op: "delete", RecordID: "rec-old"},
	}
	f, err := os.Create(path + ".records.jsonl")
	if err != nil {
		t.Fatalf("create legacy log: %v", err)
	}
	enc := json.NewEncoder(f)
	for _, ev := range legacyEvents {
		if err := enc.Encode(ev); err != nil {
			_ = f.Close()
			t.Fatalf("write legacy event: %v", err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close legacy log: %v", err)
	}

	store, err := newStore(path)
	if err != nil {
		t.Fatalf("newStore: %v", err)
	}
	defer store.close()
	if _, ok := store.getRecord("rec-old"); ok {
		t.Fatalf("deleted legacy record was migrated")
	}
	got, ok := store.getRecord("rec-new")
	if !ok || got.FileName != "legacy-payload.txt" {
		t.Fatalf("migrated record ok=%v got=%+v", ok, got)
	}
	page := store.listRecordsPage(RecordPageOptions{Limit: 10, Query: "legacy-payload"})
	if len(page.Items) != 1 || page.Items[0].RecordID != "rec-new" {
		t.Fatalf("legacy search page = %+v", page)
	}
}

func testLocalRecord(recordID string, unixNano int64, level, name string) LocalRecord {
	rec := LocalRecord{
		RecordID:       recordID,
		FilePath:       "C:/tmp/" + name,
		FileName:       name,
		ContentHashHex: "0202020202020202020202020202020202020202020202020202020202020202",
		ContentLength:  42,
		ProofLevel:     level,
		BatchID:        "batch-1",
		TenantID:       "tenant-a",
		ClientID:       "client-a",
		EventType:      "file.snapshot",
	}
	setLocalRecordSubmittedAt(&rec, time.Unix(0, unixNano).UTC())
	return rec
}
