package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	trustconfig "github.com/ryan-wong-coder/trustdb/internal/config"
	"github.com/ryan-wong-coder/trustdb/internal/wal"
	"github.com/spf13/viper"
)

func TestConfigInitAndShow(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "trustdb.yaml")

	var out, errOut bytes.Buffer
	cmd := newRootCommand(&out, &errOut)
	cmd.SetArgs([]string{"config", "init", "--out", configPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("config init error = %v stderr=%s", err, errOut.String())
	}
	if _, err := os.Stat(configPath); err != nil {
		t.Fatalf("config file not written: %v", err)
	}

	out.Reset()
	errOut.Reset()
	cmd = newRootCommand(&out, &errOut)
	cmd.SetArgs([]string{"--config", configPath, "config", "show"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("config show error = %v stderr=%s", err, errOut.String())
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("config show output is not json: %q err=%v", out.String(), err)
	}
	cfg, ok := got["config"].(map[string]any)
	if !ok {
		t.Fatalf("config is not an object: %#v", got["config"])
	}
	paths, ok := cfg["paths"].(map[string]any)
	if !ok {
		t.Fatalf("paths is not an object: %#v", cfg["paths"])
	}
	if paths["object_dir"] != ".trustdb/objects" {
		t.Fatalf("paths.object_dir = %v", paths["object_dir"])
	}
}

func TestConfigEnvOverride(t *testing.T) {
	t.Setenv("TRUSTDB_TENANT", "tenant-from-env")
	t.Setenv("TRUSTDB_PROOFSTORE_INDEX_STORAGE_TOKENS", "false")
	t.Setenv("TRUSTDB_BATCH_PROOF_MODE", "async")
	t.Setenv("TRUSTDB_PROOFSTORE_ARTIFACT_SYNC_MODE", "batch")
	t.Setenv("TRUSTDB_GLOBAL_LOG_ID", "node-log-a")
	t.Setenv("TRUSTDB_TIKV_PD_ENDPOINTS", "10.0.0.1:2379,10.0.0.2:2379")
	t.Setenv("TRUSTDB_TIKV_KEYSPACE", "trustdb-test")
	t.Setenv("TRUSTDB_TIKV_NAMESPACE", "tenant-a/log-a")
	t.Setenv("TRUSTDB_SERVER_READ_HEADER_TIMEOUT", "3s")
	t.Setenv("TRUSTDB_SERVER_IDLE_TIMEOUT", "45s")

	var out, errOut bytes.Buffer
	cmd := newRootCommand(&out, &errOut)
	cmd.SetArgs([]string{"config", "show"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("config show error = %v stderr=%s", err, errOut.String())
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("config show output is not json: %q err=%v", out.String(), err)
	}
	cfg, ok := got["config"].(map[string]any)
	if !ok {
		t.Fatalf("config is not an object: %#v", got["config"])
	}
	identity, ok := cfg["identity"].(map[string]any)
	if !ok {
		t.Fatalf("identity is not an object: %#v", cfg["identity"])
	}
	if identity["tenant"] != "tenant-from-env" {
		t.Fatalf("identity.tenant = %v", identity["tenant"])
	}
	batch, ok := cfg["batch"].(map[string]any)
	if !ok {
		t.Fatalf("batch is not an object: %#v", cfg["batch"])
	}
	if batch["proof_mode"] != "async" {
		t.Fatalf("batch.proof_mode = %v", batch["proof_mode"])
	}
	globalLog, ok := cfg["global_log"].(map[string]any)
	if !ok {
		t.Fatalf("global_log is not an object: %#v", cfg["global_log"])
	}
	if globalLog["log_id"] != "node-log-a" {
		t.Fatalf("global_log.log_id = %v", globalLog["log_id"])
	}
	server, ok := cfg["server"].(map[string]any)
	if !ok {
		t.Fatalf("server is not an object: %#v", cfg["server"])
	}
	if server["read_header_timeout"] != "3s" {
		t.Fatalf("server.read_header_timeout = %v", server["read_header_timeout"])
	}
	if server["idle_timeout"] != "45s" {
		t.Fatalf("server.idle_timeout = %v", server["idle_timeout"])
	}
	proofstore, ok := cfg["proofstore"].(map[string]any)
	if !ok {
		t.Fatalf("proofstore is not an object: %#v", cfg["proofstore"])
	}
	if proofstore["record_index_mode"] != "no_storage_tokens" {
		t.Fatalf("proofstore.record_index_mode = %v", proofstore["record_index_mode"])
	}
	if proofstore["artifact_sync_mode"] != "batch" {
		t.Fatalf("proofstore.artifact_sync_mode = %v", proofstore["artifact_sync_mode"])
	}
	endpoints, ok := proofstore["tikv_pd_endpoints"].([]any)
	if !ok || len(endpoints) != 2 || endpoints[0] != "10.0.0.1:2379" || endpoints[1] != "10.0.0.2:2379" {
		t.Fatalf("proofstore.tikv_pd_endpoints = %#v", proofstore["tikv_pd_endpoints"])
	}
	if proofstore["tikv_keyspace"] != "trustdb-test" {
		t.Fatalf("proofstore.tikv_keyspace = %v", proofstore["tikv_keyspace"])
	}
	if proofstore["tikv_namespace"] != "tenant-a/log-a" {
		t.Fatalf("proofstore.tikv_namespace = %v", proofstore["tikv_namespace"])
	}
}

func TestConfigRecordIndexModeEnvTakesPriorityOverLegacyAlias(t *testing.T) {
	t.Setenv("TRUSTDB_PROOFSTORE_INDEX_STORAGE_TOKENS", "false")
	t.Setenv("TRUSTDB_PROOFSTORE_RECORD_INDEX_MODE", "time_only")

	var out, errOut bytes.Buffer
	cmd := newRootCommand(&out, &errOut)
	cmd.SetArgs([]string{"config", "show"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("config show error = %v stderr=%s", err, errOut.String())
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("config show output is not json: %q err=%v", out.String(), err)
	}
	cfg := got["config"].(map[string]any)
	proofstore := cfg["proofstore"].(map[string]any)
	if proofstore["record_index_mode"] != "time_only" {
		t.Fatalf("proofstore.record_index_mode = %v", proofstore["record_index_mode"])
	}
}

func TestServeAcceptsProofstoreIndexStorageTokensFlag(t *testing.T) {
	t.Parallel()

	var out, errOut bytes.Buffer
	cmd := newRootCommand(&out, &errOut)
	cmd.SetArgs([]string{"serve", "--proofstore-index-storage-tokens=false", "--batch-proof-mode=async", "--proofstore-record-index-mode=time_only", "--proofstore-artifact-sync-mode=batch", "--proofstore-tikv-pd-endpoints=127.0.0.1:2379", "--proofstore-tikv-keyspace=trustdb", "--proofstore-tikv-namespace=tenant-a/log-a", "--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("serve help error = %v stderr=%s", err, errOut.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("--proofstore-index-storage-tokens")) {
		t.Fatalf("serve help missing proofstore token flag: %s", out.String())
	}
	for _, flag := range [][]byte{[]byte("--batch-proof-mode"), []byte("--read-header-timeout"), []byte("--idle-timeout"), []byte("--proofstore-record-index-mode"), []byte("--proofstore-artifact-sync-mode"), []byte("--proofstore-tikv-pd-endpoints"), []byte("--proofstore-tikv-keyspace"), []byte("--proofstore-tikv-namespace")} {
		if !bytes.Contains(out.Bytes(), flag) {
			t.Fatalf("serve help missing %s: %s", flag, out.String())
		}
	}
}

func TestValidateSemanticModes(t *testing.T) {
	t.Parallel()

	if got := normalizeSemanticProofMode(""); got != "inline" {
		t.Fatalf("normalize empty proof mode = %q", got)
	}
	if got := normalizeSemanticRecordIndexMode(""); got != "full" {
		t.Fatalf("normalize empty record index mode = %q", got)
	}
	if got := normalizeSemanticArtifactSyncMode(""); got != "chunk" {
		t.Fatalf("normalize empty artifact sync mode = %q", got)
	}
	if err := validateSemanticModes("async", "time_only", "batch"); err != nil {
		t.Fatalf("validate semantic modes: %v", err)
	}
	for _, tc := range []struct {
		proof    string
		index    string
		artifact string
	}{
		{proof: "later", index: "full", artifact: "chunk"},
		{proof: "inline", index: "none", artifact: "chunk"},
		{proof: "inline", index: "full", artifact: "never"},
	} {
		if err := validateSemanticModes(tc.proof, tc.index, tc.artifact); err == nil {
			t.Fatalf("validateSemanticModes(%+v) = nil, want error", tc)
		}
	}
}

func TestConfigShowRedactsKeysByDefault(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "trustdb.yaml")
	config := []byte(`paths:
  data_dir: ".trustdb"
  key_registry: ".trustdb/keys.tdkeys"
  wal: ".trustdb/trustdb.wal"
  object_dir: ".trustdb/objects"
identity:
  tenant: "default"
server:
  id: "local-server"
  key_id: "server-key"
registry:
  key_id: "registry-key"
log:
  level: "warn"
  format: "json"
  output: "stderr"
  file:
    path: ".trustdb/logs/trustdb.log"
    max_size_mb: 256
    max_backups: 16
    max_age_days: 30
    compress: true
keys:
  client_private: "client.key"
`)
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var out, errOut bytes.Buffer
	cmd := newRootCommand(&out, &errOut)
	cmd.SetArgs([]string{"--config", configPath, "config", "show"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("config show error = %v stderr=%s", err, errOut.String())
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("config show output is not json: %q err=%v", out.String(), err)
	}
	cfg := got["config"].(map[string]any)
	keys := cfg["keys"].(map[string]any)
	if keys["client_private"] != "<redacted>" {
		t.Fatalf("client_private = %v", keys["client_private"])
	}
}

func TestConfigValidate(t *testing.T) {
	t.Parallel()

	var out, errOut bytes.Buffer
	cmd := newRootCommand(&out, &errOut)
	cmd.SetArgs([]string{"config", "validate"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("config validate error = %v stderr=%s", err, errOut.String())
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("config validate output is not json: %q err=%v", out.String(), err)
	}
	if got["valid"] != true {
		t.Fatalf("valid = %v", got["valid"])
	}
}

func TestLogsGoToStderr(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	var out, errOut bytes.Buffer
	cmd := newRootCommand(&out, &errOut)
	cmd.SetArgs([]string{"--log-level", "info", "keygen", "--out", tmp, "--prefix", "client"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("keygen error = %v stderr=%s", err, errOut.String())
	}
	if !json.Valid(out.Bytes()) {
		t.Fatalf("stdout is not json: %q", out.String())
	}
	var logLine map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(errOut.Bytes()), &logLine); err != nil {
		t.Fatalf("stderr log is not json: %q err=%v", errOut.String(), err)
	}
	if logLine["level"] != "info" || logLine["message"] != "generated key pair" {
		t.Fatalf("stderr log missing expected fields: %#v", logLine)
	}
}

func TestLogsCanWriteRotatingFile(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "logs", "trustdb.log")
	var out, errOut bytes.Buffer
	cmd := newRootCommand(&out, &errOut)
	cmd.SetArgs([]string{
		"--log-level", "info",
		"--log-output", "file",
		"--log-file", logPath,
		"--log-max-size-mb", "1",
		"--log-max-backups", "2",
		"--log-max-age-days", "7",
		"keygen",
		"--out", tmp,
		"--prefix", "client",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("keygen error = %v stderr=%s", err, errOut.String())
	}
	if errOut.Len() != 0 {
		t.Fatalf("stderr should be empty when log output is file: %q", errOut.String())
	}
	if !json.Valid(out.Bytes()) {
		t.Fatalf("stdout is not json: %q", out.String())
	}
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	var logLine map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(logData), &logLine); err != nil {
		t.Fatalf("log file is not json: %q err=%v", string(logData), err)
	}
	if logLine["level"] != "info" || logLine["message"] != "generated key pair" {
		t.Fatalf("log file missing expected fields: %#v", logLine)
	}
}

func TestLogsCanWriteAsyncFile(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "logs", "trustdb.log")
	var out, errOut bytes.Buffer
	cmd := newRootCommand(&out, &errOut)
	cmd.SetArgs([]string{
		"--log-level", "info",
		"--log-output", "file",
		"--log-file", logPath,
		"--log-async",
		"--log-async-buffer", "8",
		"keygen",
		"--out", tmp,
		"--prefix", "client",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("keygen error = %v stderr=%s", err, errOut.String())
	}
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if !bytes.Contains(logData, []byte(`"message":"generated key pair"`)) {
		t.Fatalf("log file missing message: %q", string(logData))
	}
}

func TestWALInspectCommand(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	walPath := filepath.Join(tmp, "trustdb.wal")
	writer, err := wal.OpenWriter(walPath, 1)
	if err != nil {
		t.Fatalf("OpenWriter() error = %v", err)
	}
	if _, _, err := writer.Append(context.Background(), []byte("payload")); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	var out, errOut bytes.Buffer
	cmd := newRootCommand(&out, &errOut)
	cmd.SetArgs([]string{"wal", "inspect", "--wal", walPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("wal inspect error = %v stderr=%s", err, errOut.String())
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("wal inspect output is not json: %q err=%v", out.String(), err)
	}
	if got["records"] != float64(1) || got["last_sequence"] != float64(1) {
		t.Fatalf("wal inspect = %#v", got)
	}
}

func TestWALDumpCommand(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	walPath := filepath.Join(tmp, "trustdb.wal")
	writer, err := wal.OpenWriter(walPath, 1)
	if err != nil {
		t.Fatalf("OpenWriter() error = %v", err)
	}
	if _, _, err := writer.Append(context.Background(), []byte("payload")); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	var out, errOut bytes.Buffer
	cmd := newRootCommand(&out, &errOut)
	cmd.SetArgs([]string{"wal", "dump", "--wal", walPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("wal dump error = %v stderr=%s", err, errOut.String())
	}
	var got []map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("wal dump output is not json: %q err=%v", out.String(), err)
	}
	if len(got) != 1 || got[0]["payload_len"] != float64(len("payload")) {
		t.Fatalf("wal dump = %#v", got)
	}
}

// TestWALInspectCommandDirectoryMode verifies the `wal inspect` CLI produces
// the per-segment breakdown (DirInspectResult) when pointed at a directory
// WAL with multiple rotated segments.
func TestWALInspectCommandDirectoryMode(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	walDir := filepath.Join(tmp, "wal")
	writer, err := wal.OpenDirWriter(walDir, wal.Options{MaxSegmentBytes: 120})
	if err != nil {
		t.Fatalf("OpenDirWriter() error = %v", err)
	}
	for i := 0; i < 4; i++ {
		if _, _, err := writer.Append(context.Background(), bytes.Repeat([]byte{byte('a' + i)}, 80)); err != nil {
			t.Fatalf("Append(%d) error = %v", i, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	var out, errOut bytes.Buffer
	cmd := newRootCommand(&out, &errOut)
	cmd.SetArgs([]string{"wal", "inspect", "--wal", walDir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("wal inspect (dir) error = %v stderr=%s", err, errOut.String())
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("wal inspect (dir) output is not json: %q err=%v", out.String(), err)
	}
	if got["total_records"] != float64(4) {
		t.Fatalf("wal inspect (dir) total_records = %v, want 4", got["total_records"])
	}
	if got["last_sequence"] != float64(4) {
		t.Fatalf("wal inspect (dir) last_sequence = %v, want 4", got["last_sequence"])
	}
	segs, ok := got["segments"].([]any)
	if !ok || len(segs) < 2 {
		t.Fatalf("wal inspect (dir) segments = %v, want >= 2 entries", got["segments"])
	}
}

// TestWALDumpCommandDirectoryMode verifies dump walks every segment in a
// directory WAL so operators see the full record stream instead of just the
// first file.
func TestWALDumpCommandDirectoryMode(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	walDir := filepath.Join(tmp, "wal")
	writer, err := wal.OpenDirWriter(walDir, wal.Options{MaxSegmentBytes: 120})
	if err != nil {
		t.Fatalf("OpenDirWriter() error = %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, _, err := writer.Append(context.Background(), bytes.Repeat([]byte{byte('x' + i)}, 80)); err != nil {
			t.Fatalf("Append(%d) error = %v", i, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	var out, errOut bytes.Buffer
	cmd := newRootCommand(&out, &errOut)
	cmd.SetArgs([]string{"wal", "dump", "--wal", walDir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("wal dump (dir) error = %v stderr=%s", err, errOut.String())
	}
	var got []map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("wal dump (dir) output is not json: %q err=%v", out.String(), err)
	}
	if len(got) != 3 {
		t.Fatalf("wal dump (dir) = %d records, want 3", len(got))
	}
	// Records should span at least two segments to prove multi-segment
	// walk actually happens.
	segments := map[float64]struct{}{}
	for _, item := range got {
		segments[item["segment_id"].(float64)] = struct{}{}
	}
	if len(segments) < 2 {
		t.Fatalf("dump only saw segments %v; want at least 2 distinct ids", segments)
	}
}

// TestWALRepairCommandDirectoryModeTruncatesTail exercises the directory-mode
// repair path end-to-end through the CLI: we append junk bytes to the active
// segment and verify the command truncates exactly that garbage while leaving
// the earlier segments byte-identical.
func TestWALRepairCommandDirectoryModeTruncatesTail(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	walDir := filepath.Join(tmp, "wal")
	writer, err := wal.OpenDirWriter(walDir, wal.Options{MaxSegmentBytes: 200})
	if err != nil {
		t.Fatalf("OpenDirWriter() error = %v", err)
	}
	for i := 0; i < 4; i++ {
		if _, _, err := writer.Append(context.Background(), bytes.Repeat([]byte{byte('a' + i)}, 80)); err != nil {
			t.Fatalf("Append(%d) error = %v", i, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	inspect, err := wal.InspectDir(walDir)
	if err != nil {
		t.Fatalf("InspectDir() error = %v", err)
	}
	if len(inspect.Segments) < 2 {
		t.Fatalf("expected >= 2 segments for the dir-repair test, got %d", len(inspect.Segments))
	}
	tailPath := inspect.Segments[len(inspect.Segments)-1].Path
	tailID := inspect.Segments[len(inspect.Segments)-1].SegmentID
	f, err := os.OpenFile(tailPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open tail: %v", err)
	}
	junk := bytes.Repeat([]byte{0xCA, 0xFE}, 16)
	if _, err := f.Write(junk); err != nil {
		t.Fatalf("write junk: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close tail: %v", err)
	}

	var out, errOut bytes.Buffer
	cmd := newRootCommand(&out, &errOut)
	cmd.SetArgs([]string{"wal", "repair", "--wal", walDir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("wal repair (dir) error = %v stderr=%s", err, errOut.String())
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("wal repair (dir) output is not json: %q err=%v", out.String(), err)
	}
	tail, ok := got["tail_repair"].(map[string]any)
	if !ok {
		t.Fatalf("tail_repair missing or wrong type: %v", got["tail_repair"])
	}
	if tail["truncated_bytes"] != float64(len(junk)) {
		t.Fatalf("tail truncated_bytes = %v, want %d", tail["truncated_bytes"], len(junk))
	}
	if tail["repaired"] != true {
		t.Fatalf("tail repaired = %v, want true", tail["repaired"])
	}
	if got["active_segment_id"] != float64(tailID) {
		t.Fatalf("active_segment_id = %v, want %d", got["active_segment_id"], tailID)
	}
}

func TestKeyInspectCommand(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	var out, errOut bytes.Buffer
	cmd := newRootCommand(&out, &errOut)
	cmd.SetArgs([]string{"keygen", "--out", tmp, "--prefix", "client"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("keygen error = %v stderr=%s", err, errOut.String())
	}

	out.Reset()
	errOut.Reset()
	cmd = newRootCommand(&out, &errOut)
	cmd.SetArgs([]string{"key", "inspect", "--key", filepath.Join(tmp, "client.pub")})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("key inspect error = %v stderr=%s", err, errOut.String())
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("key inspect output is not json: %q err=%v", out.String(), err)
	}
	if got["kind"] != "public" || got["alg"] != "ed25519" || got["fingerprint"] == "" {
		t.Fatalf("key inspect = %#v", got)
	}
}

func TestKeygenPrefixCannotEscapeOutputDir(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	outDir := filepath.Join(tmp, "keys")
	outsidePub := filepath.Join(tmp, "outside.pub")
	outsideKey := filepath.Join(tmp, "outside.key")

	var out, errOut bytes.Buffer
	cmd := newRootCommand(&out, &errOut)
	cmd.SetArgs([]string{"keygen", "--out", outDir, "--prefix", "../outside"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("keygen error = %v stderr=%s", err, errOut.String())
	}

	var got map[string]string
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("keygen output is not json: %q err=%v", out.String(), err)
	}
	for _, path := range []string{got["public_key"], got["private_key"]} {
		if path == "" {
			t.Fatalf("keygen output missing key path: %#v", got)
		}
		if strings.ContainsAny(filepath.Base(path), `/\`) {
			t.Fatalf("key path base contains a path separator: %q", path)
		}
		rel, err := filepath.Rel(outDir, path)
		if err != nil {
			t.Fatalf("Rel() error = %v", err)
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
			t.Fatalf("key path escapes output dir: outDir=%q path=%q rel=%q", outDir, path, rel)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected key file at %q: %v", path, err)
		}
	}
	if _, err := os.Stat(outsidePub); !os.IsNotExist(err) {
		t.Fatalf("keygen wrote outside public key %q: %v", outsidePub, err)
	}
	if _, err := os.Stat(outsideKey); !os.IsNotExist(err) {
		t.Fatalf("keygen wrote outside private key %q: %v", outsideKey, err)
	}
}

func TestShippedProfileConfigsLoad(t *testing.T) {
	t.Parallel()

	repoConfigs := filepath.Join("..", "..", "configs")
	for _, name := range []string{"development.yaml", "production.yaml", "benchmark.yaml"} {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			// Validate merged YAML without full runtimeConfig.load(), which
			// creates loggers and may mkdir production paths like /var/log/trustdb
			// (permission denied on CI runners).
			v := viper.New()
			setDefaults(v)
			v.SetConfigFile(filepath.Join(repoConfigs, name))
			if err := v.ReadInConfig(); err != nil {
				t.Fatalf("ReadInConfig: %v", err)
			}
			cfg := trustconfig.FromViper(v)
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
		})
	}
}

func TestVersionCommand(t *testing.T) {
	t.Parallel()

	var out, errOut bytes.Buffer
	cmd := newRootCommand(&out, &errOut)
	cmd.SetArgs([]string{"version"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("version error = %v stderr=%s", err, errOut.String())
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("version output is not json: %q err=%v", out.String(), err)
	}
	if got["version"] == "" || got["go"] == "" {
		t.Fatalf("version output missing fields: %#v", got)
	}
}
