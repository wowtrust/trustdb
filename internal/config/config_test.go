package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestDefaultConfigIsValid(t *testing.T) {
	t.Parallel()

	if err := Default().Validate(); err != nil {
		t.Fatalf("default config is invalid: %v", err)
	}
}

func TestDefaultYAMLIsStructured(t *testing.T) {
	t.Parallel()

	for _, section := range []string{"paths:", "identity:", "server:", "registry:", "batch:", "proofstore:", "log:", "keys:"} {
		if !strings.Contains(DefaultYAML, section) {
			t.Fatalf("default yaml missing section %q", section)
		}
	}
	if Default().Paths.WAL != ".trustdb/wal" {
		t.Fatalf("default paths.wal = %q, want directory path", Default().Paths.WAL)
	}
	if !strings.Contains(DefaultYAML, `wal: ".trustdb/wal"`) {
		t.Fatal("default yaml paths.wal is not a directory path")
	}
	if Default().Batch.ProofMode != "inline" {
		t.Fatalf("default batch.proof_mode = %q, want inline", Default().Batch.ProofMode)
	}
	if Default().Proofstore.ArtifactSyncMode != "chunk" {
		t.Fatalf("default proofstore.artifact_sync_mode = %q, want chunk", Default().Proofstore.ArtifactSyncMode)
	}
	if Default().Proofstore.RecordIndexMode != "full" {
		t.Fatalf("default proofstore.record_index_mode = %q, want full", Default().Proofstore.RecordIndexMode)
	}
	if Default().GlobalLog.LogID != "trustdb-global-log" {
		t.Fatalf("default global_log.log_id = %q, want trustdb-global-log", Default().GlobalLog.LogID)
	}
	if Default().Proofstore.TiKVPDAddresses != nil {
		t.Fatalf("default proofstore.tikv_pd_endpoints = %#v, want nil", Default().Proofstore.TiKVPDAddresses)
	}
	if Default().Proofstore.TiKVNamespace != "default" {
		t.Fatalf("default proofstore.tikv_namespace = %q, want default", Default().Proofstore.TiKVNamespace)
	}
	if !strings.Contains(DefaultYAML, `read_header_timeout: "5s"`) {
		t.Fatal("default yaml missing server.read_header_timeout")
	}
	if !strings.Contains(DefaultYAML, `idle_timeout: "120s"`) {
		t.Fatal("default yaml missing server.idle_timeout")
	}
	if !strings.Contains(DefaultYAML, `poll_interval: "2s"`) {
		t.Fatal("default yaml missing anchor.poll_interval")
	}
	if Default().Server.ReadHeaderTimeout != "5s" {
		t.Fatalf("default server.read_header_timeout = %q, want 5s", Default().Server.ReadHeaderTimeout)
	}
	if Default().Server.IdleTimeout != "120s" {
		t.Fatalf("default server.idle_timeout = %q, want 120s", Default().Server.IdleTimeout)
	}
}

func TestFromViperDefaultsMissingAnchorPollInterval(t *testing.T) {
	t.Parallel()

	cfg := FromViper(viper.New())
	if cfg.Anchor.PollInterval != "2s" {
		t.Fatalf("anchor.poll_interval = %q, want 2s", cfg.Anchor.PollInterval)
	}
}

func TestValidateRejectsInvalidLogConfig(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.Log.Format = "console"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate rejected console log format: %v", err)
	}

	cfg = Default()
	cfg.Log.Level = "trace"
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted invalid log level")
	}

	cfg = Default()
	cfg.Log.Format = "pretty"
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted invalid log format")
	}

	cfg = Default()
	cfg.Log.Output = "syslog"
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted invalid log output")
	}

	cfg = Default()
	cfg.Log.Output = "file"
	cfg.Log.File.Path = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted file output without file path")
	}

	cfg = Default()
	cfg.Log.File.MaxSizeMB = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted invalid log max size")
	}

	cfg = Default()
	cfg.Log.Async.BufferSize = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted invalid async log buffer size")
	}
}

func TestValidateRejectsInvalidBatchConfig(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.Batch.QueueSize = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted invalid batch queue size")
	}

	cfg = Default()
	cfg.Batch.MaxRecords = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted invalid batch max records")
	}

	cfg = Default()
	cfg.Batch.MaxDelay = "soon"
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted invalid batch max delay")
	}

	cfg = Default()
	cfg.Batch.ProofMode = "eventually"
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted invalid batch proof mode")
	}
}

func TestValidateRejectsInvalidDurationBounds(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{
			name: "negative read timeout",
			mutate: func(c *Config) {
				c.Server.ReadTimeout = "-1s"
			},
			want: "server.read_timeout",
		},
		{
			name: "negative read header timeout",
			mutate: func(c *Config) {
				c.Server.ReadHeaderTimeout = "-1s"
			},
			want: "server.read_header_timeout",
		},
		{
			name: "negative idle timeout",
			mutate: func(c *Config) {
				c.Server.IdleTimeout = "-1s"
			},
			want: "server.idle_timeout",
		},
		{
			name: "zero batch max delay",
			mutate: func(c *Config) {
				c.Batch.MaxDelay = "0s"
			},
			want: "batch.max_delay",
		},
		{
			name: "zero anchor max delay",
			mutate: func(c *Config) {
				c.Anchor.MaxDelay = "0s"
			},
			want: "anchor.max_delay",
		},
		{
			name: "zero anchor poll interval",
			mutate: func(c *Config) {
				c.Anchor.PollInterval = "0s"
			},
			want: "anchor.poll_interval",
		},
		{
			name: "zero admin session ttl",
			mutate: func(c *Config) {
				webDir := testAdminWebDir(t)
				c.Admin = Admin{
					Enabled:       true,
					BasePath:      "/admin",
					Username:      "op",
					PasswordHash:  "$2a$10$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
					SessionSecret: strings.Repeat("s", 32),
					WebDir:        webDir,
					SessionTTL:    "0s",
				}
			},
			want: "admin.session_ttl",
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			tc.mutate(&cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestValidateAllowsZeroServerTimeouts(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.Server.ReadTimeout = "0s"
	cfg.Server.ReadHeaderTimeout = "0s"
	cfg.Server.WriteTimeout = "0s"
	cfg.Server.IdleTimeout = "0s"
	cfg.Server.ShutdownTimeout = "0s"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate rejected zero server network timeouts: %v", err)
	}
}

func testAdminWebDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestValidateRejectsInvalidProofstoreConfig(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.Proofstore.ArtifactSyncMode = "sometimes"
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted invalid proofstore artifact sync mode")
	}

	cfg = Default()
	cfg.Proofstore.RecordIndexMode = "none"
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted invalid proofstore record index mode")
	}
}

func TestValidateRunProfileAliases(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"", "development", "DEV", "single_node_production", "prod", "benchmark", "bench"} {
		raw := raw
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			cfg := Default()
			cfg.RunProfile = raw
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
		})
	}
}

func TestValidateRunProfileRejectsUnknown(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.RunProfile = "staging"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for unknown run_profile")
	}
}

func TestRedactedHidesKeyPaths(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.Keys.ClientPrivate = "client.key"
	cfg.Keys.ServerPublic = "server.pub"
	redacted := cfg.Redacted()
	if redacted.Keys.ClientPrivate != "<redacted>" {
		t.Fatalf("client private = %q", redacted.Keys.ClientPrivate)
	}
	if redacted.Keys.ServerPublic != "<redacted>" {
		t.Fatalf("server public = %q", redacted.Keys.ServerPublic)
	}
	if redacted.Paths.DataDir != cfg.Paths.DataDir {
		t.Fatalf("paths should not be redacted")
	}
}
