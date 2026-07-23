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

	for _, section := range []string{"paths:", "identity:", "server:", "nats:", "registry:", "batch:", "proofstore:", "log:", "keys:"} {
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
	if strings.Contains(DefaultYAML, "  poll_interval: \"2s\"\n  workers:") {
		t.Fatal("default yaml still exposes removed anchor.workers")
	}
	if Default().Anchor.MaxDelay != "5m" {
		t.Fatalf("default anchor.max_delay = %q, want 5m", Default().Anchor.MaxDelay)
	}
	if Default().Anchor.Plugin.StartTimeout != "10s" || Default().Anchor.Plugin.RPCTimeout != "30s" {
		t.Fatalf("default anchor plugin timeouts = %+v", Default().Anchor.Plugin)
	}
	if Default().Server.ReadHeaderTimeout != "5s" {
		t.Fatalf("default server.read_header_timeout = %q, want 5s", Default().Server.ReadHeaderTimeout)
	}
	if Default().Server.IdleTimeout != "120s" {
		t.Fatalf("default server.idle_timeout = %q, want 120s", Default().Server.IdleTimeout)
	}
	if Default().NATS.Enabled {
		t.Fatal("default nats.enabled = true, want false")
	}
	if !strings.Contains(DefaultYAML, "nats:\n  enabled: false") {
		t.Fatal("default yaml must keep NATS disabled")
	}
	if Default().NATS.Workers != 0 {
		t.Fatalf("default nats.workers = %d, want automatic sizing (0)", Default().NATS.Workers)
	}
	if Default().NATS.ResultStream != "TRUSTDB_INGRESS_RESULTS" || Default().NATS.ResultSubject != "trustdb.ingress.v1.results.*" || Default().NATS.ResultMaxAge != "24h" {
		t.Fatalf("default NATS result topology = %+v", Default().NATS)
	}
	if Default().NATS.DLQStream != "TRUSTDB_INGRESS_DLQ" || Default().NATS.DLQSubject != "trustdb.ingress.v1.dlq.*" || Default().NATS.DLQMaxAge != "0s" {
		t.Fatalf("default NATS DLQ topology = %+v", Default().NATS)
	}
}

func TestValidateAnchorPluginIsConditional(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.Anchor.Sink = "plugin"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "anchor.plugin.command") {
		t.Fatalf("Validate() error = %v, want plugin command requirement", err)
	}
	cfg.Anchor.Plugin.Command = "/usr/local/bin/trustdb-anchor"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() rejected configured plugin: %v", err)
	}
	cfg.Anchor.Plugin.RPCTimeout = "0s"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "anchor.plugin.rpc_timeout") {
		t.Fatalf("Validate() error = %v, want rpc timeout error", err)
	}
}

func TestValidateNATSIsConditional(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.NATS = NATS{Enabled: false}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate rejected disabled empty NATS config: %v", err)
	}

	cfg = Default()
	cfg.NATS.Enabled = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate rejected enabled default NATS config: %v", err)
	}
}

func TestValidateRejectsInvalidEnabledNATSConfig(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		mutate func(*NATS)
		want   string
	}{
		{name: "missing URLs", mutate: func(n *NATS) { n.URLs = nil }, want: "nats.urls"},
		{name: "unsupported URL", mutate: func(n *NATS) { n.URLs = []string{"http://127.0.0.1:4222"} }, want: "unsupported scheme"},
		{name: "URL credentials", mutate: func(n *NATS) { n.URLs = []string{"nats://user:pass@127.0.0.1:4222"} }, want: "must not contain credentials"},
		{name: "invalid stream", mutate: func(n *NATS) { n.Stream = "trustdb.ingress" }, want: "nats.stream"},
		{name: "wildcard subject", mutate: func(n *NATS) { n.Subject = "trustdb.ingress.*" }, want: "nats.subject"},
		{name: "invalid durable", mutate: func(n *NATS) { n.Durable = "trustdb.ingress" }, want: "nats.durable"},
		{name: "invalid storage", mutate: func(n *NATS) { n.StreamStorage = "disk" }, want: "nats.stream_storage"},
		{name: "zero replicas", mutate: func(n *NATS) { n.StreamReplicas = 0 }, want: "nats.stream_replicas"},
		{name: "too many replicas", mutate: func(n *NATS) { n.StreamReplicas = 6 }, want: "nats.stream_replicas"},
		{name: "zero stream bytes", mutate: func(n *NATS) { n.StreamMaxBytes = 0 }, want: "nats.stream_max_bytes"},
		{name: "negative max age", mutate: func(n *NATS) { n.StreamMaxAge = "-1s" }, want: "nats.stream_max_age"},
		{name: "duplicate result stream", mutate: func(n *NATS) { n.ResultStream = n.Stream }, want: "must be distinct"},
		{name: "duplicate DLQ stream", mutate: func(n *NATS) { n.DLQStream = n.ResultStream }, want: "must be distinct"},
		{name: "invalid result subject", mutate: func(n *NATS) { n.ResultSubject = "trustdb.results" }, want: "nats.result_subject"},
		{name: "invalid DLQ subject", mutate: func(n *NATS) { n.DLQSubject = "trustdb.dlq.>" }, want: "nats.dlq_subject"},
		{name: "overlapping outcome subjects", mutate: func(n *NATS) { n.DLQSubject = n.ResultSubject }, want: "must not overlap"},
		{name: "result overlaps ingress", mutate: func(n *NATS) { n.ResultSubject = "trustdb.ingress.v1.*" }, want: "must not overlap"},
		{name: "zero result bytes", mutate: func(n *NATS) { n.ResultMaxBytes = 0 }, want: "nats.result_max_bytes"},
		{name: "negative result max age", mutate: func(n *NATS) { n.ResultMaxAge = "-1s" }, want: "nats.result_max_age"},
		{name: "zero DLQ bytes", mutate: func(n *NATS) { n.DLQMaxBytes = 0 }, want: "nats.dlq_max_bytes"},
		{name: "negative DLQ max age", mutate: func(n *NATS) { n.DLQMaxAge = "-1s" }, want: "nats.dlq_max_age"},
		{name: "zero duplicate window", mutate: func(n *NATS) { n.DuplicateWindow = "0s" }, want: "nats.duplicate_window"},
		{name: "negative workers", mutate: func(n *NATS) { n.Workers = -1 }, want: "nats.workers"},
		{name: "workers exceed pending", mutate: func(n *NATS) { n.Workers = n.MaxAckPending + 1 }, want: "nats.workers"},
		{name: "zero fetch batch", mutate: func(n *NATS) { n.FetchBatch = 0 }, want: "nats.fetch_batch"},
		{name: "fetch exceeds pending", mutate: func(n *NATS) { n.FetchBatch = n.MaxAckPending + 1 }, want: "must not exceed"},
		{name: "zero max deliver", mutate: func(n *NATS) { n.MaxDeliver = 0 }, want: "nats.max_deliver"},
		{name: "invalid ack wait", mutate: func(n *NATS) { n.AckWait = "soon" }, want: "nats.ack_wait"},
		{name: "short fetch wait", mutate: func(n *NATS) { n.FetchWait = "999ms" }, want: "nats.fetch_wait"},
		{name: "zero nak delay", mutate: func(n *NATS) { n.NakDelay = "0s" }, want: "nats.nak_delay"},
		{name: "invalid outcome retry", mutate: func(n *NATS) { n.ResultRetryWait = "later" }, want: "nats.outcome_retry_wait"},
		{name: "invalid reconnects", mutate: func(n *NATS) { n.MaxReconnects = -2 }, want: "nats.max_reconnects"},
		{name: "password without username", mutate: func(n *NATS) { n.Password = "secret" }, want: "configured together"},
		{name: "multiple auth modes", mutate: func(n *NATS) { n.CredentialsFile = "/run/nats.creds"; n.Token = "secret" }, want: "mutually exclusive"},
		{name: "TLS cert without key", mutate: func(n *NATS) { n.TLS.CertFile = "/run/client.crt" }, want: "configured together"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := Default()
			cfg.NATS.Enabled = true
			tc.mutate(&cfg.NATS)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestFromViperMapsNATSConfig(t *testing.T) {
	t.Parallel()

	v := viper.New()
	v.Set("nats.enabled", true)
	v.Set("nats.urls", []string{"nats://one:4222", "tls://two:4222"})
	v.Set("nats.stream", "INGRESS")
	v.Set("nats.subject", "claims.ingress")
	v.Set("nats.durable", "worker-a")
	v.Set("nats.provision", true)
	v.Set("nats.stream_storage", "memory")
	v.Set("nats.stream_replicas", 3)
	v.Set("nats.stream_max_bytes", int64(1<<30))
	v.Set("nats.stream_max_age", "24h")
	v.Set("nats.result_stream", "RESULTS")
	v.Set("nats.result_subject", "claims.results.*")
	v.Set("nats.result_max_bytes", int64(2<<30))
	v.Set("nats.result_max_age", "12h")
	v.Set("nats.dlq_stream", "DLQ")
	v.Set("nats.dlq_subject", "claims.dlq.*")
	v.Set("nats.dlq_max_bytes", int64(3<<30))
	v.Set("nats.dlq_max_age", "168h")
	v.Set("nats.duplicate_window", "5m")
	v.Set("nats.workers", 12)
	v.Set("nats.fetch_batch", 128)
	v.Set("nats.fetch_wait", "250ms")
	v.Set("nats.ack_wait", "45s")
	v.Set("nats.nak_delay", "2s")
	v.Set("nats.outcome_retry_wait", "3s")
	v.Set("nats.max_ack_pending", 1024)
	v.Set("nats.max_deliver", 20)
	v.Set("nats.connect_timeout", "3s")
	v.Set("nats.reconnect_wait", "500ms")
	v.Set("nats.max_reconnects", 50)
	v.Set("nats.drain_timeout", "15s")
	v.Set("nats.credentials_file", "/run/nats.creds")
	v.Set("nats.tls.enabled", true)
	v.Set("nats.tls.ca_file", "/run/ca.crt")
	v.Set("nats.tls.server_name", "nats.internal")

	got := FromViper(v).NATS
	if !got.Enabled || len(got.URLs) != 2 || got.URLs[1] != "tls://two:4222" {
		t.Fatalf("NATS URLs = %#v enabled=%v", got.URLs, got.Enabled)
	}
	if got.Stream != "INGRESS" || got.Subject != "claims.ingress" || got.Durable != "worker-a" || got.Workers != 12 {
		t.Fatalf("NATS identity/config = %+v", got)
	}
	if !got.Provision || got.StreamStorage != "memory" || got.StreamReplicas != 3 || got.StreamMaxBytes != 1<<30 || got.StreamMaxAge != "24h" || got.DuplicateWindow != "5m" {
		t.Fatalf("NATS topology = %+v", got)
	}
	if got.ResultStream != "RESULTS" || got.ResultSubject != "claims.results.*" || got.ResultMaxBytes != 2<<30 || got.ResultMaxAge != "12h" {
		t.Fatalf("NATS result topology = %+v", got)
	}
	if got.DLQStream != "DLQ" || got.DLQSubject != "claims.dlq.*" || got.DLQMaxBytes != 3<<30 || got.DLQMaxAge != "168h" {
		t.Fatalf("NATS DLQ topology = %+v", got)
	}
	if got.FetchBatch != 128 || got.MaxAckPending != 1024 || got.MaxDeliver != 20 || got.MaxReconnects != 50 {
		t.Fatalf("NATS limits = %+v", got)
	}
	if got.NakDelay != "2s" || got.ResultRetryWait != "3s" {
		t.Fatalf("NATS delivery retry settings = %+v", got)
	}
	if got.CredentialsFile != "/run/nats.creds" || !got.TLS.Enabled || got.TLS.CAFile != "/run/ca.crt" || got.TLS.ServerName != "nats.internal" {
		t.Fatalf("NATS auth/TLS = %+v", got)
	}
}

func TestFromViperDefaultsMissingAnchorPollInterval(t *testing.T) {
	t.Parallel()

	cfg := FromViper(viper.New())
	if cfg.Anchor.MaxDelay != "5m" {
		t.Fatalf("anchor.max_delay = %q, want 5m", cfg.Anchor.MaxDelay)
	}
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
	cfg.NATS.Password = "password"
	cfg.NATS.Token = "token"
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
	if redacted.NATS.Password != "<redacted>" || redacted.NATS.Token != "<redacted>" {
		t.Fatalf("NATS secrets were not redacted: %+v", redacted.NATS)
	}
}
