package config

import (
	"os"
	"strings"

	"github.com/spf13/viper"
)

// FromViper maps a populated viper instance into Config. It mirrors the
// mapping previously done in cmd/trustdb/root.go so validation and admin
// config reload can share one code path.
func FromViper(v *viper.Viper) Config {
	return Config{
		RunProfile: v.GetString("run_profile"),
		Paths: Paths{
			DataDir:     v.GetString("paths.data_dir"),
			KeyRegistry: v.GetString("paths.key_registry"),
			WAL:         v.GetString("paths.wal"),
			ObjectDir:   v.GetString("paths.object_dir"),
			ProofDir:    v.GetString("paths.proof_dir"),
		},
		Identity: Identity{
			Tenant: v.GetString("identity.tenant"),
			Client: v.GetString("identity.client"),
			KeyID:  v.GetString("identity.key_id"),
		},
		Server: Server{
			Listen:            v.GetString("server.listen"),
			GRPCListen:        v.GetString("server.grpc_listen"),
			ID:                v.GetString("server.id"),
			KeyID:             v.GetString("server.key_id"),
			QueueSize:         v.GetInt("server.queue_size"),
			Workers:           v.GetInt("server.workers"),
			ReadTimeout:       v.GetString("server.read_timeout"),
			ReadHeaderTimeout: v.GetString("server.read_header_timeout"),
			WriteTimeout:      v.GetString("server.write_timeout"),
			IdleTimeout:       v.GetString("server.idle_timeout"),
			ShutdownTimeout:   v.GetString("server.shutdown_timeout"),
		},
		Registry: Registry{
			KeyID: v.GetString("registry.key_id"),
		},
		Batch: Batch{
			QueueSize:                v.GetInt("batch.queue_size"),
			MaxRecords:               v.GetInt("batch.max_records"),
			MaxDelay:                 v.GetString("batch.max_delay"),
			ProofMode:                v.GetString("batch.proof_mode"),
			MaterializerWorkers:      v.GetInt("batch.materializer_workers"),
			MaterializerQueueSize:    v.GetInt("batch.materializer_queue_size"),
			MaterializerPollInterval: v.GetString("batch.materializer_poll_interval"),
			ProofWorkers:             v.GetInt("batch.proof_workers"),
		},
		GlobalLog: GlobalLog{
			Enabled: v.GetBool("global_log.enabled"),
			LogID:   v.GetString("global_log.log_id"),
		},
		Anchor: Anchor{
			Scope:    v.GetString("anchor.scope"),
			MaxDelay: v.GetString("anchor.max_delay"),
			Workers:  v.GetInt("anchor.workers"),
		},
		History: History{
			TileSize:        v.GetUint64("history.tile_size"),
			HotWindowLeaves: v.GetUint64("history.hot_window_leaves"),
		},
		Backup: Backup{
			Compression: v.GetString("backup.compression"),
		},
		Proofstore: Proofstore{
			ArtifactSyncMode: v.GetString("proofstore.artifact_sync_mode"),
			RecordIndexMode:  proofstoreRecordIndexModeFromViper(v),
			TiKVPDAddresses:  splitCSV(strings.Join(v.GetStringSlice("proofstore.tikv_pd_endpoints"), ",")),
			TiKVKeyspace:     v.GetString("proofstore.tikv_keyspace"),
			TiKVNamespace:    v.GetString("proofstore.tikv_namespace"),
		},
		Log: Log{
			Level:  v.GetString("log.level"),
			Format: v.GetString("log.format"),
			Output: v.GetString("log.output"),
			File: LogFile{
				Path:       v.GetString("log.file.path"),
				MaxSizeMB:  v.GetInt("log.file.max_size_mb"),
				MaxBackups: v.GetInt("log.file.max_backups"),
				MaxAgeDays: v.GetInt("log.file.max_age_days"),
				Compress:   v.GetBool("log.file.compress"),
			},
			Async: LogAsync{
				Enabled:    v.GetBool("log.async.enabled"),
				BufferSize: v.GetInt("log.async.buffer_size"),
				DropOnFull: v.GetBool("log.async.drop_on_full"),
			},
		},
		Keys: Keys{
			ClientPrivate:   v.GetString("keys.client_private"),
			ClientPublic:    v.GetString("keys.client_public"),
			ServerPrivate:   v.GetString("keys.server_private"),
			ServerPublic:    v.GetString("keys.server_public"),
			RegistryPrivate: v.GetString("keys.registry_private"),
			RegistryPublic:  v.GetString("keys.registry_public"),
		},
		Admin: Admin{
			Enabled:       v.GetBool("admin.enabled"),
			BasePath:      v.GetString("admin.base_path"),
			Username:      v.GetString("admin.username"),
			PasswordHash:  v.GetString("admin.password_hash"),
			SessionSecret: v.GetString("admin.session_secret"),
			WebDir:        v.GetString("admin.web_dir"),
			CookieSecure:  v.GetBool("admin.cookie_secure"),
			SessionTTL:    v.GetString("admin.session_ttl"),
		},
	}
}

func proofstoreRecordIndexModeFromViper(v *viper.Viper) string {
	mode := strings.TrimSpace(v.GetString("proofstore.record_index_mode"))
	if envIsSet("TRUSTDB_PROOFSTORE_RECORD_INDEX_MODE") && mode != "" {
		return mode
	}
	if envIsSet("TRUSTDB_PROOFSTORE_INDEX_STORAGE_TOKENS") && !v.GetBool("proofstore.index_storage_tokens") {
		return "no_storage_tokens"
	}
	if v.InConfig("proofstore.record_index_mode") && mode != "" {
		return mode
	}
	if v.InConfig("proofstore.index_storage_tokens") && !v.GetBool("proofstore.index_storage_tokens") {
		return "no_storage_tokens"
	}
	if mode != "" {
		return mode
	}
	return "full"
}

func envIsSet(names ...string) bool {
	for _, name := range names {
		if _, ok := os.LookupEnv(name); ok {
			return true
		}
	}
	return false
}

func splitCSV(text string) []string {
	parts := strings.Split(text, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
