package config

import (
	"os"
	"strings"

	"github.com/spf13/viper"
	"github.com/wowtrust/trustdb/transporttls"
)

// FromViper maps a populated viper instance into Config. It mirrors the
// mapping previously done in cmd/trustdb/root.go so validation and admin
// config reload can share one code path.
func FromViper(v *viper.Viper) Config {
	defaults := Default()
	anchorMaxDelay := strings.TrimSpace(v.GetString("anchor.max_delay"))
	if anchorMaxDelay == "" {
		anchorMaxDelay = defaults.Anchor.MaxDelay
	}
	anchorPollInterval := strings.TrimSpace(v.GetString("anchor.poll_interval"))
	if anchorPollInterval == "" {
		anchorPollInterval = defaults.Anchor.PollInterval
	}
	anchorPluginStartTimeout := strings.TrimSpace(v.GetString("anchor.plugin.start_timeout"))
	if anchorPluginStartTimeout == "" {
		anchorPluginStartTimeout = defaults.Anchor.Plugin.StartTimeout
	}
	anchorPluginRPCTimeout := strings.TrimSpace(v.GetString("anchor.plugin.rpc_timeout"))
	if anchorPluginRPCTimeout == "" {
		anchorPluginRPCTimeout = defaults.Anchor.Plugin.RPCTimeout
	}
	remoteSignerPlugin := signerPluginFromViper(v, "remote", defaults.Crypto.SignerPlugins.Remote)
	pkcs11SignerPlugin := signerPluginFromViper(v, "pkcs11", defaults.Crypto.SignerPlugins.PKCS11)
	sdfSignerPlugin := signerPluginFromViper(v, "sdf", defaults.Crypto.SignerPlugins.SDF)
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
			Transport: ServerTransport{
				Mode:                v.GetString("server.transport.mode"),
				AllowLocalPlaintext: v.GetBool("server.transport.allow_local_plaintext"),
				CertFile:            v.GetString("server.transport.cert_file"),
				KeyFile:             v.GetString("server.transport.key_file"),
				ClientCAFile:        v.GetString("server.transport.client_ca_file"),
				ClientCAPinsSHA256:  append([]string(nil), v.GetStringSlice("server.transport.client_ca_pins_sha256")...),
				MinVersion:          v.GetString("server.transport.min_version"),
				MaxVersion:          v.GetString("server.transport.max_version"),
				ReloadInterval:      v.GetString("server.transport.reload_interval"),
				Revocation: transporttls.RevocationConfig{
					Mode:       v.GetString("server.transport.revocation.mode"),
					SerialFile: v.GetString("server.transport.revocation.serial_file"),
				},
			},
		},
		NATS: NATS{
			Enabled:         v.GetBool("nats.enabled"),
			URLs:            splitCSV(strings.Join(v.GetStringSlice("nats.urls"), ",")),
			Stream:          v.GetString("nats.stream"),
			Subject:         v.GetString("nats.subject"),
			Durable:         v.GetString("nats.durable"),
			Provision:       v.GetBool("nats.provision"),
			StreamStorage:   v.GetString("nats.stream_storage"),
			StreamReplicas:  v.GetInt("nats.stream_replicas"),
			StreamMaxBytes:  v.GetInt64("nats.stream_max_bytes"),
			StreamMaxAge:    v.GetString("nats.stream_max_age"),
			ResultStream:    v.GetString("nats.result_stream"),
			ResultSubject:   v.GetString("nats.result_subject"),
			ResultMaxBytes:  v.GetInt64("nats.result_max_bytes"),
			ResultMaxAge:    v.GetString("nats.result_max_age"),
			DLQStream:       v.GetString("nats.dlq_stream"),
			DLQSubject:      v.GetString("nats.dlq_subject"),
			DLQMaxBytes:     v.GetInt64("nats.dlq_max_bytes"),
			DLQMaxAge:       v.GetString("nats.dlq_max_age"),
			DuplicateWindow: v.GetString("nats.duplicate_window"),
			Workers:         v.GetInt("nats.workers"),
			FetchBatch:      v.GetInt("nats.fetch_batch"),
			FetchWait:       v.GetString("nats.fetch_wait"),
			AckWait:         v.GetString("nats.ack_wait"),
			NakDelay:        v.GetString("nats.nak_delay"),
			ResultRetryWait: v.GetString("nats.outcome_retry_wait"),
			MaxAckPending:   v.GetInt("nats.max_ack_pending"),
			MaxDeliver:      v.GetInt("nats.max_deliver"),
			ConnectTimeout:  v.GetString("nats.connect_timeout"),
			ReconnectWait:   v.GetString("nats.reconnect_wait"),
			MaxReconnects:   v.GetInt("nats.max_reconnects"),
			DrainTimeout:    v.GetString("nats.drain_timeout"),
			CredentialsFile: v.GetString("nats.credentials_file"),
			Username:        v.GetString("nats.username"),
			Password:        v.GetString("nats.password"),
			Token:           v.GetString("nats.token"),
			TLS: NATSTLS{
				Enabled:            v.GetBool("nats.tls.enabled"),
				CAFile:             v.GetString("nats.tls.ca_file"),
				CertFile:           v.GetString("nats.tls.cert_file"),
				KeyFile:            v.GetString("nats.tls.key_file"),
				ServerName:         v.GetString("nats.tls.server_name"),
				InsecureSkipVerify: v.GetBool("nats.tls.insecure_skip_verify"),
			},
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
			Scope:        v.GetString("anchor.scope"),
			MaxDelay:     anchorMaxDelay,
			PollInterval: anchorPollInterval,
			Sink:         v.GetString("anchor.sink"),
			Path:         v.GetString("anchor.path"),
			Plugin: AnchorPlugin{
				Command:      v.GetString("anchor.plugin.command"),
				Args:         append([]string(nil), v.GetStringSlice("anchor.plugin.args")...),
				StartTimeout: anchorPluginStartTimeout,
				RPCTimeout:   anchorPluginRPCTimeout,
			},
		},
		Crypto: Crypto{SignerPlugins: SignerPlugins{
			Remote: remoteSignerPlugin,
			PKCS11: pkcs11SignerPlugin,
			SDF:    sdfSignerPlugin,
		}},
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

func signerPluginFromViper(v *viper.Viper, provider string, defaults SignerPlugin) SignerPlugin {
	prefix := "crypto.signer_plugins." + provider + "."
	startTimeout := strings.TrimSpace(v.GetString(prefix + "start_timeout"))
	if startTimeout == "" {
		startTimeout = defaults.StartTimeout
	}
	rpcTimeout := strings.TrimSpace(v.GetString(prefix + "rpc_timeout"))
	if rpcTimeout == "" {
		rpcTimeout = defaults.RPCTimeout
	}
	return SignerPlugin{
		Command:        v.GetString(prefix + "command"),
		Args:           append([]string(nil), v.GetStringSlice(prefix+"args")...),
		InheritEnv:     append([]string(nil), v.GetStringSlice(prefix+"inherit_env")...),
		StartTimeout:   startTimeout,
		RPCTimeout:     rpcTimeout,
		MaxConcurrency: v.GetInt(prefix + "max_concurrency"),
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
