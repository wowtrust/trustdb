package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog"
	trustconfig "github.com/wowtrust/trustdb/internal/config"
	"github.com/wowtrust/trustdb/internal/logx"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/natefinch/lumberjack.v2"
)

type runtimeConfig struct {
	out        io.Writer
	errOut     io.Writer
	configPath string
	cfg        trustconfig.Config
	viper      *viper.Viper
	logger     zerolog.Logger
	logCloser  io.Closer
}

func newRootCommand(out, errOut io.Writer) *cobra.Command {
	rt := &runtimeConfig{
		out:    out,
		errOut: errOut,
		viper:  viper.New(),
	}
	setDefaults(rt.viper)

	root := &cobra.Command{
		Use:           "trustdb",
		Short:         "High-performance evidence database client",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return rt.load()
		},
		PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
			return rt.close()
		},
	}
	root.SetOut(out)
	root.SetErr(errOut)

	root.PersistentFlags().StringVar(&rt.configPath, "config", "", "config file path")
	root.PersistentFlags().String("data-dir", "", "data directory")
	root.PersistentFlags().String("log-level", "", "log level: debug, info, warn, error")
	root.PersistentFlags().String("log-format", "", "log format: json, console, or text")
	root.PersistentFlags().String("log-output", "", "log output: stderr, file, or both")
	root.PersistentFlags().String("log-file", "", "rotating log file path")
	root.PersistentFlags().Int("log-max-size-mb", 0, "maximum log file size before rotation in MiB")
	root.PersistentFlags().Int("log-max-backups", 0, "maximum rotated log files to retain, 0 keeps all")
	root.PersistentFlags().Int("log-max-age-days", 0, "maximum days to retain rotated log files, 0 disables age cleanup")
	root.PersistentFlags().Bool("log-compress", false, "compress rotated log files with gzip")
	root.PersistentFlags().Bool("log-async", false, "write logs through a bounded async buffer")
	root.PersistentFlags().Int("log-async-buffer", 0, "async log queue capacity")
	root.PersistentFlags().Bool("log-async-drop", false, "drop logs when async queue is full")
	_ = rt.viper.BindPFlag("paths.data_dir", root.PersistentFlags().Lookup("data-dir"))
	_ = rt.viper.BindPFlag("log.level", root.PersistentFlags().Lookup("log-level"))
	_ = rt.viper.BindPFlag("log.format", root.PersistentFlags().Lookup("log-format"))
	_ = rt.viper.BindPFlag("log.output", root.PersistentFlags().Lookup("log-output"))
	_ = rt.viper.BindPFlag("log.file.path", root.PersistentFlags().Lookup("log-file"))
	_ = rt.viper.BindPFlag("log.file.max_size_mb", root.PersistentFlags().Lookup("log-max-size-mb"))
	_ = rt.viper.BindPFlag("log.file.max_backups", root.PersistentFlags().Lookup("log-max-backups"))
	_ = rt.viper.BindPFlag("log.file.max_age_days", root.PersistentFlags().Lookup("log-max-age-days"))
	_ = rt.viper.BindPFlag("log.file.compress", root.PersistentFlags().Lookup("log-compress"))
	_ = rt.viper.BindPFlag("log.async.enabled", root.PersistentFlags().Lookup("log-async"))
	_ = rt.viper.BindPFlag("log.async.buffer_size", root.PersistentFlags().Lookup("log-async-buffer"))
	_ = rt.viper.BindPFlag("log.async.drop_on_full", root.PersistentFlags().Lookup("log-async-drop"))

	root.AddCommand(newConfigCommand(rt))
	root.AddCommand(newAdminCommand(rt))
	root.AddCommand(newServeCommand(rt))
	root.AddCommand(newKeyCommand(rt))
	root.AddCommand(newKeygenCommand(rt, false))
	root.AddCommand(newKeyRegisterCommand(rt, false))
	root.AddCommand(newKeyRevokeCommand(rt, false))
	root.AddCommand(newKeyListCommand(rt, false))
	root.AddCommand(newClaimFileCommand(rt))
	root.AddCommand(newCommitCommand(rt))
	root.AddCommand(newCommitBatchCommand(rt))
	root.AddCommand(newVerifyCommand(rt))
	root.AddCommand(newProofCommand(rt))
	root.AddCommand(newWALCommand(rt))
	root.AddCommand(newMetastoreCommand(rt))
	root.AddCommand(newAnchorCommand(rt))
	root.AddCommand(newGlobalLogCommand(rt))
	root.AddCommand(newBackupCommand(rt))
	root.AddCommand(newBenchCommand(rt))
	root.AddCommand(newVersionCommand(rt))
	root.AddCommand(newDoctorCommand(rt))
	root.AddCommand(newCompletionCommand(rt))
	return root
}

func setDefaults(v *viper.Viper) {
	v.SetEnvPrefix("TRUSTDB")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	defaults := trustconfig.Default()
	v.SetDefault("run_profile", defaults.RunProfile)
	v.SetDefault("paths.data_dir", defaults.Paths.DataDir)
	v.SetDefault("paths.key_registry", defaults.Paths.KeyRegistry)
	v.SetDefault("paths.wal", defaults.Paths.WAL)
	v.SetDefault("paths.object_dir", defaults.Paths.ObjectDir)
	v.SetDefault("paths.proof_dir", defaults.Paths.ProofDir)
	v.SetDefault("identity.tenant", defaults.Identity.Tenant)
	v.SetDefault("identity.client", defaults.Identity.Client)
	v.SetDefault("identity.key_id", defaults.Identity.KeyID)
	v.SetDefault("server.listen", defaults.Server.Listen)
	v.SetDefault("server.id", defaults.Server.ID)
	v.SetDefault("server.key_id", defaults.Server.KeyID)
	v.SetDefault("server.queue_size", defaults.Server.QueueSize)
	v.SetDefault("server.workers", defaults.Server.Workers)
	v.SetDefault("server.read_timeout", defaults.Server.ReadTimeout)
	v.SetDefault("server.read_header_timeout", defaults.Server.ReadHeaderTimeout)
	v.SetDefault("server.write_timeout", defaults.Server.WriteTimeout)
	v.SetDefault("server.idle_timeout", defaults.Server.IdleTimeout)
	v.SetDefault("server.shutdown_timeout", defaults.Server.ShutdownTimeout)
	v.SetDefault("registry.key_id", defaults.Registry.KeyID)
	v.SetDefault("batch.queue_size", defaults.Batch.QueueSize)
	v.SetDefault("batch.max_records", defaults.Batch.MaxRecords)
	v.SetDefault("batch.max_delay", defaults.Batch.MaxDelay)
	v.SetDefault("batch.proof_mode", defaults.Batch.ProofMode)
	v.SetDefault("batch.materializer_workers", defaults.Batch.MaterializerWorkers)
	v.SetDefault("batch.materializer_queue_size", defaults.Batch.MaterializerQueueSize)
	v.SetDefault("batch.materializer_poll_interval", defaults.Batch.MaterializerPollInterval)
	v.SetDefault("batch.proof_workers", defaults.Batch.ProofWorkers)
	v.SetDefault("global_log.enabled", defaults.GlobalLog.Enabled)
	v.SetDefault("global_log.log_id", defaults.GlobalLog.LogID)
	v.SetDefault("anchor.scope", defaults.Anchor.Scope)
	v.SetDefault("anchor.max_delay", defaults.Anchor.MaxDelay)
	v.SetDefault("anchor.poll_interval", defaults.Anchor.PollInterval)
	v.SetDefault("history.tile_size", defaults.History.TileSize)
	v.SetDefault("history.hot_window_leaves", defaults.History.HotWindowLeaves)
	v.SetDefault("backup.compression", defaults.Backup.Compression)
	v.SetDefault("proofstore.artifact_sync_mode", defaults.Proofstore.ArtifactSyncMode)
	v.SetDefault("proofstore.record_index_mode", defaults.Proofstore.RecordIndexMode)
	v.SetDefault("proofstore.tikv_pd_endpoints", defaults.Proofstore.TiKVPDAddresses)
	v.SetDefault("proofstore.tikv_keyspace", defaults.Proofstore.TiKVKeyspace)
	v.SetDefault("proofstore.tikv_namespace", defaults.Proofstore.TiKVNamespace)
	v.SetDefault("proofstore.index_storage_tokens", true)
	v.SetDefault("log.level", defaults.Log.Level)
	v.SetDefault("log.format", defaults.Log.Format)
	v.SetDefault("log.output", defaults.Log.Output)
	v.SetDefault("log.file.path", defaults.Log.File.Path)
	v.SetDefault("log.file.max_size_mb", defaults.Log.File.MaxSizeMB)
	v.SetDefault("log.file.max_backups", defaults.Log.File.MaxBackups)
	v.SetDefault("log.file.max_age_days", defaults.Log.File.MaxAgeDays)
	v.SetDefault("log.file.compress", defaults.Log.File.Compress)
	v.SetDefault("log.async.enabled", defaults.Log.Async.Enabled)
	v.SetDefault("log.async.buffer_size", defaults.Log.Async.BufferSize)
	v.SetDefault("log.async.drop_on_full", defaults.Log.Async.DropOnFull)
	v.SetDefault("keys.client_private", defaults.Keys.ClientPrivate)
	v.SetDefault("keys.client_public", defaults.Keys.ClientPublic)
	v.SetDefault("keys.server_private", defaults.Keys.ServerPrivate)
	v.SetDefault("keys.server_public", defaults.Keys.ServerPublic)
	v.SetDefault("keys.registry_private", defaults.Keys.RegistryPrivate)
	v.SetDefault("keys.registry_public", defaults.Keys.RegistryPublic)
	// Anchor sink defaults: keep "anchor.sink" empty/off so a fresh
	// install does not silently start reaching out to public OTS
	// calendars. Callers have to opt in with --anchor-sink=ots.
	v.SetDefault("anchor.sink", "")
	v.SetDefault("anchor.path", "")
	v.SetDefault("anchor.ots.calendars", []string{})
	v.SetDefault("anchor.ots.min_accepted", 0)
	v.SetDefault("anchor.ots.timeout", "")
	// OTS upgrader defaults: enabled by default so flipping
	// --anchor-sink=ots gives operators an automatic
	// pending→attested progression. Empty interval / timeout fall
	// back to the upgrader's compile-time defaults (1h / 30s).
	v.SetDefault("anchor.ots.upgrade.enabled", true)
	v.SetDefault("anchor.ots.upgrade.interval", "")
	v.SetDefault("anchor.ots.upgrade.batch_size", 0)
	v.SetDefault("anchor.ots.upgrade.timeout", "")
	v.SetDefault("anchor.ots.upgrade.workers", 4)

	defAdmin := defaults.Admin
	v.SetDefault("admin.enabled", defAdmin.Enabled)
	v.SetDefault("admin.base_path", defAdmin.BasePath)
	v.SetDefault("admin.username", defAdmin.Username)
	v.SetDefault("admin.password_hash", defAdmin.PasswordHash)
	v.SetDefault("admin.session_secret", defAdmin.SessionSecret)
	v.SetDefault("admin.web_dir", defAdmin.WebDir)
	v.SetDefault("admin.cookie_secure", defAdmin.CookieSecure)
	v.SetDefault("admin.session_ttl", defAdmin.SessionTTL)

	bindEnv(v, "run_profile", "TRUSTDB_RUN_PROFILE")
	bindEnv(v, "paths.data_dir", "TRUSTDB_PATHS_DATA_DIR", "TRUSTDB_DATA_DIR")
	bindEnv(v, "paths.key_registry", "TRUSTDB_PATHS_KEY_REGISTRY", "TRUSTDB_KEY_REGISTRY")
	bindEnv(v, "paths.wal", "TRUSTDB_PATHS_WAL", "TRUSTDB_WAL")
	bindEnv(v, "paths.object_dir", "TRUSTDB_PATHS_OBJECT_DIR", "TRUSTDB_OBJECT_DIR")
	bindEnv(v, "paths.proof_dir", "TRUSTDB_PATHS_PROOF_DIR", "TRUSTDB_PROOF_DIR")
	bindEnv(v, "identity.tenant", "TRUSTDB_IDENTITY_TENANT", "TRUSTDB_TENANT")
	bindEnv(v, "identity.client", "TRUSTDB_IDENTITY_CLIENT", "TRUSTDB_CLIENT")
	bindEnv(v, "identity.key_id", "TRUSTDB_IDENTITY_KEY_ID", "TRUSTDB_KEY_ID")
	bindEnv(v, "server.listen", "TRUSTDB_SERVER_LISTEN")
	bindEnv(v, "server.id", "TRUSTDB_SERVER_ID")
	bindEnv(v, "server.key_id", "TRUSTDB_SERVER_KEY_ID")
	bindEnv(v, "server.queue_size", "TRUSTDB_SERVER_QUEUE_SIZE")
	bindEnv(v, "server.workers", "TRUSTDB_SERVER_WORKERS")
	bindEnv(v, "server.read_timeout", "TRUSTDB_SERVER_READ_TIMEOUT")
	bindEnv(v, "server.read_header_timeout", "TRUSTDB_SERVER_READ_HEADER_TIMEOUT")
	bindEnv(v, "server.write_timeout", "TRUSTDB_SERVER_WRITE_TIMEOUT")
	bindEnv(v, "server.idle_timeout", "TRUSTDB_SERVER_IDLE_TIMEOUT")
	bindEnv(v, "server.shutdown_timeout", "TRUSTDB_SERVER_SHUTDOWN_TIMEOUT")
	bindEnv(v, "registry.key_id", "TRUSTDB_REGISTRY_KEY_ID")
	bindEnv(v, "batch.queue_size", "TRUSTDB_BATCH_QUEUE_SIZE")
	bindEnv(v, "batch.max_records", "TRUSTDB_BATCH_MAX_RECORDS")
	bindEnv(v, "batch.max_delay", "TRUSTDB_BATCH_MAX_DELAY")
	bindEnv(v, "batch.proof_mode", "TRUSTDB_BATCH_PROOF_MODE")
	bindEnv(v, "batch.materializer_workers", "TRUSTDB_BATCH_MATERIALIZER_WORKERS")
	bindEnv(v, "batch.materializer_queue_size", "TRUSTDB_BATCH_MATERIALIZER_QUEUE_SIZE")
	bindEnv(v, "batch.materializer_poll_interval", "TRUSTDB_BATCH_MATERIALIZER_POLL_INTERVAL")
	bindEnv(v, "batch.proof_workers", "TRUSTDB_BATCH_PROOF_WORKERS")
	bindEnv(v, "global_log.enabled", "TRUSTDB_GLOBAL_LOG_ENABLED")
	bindEnv(v, "global_log.log_id", "TRUSTDB_GLOBAL_LOG_LOG_ID", "TRUSTDB_GLOBAL_LOG_ID")
	bindEnv(v, "anchor.scope", "TRUSTDB_ANCHOR_SCOPE")
	bindEnv(v, "anchor.max_delay", "TRUSTDB_ANCHOR_MAX_DELAY")
	bindEnv(v, "anchor.poll_interval", "TRUSTDB_ANCHOR_POLL_INTERVAL")
	bindEnv(v, "history.tile_size", "TRUSTDB_HISTORY_TILE_SIZE")
	bindEnv(v, "history.hot_window_leaves", "TRUSTDB_HISTORY_HOT_WINDOW_LEAVES")
	bindEnv(v, "backup.compression", "TRUSTDB_BACKUP_COMPRESSION")
	bindEnv(v, "proofstore.artifact_sync_mode", "TRUSTDB_PROOFSTORE_ARTIFACT_SYNC_MODE")
	bindEnv(v, "proofstore.record_index_mode", "TRUSTDB_PROOFSTORE_RECORD_INDEX_MODE")
	bindEnv(v, "proofstore.tikv_pd_endpoints", "TRUSTDB_PROOFSTORE_TIKV_PD_ENDPOINTS", "TRUSTDB_TIKV_PD_ENDPOINTS")
	bindEnv(v, "proofstore.tikv_keyspace", "TRUSTDB_PROOFSTORE_TIKV_KEYSPACE", "TRUSTDB_TIKV_KEYSPACE")
	bindEnv(v, "proofstore.tikv_namespace", "TRUSTDB_PROOFSTORE_TIKV_NAMESPACE", "TRUSTDB_TIKV_NAMESPACE")
	bindEnv(v, "proofstore.index_storage_tokens", "TRUSTDB_PROOFSTORE_INDEX_STORAGE_TOKENS")
	bindEnv(v, "log.level", "TRUSTDB_LOG_LEVEL")
	bindEnv(v, "log.format", "TRUSTDB_LOG_FORMAT")
	bindEnv(v, "log.output", "TRUSTDB_LOG_OUTPUT")
	bindEnv(v, "log.file.path", "TRUSTDB_LOG_FILE_PATH", "TRUSTDB_LOG_FILE")
	bindEnv(v, "log.file.max_size_mb", "TRUSTDB_LOG_FILE_MAX_SIZE_MB")
	bindEnv(v, "log.file.max_backups", "TRUSTDB_LOG_FILE_MAX_BACKUPS")
	bindEnv(v, "log.file.max_age_days", "TRUSTDB_LOG_FILE_MAX_AGE_DAYS")
	bindEnv(v, "log.file.compress", "TRUSTDB_LOG_FILE_COMPRESS")
	bindEnv(v, "log.async.enabled", "TRUSTDB_LOG_ASYNC_ENABLED", "TRUSTDB_LOG_ASYNC")
	bindEnv(v, "log.async.buffer_size", "TRUSTDB_LOG_ASYNC_BUFFER_SIZE")
	bindEnv(v, "log.async.drop_on_full", "TRUSTDB_LOG_ASYNC_DROP_ON_FULL")
	bindEnv(v, "keys.client_private", "TRUSTDB_KEYS_CLIENT_PRIVATE")
	bindEnv(v, "keys.client_public", "TRUSTDB_KEYS_CLIENT_PUBLIC")
	bindEnv(v, "keys.server_private", "TRUSTDB_KEYS_SERVER_PRIVATE")
	bindEnv(v, "keys.server_public", "TRUSTDB_KEYS_SERVER_PUBLIC")
	bindEnv(v, "keys.registry_private", "TRUSTDB_KEYS_REGISTRY_PRIVATE")
	bindEnv(v, "keys.registry_public", "TRUSTDB_KEYS_REGISTRY_PUBLIC")
	bindEnv(v, "anchor.sink", "TRUSTDB_ANCHOR_SINK")
	bindEnv(v, "anchor.path", "TRUSTDB_ANCHOR_PATH")
	bindEnv(v, "anchor.ots.calendars", "TRUSTDB_ANCHOR_OTS_CALENDARS")
	bindEnv(v, "anchor.ots.min_accepted", "TRUSTDB_ANCHOR_OTS_MIN_ACCEPTED")
	bindEnv(v, "anchor.ots.timeout", "TRUSTDB_ANCHOR_OTS_TIMEOUT")
	bindEnv(v, "anchor.ots.upgrade.enabled", "TRUSTDB_ANCHOR_OTS_UPGRADE_ENABLED")
	bindEnv(v, "anchor.ots.upgrade.interval", "TRUSTDB_ANCHOR_OTS_UPGRADE_INTERVAL")
	bindEnv(v, "anchor.ots.upgrade.batch_size", "TRUSTDB_ANCHOR_OTS_UPGRADE_BATCH_SIZE")
	bindEnv(v, "anchor.ots.upgrade.timeout", "TRUSTDB_ANCHOR_OTS_UPGRADE_TIMEOUT")
	bindEnv(v, "anchor.ots.upgrade.workers", "TRUSTDB_ANCHOR_OTS_UPGRADE_WORKERS")
	bindEnv(v, "admin.enabled", "TRUSTDB_ADMIN_ENABLED")
	bindEnv(v, "admin.base_path", "TRUSTDB_ADMIN_BASE_PATH")
	bindEnv(v, "admin.username", "TRUSTDB_ADMIN_USERNAME")
	bindEnv(v, "admin.password_hash", "TRUSTDB_ADMIN_PASSWORD_HASH")
	bindEnv(v, "admin.session_secret", "TRUSTDB_ADMIN_SESSION_SECRET")
	bindEnv(v, "admin.web_dir", "TRUSTDB_ADMIN_WEB_DIR")
	bindEnv(v, "admin.cookie_secure", "TRUSTDB_ADMIN_COOKIE_SECURE")
	bindEnv(v, "admin.session_ttl", "TRUSTDB_ADMIN_SESSION_TTL")
}

func bindEnv(v *viper.Viper, key string, env ...string) {
	input := append([]string{key}, env...)
	_ = v.BindEnv(input...)
}

func (rt *runtimeConfig) load() error {
	if rt.configPath != "" {
		rt.viper.SetConfigFile(rt.configPath)
	} else {
		rt.viper.SetConfigName("trustdb")
		rt.viper.SetConfigType("yaml")
		rt.viper.AddConfigPath(".")
		rt.viper.AddConfigPath(rt.viper.GetString("paths.data_dir"))
	}

	if err := rt.viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok || rt.configPath != "" {
			return fmt.Errorf("read config: %w", err)
		}
	}
	cfg := trustconfig.FromViper(rt.viper)
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}
	rt.cfg = cfg
	logger, closer, err := newLogger(rt.errOut, cfg.Log)
	if err != nil {
		return err
	}
	rt.logger = logger
	rt.logCloser = closer
	return nil
}

func (rt *runtimeConfig) close() error {
	if rt.logCloser == nil {
		return nil
	}
	err := rt.logCloser.Close()
	rt.logCloser = nil
	return err
}

func (rt *runtimeConfig) writeJSON(v any) error {
	enc := json.NewEncoder(rt.out)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

func newLogger(stderr io.Writer, cfg trustconfig.Log) (zerolog.Logger, io.Closer, error) {
	level := zerolog.WarnLevel
	switch strings.ToLower(cfg.Level) {
	case "debug":
		level = zerolog.DebugLevel
	case "info":
		level = zerolog.InfoLevel
	case "warn", "warning", "":
		level = zerolog.WarnLevel
	case "error":
		level = zerolog.ErrorLevel
	default:
		level = zerolog.WarnLevel
	}
	out, closer, err := logWriter(stderr, cfg)
	if err != nil {
		return zerolog.Logger{}, nil, err
	}
	switch strings.ToLower(cfg.Format) {
	case "console", "text":
		out = zerolog.ConsoleWriter{
			Out:        out,
			TimeFormat: time.RFC3339,
			NoColor:    true,
		}
	}
	return zerolog.New(out).Level(level).With().Timestamp().Logger(), closer, nil
}

func logWriter(stderr io.Writer, cfg trustconfig.Log) (io.Writer, io.Closer, error) {
	out, closer, err := logOutputWriter(stderr, cfg)
	if err != nil {
		return nil, nil, err
	}
	if cfg.Async.Enabled {
		async := logx.NewAsyncWriter(out, cfg.Async.BufferSize, cfg.Async.DropOnFull)
		return async, multiCloser{async, closer}, nil
	}
	return out, closer, nil
}

func logOutputWriter(stderr io.Writer, cfg trustconfig.Log) (io.Writer, io.Closer, error) {
	switch strings.ToLower(cfg.Output) {
	case "", "stderr":
		return stderr, nil, nil
	case "file":
		return rotatingLogWriter(cfg.File)
	case "both":
		file, closer, err := rotatingLogWriter(cfg.File)
		if err != nil {
			return nil, nil, err
		}
		return io.MultiWriter(stderr, file), closer, nil
	default:
		return nil, nil, fmt.Errorf("unsupported log output: %s", cfg.Output)
	}
}

type multiCloser []io.Closer

func (m multiCloser) Close() error {
	var firstErr error
	for _, closer := range m {
		if closer == nil {
			continue
		}
		if err := closer.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func rotatingLogWriter(cfg trustconfig.LogFile) (io.Writer, io.Closer, error) {
	if err := os.MkdirAll(filepath.Dir(cfg.Path), 0o755); err != nil {
		return nil, nil, fmt.Errorf("create log directory: %w", err)
	}
	writer := &lumberjack.Logger{
		Filename:   cfg.Path,
		MaxSize:    cfg.MaxSizeMB,
		MaxBackups: cfg.MaxBackups,
		MaxAge:     cfg.MaxAgeDays,
		Compress:   cfg.Compress,
		LocalTime:  false,
	}
	return writer, writer, nil
}

func stringValue(cmd *cobra.Command, rt *runtimeConfig, flagName, key string) string {
	if cmd.Flags().Changed(flagName) {
		v, _ := cmd.Flags().GetString(flagName)
		return v
	}
	return configString(rt.cfg, key)
}

func addCommonIdentityFlags(cmd *cobra.Command) {
	cmd.Flags().String("tenant", "", "tenant id")
	cmd.Flags().String("client", "", "client id")
	cmd.Flags().String("key-id", "", "client key id")
}

func addRegistryFlags(cmd *cobra.Command) {
	cmd.Flags().String("registry", "", "key registry path")
	cmd.Flags().String("registry-public-key", "", "registry public key")
}

func addServerFlags(cmd *cobra.Command) {
	cmd.Flags().String("server-id", "", "server id")
	cmd.Flags().String("server-key-id", "", "server key id")
}

func dataDir(rt *runtimeConfig) string {
	return rt.cfg.Paths.DataDir
}

func configString(cfg trustconfig.Config, key string) string {
	switch key {
	case "paths.data_dir", "data_dir":
		return cfg.Paths.DataDir
	case "paths.key_registry", "key_registry":
		return cfg.Paths.KeyRegistry
	case "paths.wal", "wal":
		return cfg.Paths.WAL
	case "paths.object_dir", "object_dir":
		return cfg.Paths.ObjectDir
	case "paths.proof_dir", "proof_dir":
		return cfg.Paths.ProofDir
	case "identity.tenant", "tenant":
		return cfg.Identity.Tenant
	case "identity.client", "client":
		return cfg.Identity.Client
	case "identity.key_id", "key_id":
		return cfg.Identity.KeyID
	case "server.id", "server_id":
		return cfg.Server.ID
	case "server.listen", "server_listen":
		return cfg.Server.Listen
	case "server.key_id", "server_key_id":
		return cfg.Server.KeyID
	case "registry.key_id", "registry_key_id":
		return cfg.Registry.KeyID
	case "global_log.enabled":
		if cfg.GlobalLog.Enabled {
			return "true"
		}
		return "false"
	case "global_log.log_id":
		return cfg.GlobalLog.LogID
	case "anchor.scope":
		return cfg.Anchor.Scope
	case "anchor.max_delay":
		return cfg.Anchor.MaxDelay
	case "anchor.poll_interval":
		return cfg.Anchor.PollInterval
	case "anchor.sink":
		return cfg.Anchor.Sink
	case "anchor.path":
		return cfg.Anchor.Path
	case "batch.proof_mode":
		return cfg.Batch.ProofMode
	case "proofstore.artifact_sync_mode":
		return cfg.Proofstore.ArtifactSyncMode
	case "proofstore.record_index_mode":
		return cfg.Proofstore.RecordIndexMode
	case "proofstore.tikv_keyspace":
		return cfg.Proofstore.TiKVKeyspace
	case "proofstore.tikv_namespace":
		return cfg.Proofstore.TiKVNamespace
	case "backup.compression":
		return cfg.Backup.Compression
	case "log.level":
		return cfg.Log.Level
	case "log.format":
		return cfg.Log.Format
	case "keys.client_private":
		return cfg.Keys.ClientPrivate
	case "keys.client_public":
		return cfg.Keys.ClientPublic
	case "keys.server_private":
		return cfg.Keys.ServerPrivate
	case "keys.server_public":
		return cfg.Keys.ServerPublic
	case "keys.registry_private":
		return cfg.Keys.RegistryPrivate
	case "keys.registry_public":
		return cfg.Keys.RegistryPublic
	default:
		return ""
	}
}
