package config

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/wowtrust/trustdb/v2/transporttls"
)

const DefaultYAML = `# TrustDB local client configuration.
# Optional run profile. Strict China/offline/assessment profiles enforce
# startup policy; development and benchmark remain operator-selected modes.
# run_profile: ""

paths:
  data_dir: ".trustdb"
  key_registry: ".trustdb/keys.tdkeys"
  wal: ".trustdb/wal"
  object_dir: ".trustdb/objects"
  proof_dir: ".trustdb/proofs"

metastore: "pebble"
metastore_path: ".trustdb/proofs/pebble"

proofstore:
  artifact_sync_mode: "chunk"
  record_index_mode: "full"
  tikv_pd_endpoints: []
  tikv_keyspace: ""
  tikv_namespace: "default"

wal:
  fsync_mode: "group"
  group_commit_interval: "10ms"
  max_segment_bytes: 0
  keep_segments: 0

identity:
  tenant: "default"
  client: ""
  key_id: ""

server:
  listen: "127.0.0.1:8080"
  grpc_listen: ""
  id: "local-server"
  key_id: "server-key"
  queue_size: 1024
  workers: 4
  read_timeout: "10s"
  read_header_timeout: "5s"
  write_timeout: "10s"
  idle_timeout: "120s"
  shutdown_timeout: "10s"
  transport:
    mode: "plaintext"
    allow_local_plaintext: false
    cert_file: ""
    key_file: ""
    client_ca_file: ""
    client_ca_pins_sha256: []
    min_version: "1.2"
    max_version: ""
    reload_interval: "1m"
    revocation:
      mode: "off"
      serial_file: ""

tlcp:
  gateway_profile: ""
  identity_manifest: ""

deployment_policy:
  egress_mode: "unrestricted"
  allowed_endpoints: []
  dns_allowlist: []
  telemetry_enabled: false
  update_checks_enabled: false
  exceptions: []

# Optional JetStream ingress. Disabled means TrustDB does not connect to NATS
# or create any broker resources; the existing HTTP and gRPC transports remain
# unchanged. workers=0 lets the future runtime size workers automatically.
nats:
  enabled: false
  urls: ["nats://127.0.0.1:4222"]
  stream: "TRUSTDB_INGRESS_V2"
  subject: "trustdb.ingress.v2.claims"
  durable: "trustdb-ingress-v2"
  provision: true
  stream_storage: "file"
  stream_replicas: 1
  stream_max_bytes: 10737418240
  stream_max_age: "0s"
  result_stream: "TRUSTDB_INGRESS_V2_RESULTS"
  result_subject: "trustdb.ingress.v2.results.*"
  result_max_bytes: 10737418240
  result_max_age: "24h"
  dlq_stream: "TRUSTDB_INGRESS_V2_DLQ"
  dlq_subject: "trustdb.ingress.v2.dlq.*"
  dlq_max_bytes: 1073741824
  dlq_max_age: "0s"
  duplicate_window: "2m"
  workers: 0
  fetch_batch: 256
  fetch_wait: "1s"
  ack_wait: "30s"
  nak_delay: "1s"
  outcome_retry_wait: "1s"
  max_ack_pending: 2048
  max_deliver: 10
  connect_timeout: "5s"
  reconnect_wait: "1s"
  max_reconnects: -1
  drain_timeout: "10s"
  credentials_file: ""
  username: ""
  password: ""
  token: ""
  tls:
    enabled: false
    ca_file: ""
    cert_file: ""
    key_file: ""
    server_name: ""
    insecure_skip_verify: false

registry:
  key_id: "registry-key"

batch:
  queue_size: 1024
  max_records: 1024
  max_delay: "500ms"
  proof_mode: "inline"
  materializer_workers: 2
  materializer_queue_size: 4
  materializer_poll_interval: "250ms"
  proof_workers: 0

global_log:
  enabled: true
  log_id: "trustdb-global-log"

anchor:
  scope: "global"
  max_delay: "5m"
  poll_interval: "2s"
  # Set sink to fisco-bcos and provision this strict mode-bound canonical-CBOR
  # file to enable the pinned standard or Guomi client.
  fisco_bcos:
    trust_config_file: ""
  plugin:
    command: ""
    args: []
    start_timeout: "10s"
    rpc_timeout: "30s"

# Optional supervised signer plugins. Plugins implement private-key custody
# only; TrustDB keeps suites, hashing, signature framing, and verification
# built in. Empty commands leave each external provider disabled.
crypto:
  signer_plugins:
    remote:
      command: ""
      args: []
      inherit_env: []
      start_timeout: "10s"
      rpc_timeout: "30s"
      max_concurrency: 0
    pkcs11:
      command: ""
      args: []
      inherit_env: []
      start_timeout: "10s"
      rpc_timeout: "30s"
      max_concurrency: 0
    sdf:
      command: ""
      args: []
      inherit_env: []
      start_timeout: "10s"
      rpc_timeout: "30s"
      max_concurrency: 0

history:
  tile_size: 256
  hot_window_leaves: 65536

backup:
  compression: "gzip"
  key_provider: "passphrase-dev-v1"
  key_id: "development-backup-key"
  frame_bytes: 1048576

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
  async:
    enabled: false
    buffer_size: 8192
    drop_on_full: false

# Dedicated signed/hash-chained security audit trail. It is separate from
# application logs and is mandatory for single_node_production.
audit:
  enabled: false
  required: false
  path: ".trustdb/audit/security.audit"
  checkpoint_path: ".trustdb/audit/security.checkpoint"
  signing_key: ""
  max_bytes: 4294967296
  retention: "4380h"
  time_reference_path: ""
  time_max_sample_age: "2m"
  time_max_drift: "5s"
  require_synchronized_time: false

keys:
  client_private: ""
  client_public: ""
  server_private: ""
  server_public: ""
  registry_private: ""
  registry_public: ""

# Administrative authorization (disabled by default). Bootstrap a versioned
# RBAC policy with trustdb admin policy bootstrap; the same policy protects
# the web console and, when cli_enforce is true, privileged local commands.
# admin:
#   enabled: false
#   base_path: "/admin"
#   policy_path: ".trustdb/admin-policy.json"
#   session_secret: ""
#   web_dir: ""
#   cookie_secure: false
#   session_ttl: "8h"
#   login_max_failures: 5
#   login_lockout: "15m"
#   cli_enforce: false
#   oidc_gateway_spki_sha256: []
`

type Config struct {
	// RunProfile selects startup policy. Custom/development/benchmark profiles
	// retain flexible behavior; strict profiles fail closed.
	RunProfile       string           `mapstructure:"run_profile" json:"run_profile"`
	DeploymentPolicy DeploymentPolicy `mapstructure:"deployment_policy" json:"deployment_policy"`
	Paths            Paths            `mapstructure:"paths" json:"paths"`
	Identity         Identity         `mapstructure:"identity" json:"identity"`
	Server           Server           `mapstructure:"server" json:"server"`
	TLCP             TLCP             `mapstructure:"tlcp" json:"tlcp"`
	NATS             NATS             `mapstructure:"nats" json:"nats"`
	Registry         Registry         `mapstructure:"registry" json:"registry"`
	Batch            Batch            `mapstructure:"batch" json:"batch"`
	GlobalLog        GlobalLog        `mapstructure:"global_log" json:"global_log"`
	Anchor           Anchor           `mapstructure:"anchor" json:"anchor"`
	Crypto           Crypto           `mapstructure:"crypto" json:"crypto"`
	History          History          `mapstructure:"history" json:"history"`
	Backup           Backup           `mapstructure:"backup" json:"backup"`
	Proofstore       Proofstore       `mapstructure:"proofstore" json:"proofstore"`
	WAL              WAL              `mapstructure:"wal" json:"wal"`
	Log              Log              `mapstructure:"log" json:"log"`
	Audit            Audit            `mapstructure:"audit" json:"audit"`
	Keys             Keys             `mapstructure:"keys" json:"keys"`
	Admin            Admin            `mapstructure:"admin" json:"admin"`
}

type TLCP struct {
	GatewayProfile   string `mapstructure:"gateway_profile" json:"gateway_profile"`
	IdentityManifest string `mapstructure:"identity_manifest" json:"identity_manifest"`
}

// Admin configures the optional operator web console mounted by trustdb serve.
type Admin struct {
	Enabled          bool     `mapstructure:"enabled" json:"enabled"`
	BasePath         string   `mapstructure:"base_path" json:"base_path"`
	PolicyPath       string   `mapstructure:"policy_path" json:"policy_path"`
	SessionSecret    string   `mapstructure:"session_secret" json:"session_secret"`
	WebDir           string   `mapstructure:"web_dir" json:"web_dir"`
	CookieSecure     bool     `mapstructure:"cookie_secure" json:"cookie_secure"`
	SessionTTL       string   `mapstructure:"session_ttl" json:"session_ttl"`
	LoginMaxFailures int      `mapstructure:"login_max_failures" json:"login_max_failures"`
	LoginLockout     string   `mapstructure:"login_lockout" json:"login_lockout"`
	CLIEnforce       bool     `mapstructure:"cli_enforce" json:"cli_enforce"`
	OIDCGatewayPins  []string `mapstructure:"oidc_gateway_spki_sha256" json:"oidc_gateway_spki_sha256"`
}

// Audit configures the independent signed security audit trail. MaxBytes is a
// fail-closed capacity boundary, not a rotation request: required audit data is
// never silently deleted by TrustDB.
type Audit struct {
	Enabled                 bool   `mapstructure:"enabled" json:"enabled"`
	Required                bool   `mapstructure:"required" json:"required"`
	Path                    string `mapstructure:"path" json:"path"`
	CheckpointPath          string `mapstructure:"checkpoint_path" json:"checkpoint_path"`
	SigningKey              string `mapstructure:"signing_key" json:"signing_key"`
	MaxBytes                int64  `mapstructure:"max_bytes" json:"max_bytes"`
	Retention               string `mapstructure:"retention" json:"retention"`
	TimeReferencePath       string `mapstructure:"time_reference_path" json:"time_reference_path"`
	TimeMaxSampleAge        string `mapstructure:"time_max_sample_age" json:"time_max_sample_age"`
	TimeMaxDrift            string `mapstructure:"time_max_drift" json:"time_max_drift"`
	RequireSynchronizedTime bool   `mapstructure:"require_synchronized_time" json:"require_synchronized_time"`
}

type Paths struct {
	DataDir     string `mapstructure:"data_dir" json:"data_dir"`
	KeyRegistry string `mapstructure:"key_registry" json:"key_registry"`
	WAL         string `mapstructure:"wal" json:"wal"`
	ObjectDir   string `mapstructure:"object_dir" json:"object_dir"`
	ProofDir    string `mapstructure:"proof_dir" json:"proof_dir"`
}

type Identity struct {
	Tenant string `mapstructure:"tenant" json:"tenant"`
	Client string `mapstructure:"client" json:"client"`
	KeyID  string `mapstructure:"key_id" json:"key_id"`
}

type Server struct {
	Listen            string          `mapstructure:"listen" json:"listen"`
	GRPCListen        string          `mapstructure:"grpc_listen" json:"grpc_listen"`
	ID                string          `mapstructure:"id" json:"id"`
	KeyID             string          `mapstructure:"key_id" json:"key_id"`
	QueueSize         int             `mapstructure:"queue_size" json:"queue_size"`
	Workers           int             `mapstructure:"workers" json:"workers"`
	ReadTimeout       string          `mapstructure:"read_timeout" json:"read_timeout"`
	ReadHeaderTimeout string          `mapstructure:"read_header_timeout" json:"read_header_timeout"`
	WriteTimeout      string          `mapstructure:"write_timeout" json:"write_timeout"`
	IdleTimeout       string          `mapstructure:"idle_timeout" json:"idle_timeout"`
	ShutdownTimeout   string          `mapstructure:"shutdown_timeout" json:"shutdown_timeout"`
	Transport         ServerTransport `mapstructure:"transport" json:"transport"`
}

// ServerTransport is network transport trust. It must never be populated from
// keys.server_* or any proof-signing trust root.
type ServerTransport struct {
	Mode                string                        `mapstructure:"mode" json:"mode"`
	AllowLocalPlaintext bool                          `mapstructure:"allow_local_plaintext" json:"allow_local_plaintext"`
	CertFile            string                        `mapstructure:"cert_file" json:"cert_file"`
	KeyFile             string                        `mapstructure:"key_file" json:"key_file"`
	ClientCAFile        string                        `mapstructure:"client_ca_file" json:"client_ca_file"`
	ClientCAPinsSHA256  []string                      `mapstructure:"client_ca_pins_sha256" json:"client_ca_pins_sha256"`
	MinVersion          string                        `mapstructure:"min_version" json:"min_version"`
	MaxVersion          string                        `mapstructure:"max_version" json:"max_version"`
	ReloadInterval      string                        `mapstructure:"reload_interval" json:"reload_interval"`
	Revocation          transporttls.RevocationConfig `mapstructure:"revocation" json:"revocation"`
}

func (c ServerTransport) TLSConfig() transporttls.ServerConfig {
	return transporttls.ServerConfig{
		Mode:               c.Mode,
		CertFile:           c.CertFile,
		KeyFile:            c.KeyFile,
		ClientCAFile:       c.ClientCAFile,
		ClientCAPinsSHA256: append([]string(nil), c.ClientCAPinsSHA256...),
		MinVersion:         c.MinVersion,
		MaxVersion:         c.MaxVersion,
		ReloadInterval:     c.ReloadInterval,
		Revocation:         c.Revocation,
	}
}

// NATS configures the optional JetStream ingress transport. The runtime must
// ignore every field in this section while Enabled is false.
type NATS struct {
	Enabled         bool     `mapstructure:"enabled" json:"enabled"`
	URLs            []string `mapstructure:"urls" json:"urls"`
	Stream          string   `mapstructure:"stream" json:"stream"`
	Subject         string   `mapstructure:"subject" json:"subject"`
	Durable         string   `mapstructure:"durable" json:"durable"`
	Provision       bool     `mapstructure:"provision" json:"provision"`
	StreamStorage   string   `mapstructure:"stream_storage" json:"stream_storage"`
	StreamReplicas  int      `mapstructure:"stream_replicas" json:"stream_replicas"`
	StreamMaxBytes  int64    `mapstructure:"stream_max_bytes" json:"stream_max_bytes"`
	StreamMaxAge    string   `mapstructure:"stream_max_age" json:"stream_max_age"`
	ResultStream    string   `mapstructure:"result_stream" json:"result_stream"`
	ResultSubject   string   `mapstructure:"result_subject" json:"result_subject"`
	ResultMaxBytes  int64    `mapstructure:"result_max_bytes" json:"result_max_bytes"`
	ResultMaxAge    string   `mapstructure:"result_max_age" json:"result_max_age"`
	DLQStream       string   `mapstructure:"dlq_stream" json:"dlq_stream"`
	DLQSubject      string   `mapstructure:"dlq_subject" json:"dlq_subject"`
	DLQMaxBytes     int64    `mapstructure:"dlq_max_bytes" json:"dlq_max_bytes"`
	DLQMaxAge       string   `mapstructure:"dlq_max_age" json:"dlq_max_age"`
	DuplicateWindow string   `mapstructure:"duplicate_window" json:"duplicate_window"`
	Workers         int      `mapstructure:"workers" json:"workers"`
	FetchBatch      int      `mapstructure:"fetch_batch" json:"fetch_batch"`
	FetchWait       string   `mapstructure:"fetch_wait" json:"fetch_wait"`
	AckWait         string   `mapstructure:"ack_wait" json:"ack_wait"`
	NakDelay        string   `mapstructure:"nak_delay" json:"nak_delay"`
	ResultRetryWait string   `mapstructure:"outcome_retry_wait" json:"outcome_retry_wait"`
	MaxAckPending   int      `mapstructure:"max_ack_pending" json:"max_ack_pending"`
	MaxDeliver      int      `mapstructure:"max_deliver" json:"max_deliver"`
	ConnectTimeout  string   `mapstructure:"connect_timeout" json:"connect_timeout"`
	ReconnectWait   string   `mapstructure:"reconnect_wait" json:"reconnect_wait"`
	MaxReconnects   int      `mapstructure:"max_reconnects" json:"max_reconnects"`
	DrainTimeout    string   `mapstructure:"drain_timeout" json:"drain_timeout"`
	CredentialsFile string   `mapstructure:"credentials_file" json:"credentials_file"`
	Username        string   `mapstructure:"username" json:"username"`
	Password        string   `mapstructure:"password" json:"password"`
	Token           string   `mapstructure:"token" json:"token"`
	TLS             NATSTLS  `mapstructure:"tls" json:"tls"`
}

// NATSTLS configures certificate verification and optional mutual TLS for the
// NATS connection.
type NATSTLS struct {
	Enabled            bool   `mapstructure:"enabled" json:"enabled"`
	CAFile             string `mapstructure:"ca_file" json:"ca_file"`
	CertFile           string `mapstructure:"cert_file" json:"cert_file"`
	KeyFile            string `mapstructure:"key_file" json:"key_file"`
	ServerName         string `mapstructure:"server_name" json:"server_name"`
	InsecureSkipVerify bool   `mapstructure:"insecure_skip_verify" json:"insecure_skip_verify"`
}

type Registry struct {
	KeyID string `mapstructure:"key_id" json:"key_id"`
}

type Batch struct {
	QueueSize                int    `mapstructure:"queue_size" json:"queue_size"`
	MaxRecords               int    `mapstructure:"max_records" json:"max_records"`
	MaxDelay                 string `mapstructure:"max_delay" json:"max_delay"`
	ProofMode                string `mapstructure:"proof_mode" json:"proof_mode"`
	MaterializerWorkers      int    `mapstructure:"materializer_workers" json:"materializer_workers"`
	MaterializerQueueSize    int    `mapstructure:"materializer_queue_size" json:"materializer_queue_size"`
	MaterializerPollInterval string `mapstructure:"materializer_poll_interval" json:"materializer_poll_interval"`
	ProofWorkers             int    `mapstructure:"proof_workers" json:"proof_workers"`
}

// WAL configures append durability, segmented rotation, and post-checkpoint
// retention. Zero rotation bytes disables size-based rotation; zero retained
// segments keeps only the active and checkpoint-covered segments.
type WAL struct {
	FsyncMode           string `mapstructure:"fsync_mode" json:"fsync_mode"`
	GroupCommitInterval string `mapstructure:"group_commit_interval" json:"group_commit_interval"`
	MaxSegmentBytes     int64  `mapstructure:"max_segment_bytes" json:"max_segment_bytes"`
	KeepSegments        int    `mapstructure:"keep_segments" json:"keep_segments"`
}

type GlobalLog struct {
	Enabled bool   `mapstructure:"enabled" json:"enabled"`
	LogID   string `mapstructure:"log_id" json:"log_id"`
}

type Anchor struct {
	Scope        string          `mapstructure:"scope" json:"scope"`
	MaxDelay     string          `mapstructure:"max_delay" json:"max_delay"`
	PollInterval string          `mapstructure:"poll_interval" json:"poll_interval"`
	Sink         string          `mapstructure:"sink" json:"sink"`
	Path         string          `mapstructure:"path" json:"path"`
	Plugin       AnchorPlugin    `mapstructure:"plugin" json:"plugin"`
	FISCOBCOS    AnchorFISCOBCOS `mapstructure:"fisco_bcos" json:"fisco_bcos"`
}

type AnchorPlugin struct {
	Command      string   `mapstructure:"command" json:"command"`
	Args         []string `mapstructure:"args" json:"args"`
	StartTimeout string   `mapstructure:"start_timeout" json:"start_timeout"`
	RPCTimeout   string   `mapstructure:"rpc_timeout" json:"rpc_timeout"`
}

// AnchorFISCOBCOS points at a canonical, locally provisioned TrustConfig.
// Chain trust roots, endpoints, certificate references, and signer-provider
// references live in that file; private key bytes must never be placed in the
// central server configuration.
type AnchorFISCOBCOS struct {
	TrustConfigFile string `mapstructure:"trust_config_file" json:"trust_config_file"`
}

// Crypto configures optional external private-key custody adapters. These
// plugins cannot register suites, hash algorithms, signature framing, Merkle
// profiles, or verifiers.
type Crypto struct {
	SignerPlugins SignerPlugins `mapstructure:"signer_plugins" json:"signer_plugins"`
}

type SignerPlugins struct {
	Remote SignerPlugin `mapstructure:"remote" json:"remote"`
	PKCS11 SignerPlugin `mapstructure:"pkcs11" json:"pkcs11"`
	SDF    SignerPlugin `mapstructure:"sdf" json:"sdf"`
}

type SignerPlugin struct {
	Command        string   `mapstructure:"command" json:"command"`
	Args           []string `mapstructure:"args" json:"args"`
	InheritEnv     []string `mapstructure:"inherit_env" json:"inherit_env"`
	StartTimeout   string   `mapstructure:"start_timeout" json:"start_timeout"`
	RPCTimeout     string   `mapstructure:"rpc_timeout" json:"rpc_timeout"`
	MaxConcurrency int      `mapstructure:"max_concurrency" json:"max_concurrency"`
}

type History struct {
	TileSize        uint64 `mapstructure:"tile_size" json:"tile_size"`
	HotWindowLeaves uint64 `mapstructure:"hot_window_leaves" json:"hot_window_leaves"`
}

type Backup struct {
	Compression string `mapstructure:"compression" json:"compression"`
	KeyProvider string `mapstructure:"key_provider" json:"key_provider"`
	KeyID       string `mapstructure:"key_id" json:"key_id"`
	FrameBytes  int    `mapstructure:"frame_bytes" json:"frame_bytes"`
}

type Proofstore struct {
	ArtifactSyncMode string   `mapstructure:"artifact_sync_mode" json:"artifact_sync_mode"`
	RecordIndexMode  string   `mapstructure:"record_index_mode" json:"record_index_mode"`
	TiKVPDAddresses  []string `mapstructure:"tikv_pd_endpoints" json:"tikv_pd_endpoints"`
	TiKVKeyspace     string   `mapstructure:"tikv_keyspace" json:"tikv_keyspace"`
	TiKVNamespace    string   `mapstructure:"tikv_namespace" json:"tikv_namespace"`
}

type Log struct {
	Level  string   `mapstructure:"level" json:"level"`
	Format string   `mapstructure:"format" json:"format"`
	Output string   `mapstructure:"output" json:"output"`
	File   LogFile  `mapstructure:"file" json:"file"`
	Async  LogAsync `mapstructure:"async" json:"async"`
}

type LogFile struct {
	Path       string `mapstructure:"path" json:"path"`
	MaxSizeMB  int    `mapstructure:"max_size_mb" json:"max_size_mb"`
	MaxBackups int    `mapstructure:"max_backups" json:"max_backups"`
	MaxAgeDays int    `mapstructure:"max_age_days" json:"max_age_days"`
	Compress   bool   `mapstructure:"compress" json:"compress"`
}

type LogAsync struct {
	Enabled    bool `mapstructure:"enabled" json:"enabled"`
	BufferSize int  `mapstructure:"buffer_size" json:"buffer_size"`
	DropOnFull bool `mapstructure:"drop_on_full" json:"drop_on_full"`
}

type Keys struct {
	ClientPrivate   string `mapstructure:"client_private" json:"client_private"`
	ClientPublic    string `mapstructure:"client_public" json:"client_public"`
	ServerPrivate   string `mapstructure:"server_private" json:"server_private"`
	ServerPublic    string `mapstructure:"server_public" json:"server_public"`
	RegistryPrivate string `mapstructure:"registry_private" json:"registry_private"`
	RegistryPublic  string `mapstructure:"registry_public" json:"registry_public"`
}

func Default() Config {
	return Config{
		RunProfile: "",
		DeploymentPolicy: DeploymentPolicy{
			EgressMode: EgressUnrestricted,
		},
		Paths: Paths{
			DataDir:     ".trustdb",
			KeyRegistry: ".trustdb/keys.tdkeys",
			WAL:         ".trustdb/wal",
			ObjectDir:   ".trustdb/objects",
			ProofDir:    ".trustdb/proofs",
		},
		Identity: Identity{
			Tenant: "default",
		},
		Server: Server{
			Listen:            "127.0.0.1:8080",
			ID:                "local-server",
			KeyID:             "server-key",
			QueueSize:         1024,
			Workers:           4,
			ReadTimeout:       "10s",
			ReadHeaderTimeout: "5s",
			WriteTimeout:      "10s",
			IdleTimeout:       "120s",
			ShutdownTimeout:   "10s",
			Transport: ServerTransport{
				Mode:                transporttls.ModePlaintext,
				AllowLocalPlaintext: false,
				MinVersion:          "1.2",
				ReloadInterval:      "1m",
				Revocation:          transporttls.RevocationConfig{Mode: transporttls.RevocationOff},
			},
		},
		NATS: NATS{
			URLs:            []string{"nats://127.0.0.1:4222"},
			Stream:          "TRUSTDB_INGRESS_V2",
			Subject:         "trustdb.ingress.v2.claims",
			Durable:         "trustdb-ingress-v2",
			Provision:       true,
			StreamStorage:   "file",
			StreamReplicas:  1,
			StreamMaxBytes:  10 << 30,
			StreamMaxAge:    "0s",
			ResultStream:    "TRUSTDB_INGRESS_V2_RESULTS",
			ResultSubject:   "trustdb.ingress.v2.results.*",
			ResultMaxBytes:  10 << 30,
			ResultMaxAge:    "24h",
			DLQStream:       "TRUSTDB_INGRESS_V2_DLQ",
			DLQSubject:      "trustdb.ingress.v2.dlq.*",
			DLQMaxBytes:     1 << 30,
			DLQMaxAge:       "0s",
			DuplicateWindow: "2m",
			Workers:         0,
			FetchBatch:      256,
			FetchWait:       "1s",
			AckWait:         "30s",
			NakDelay:        "1s",
			ResultRetryWait: "1s",
			MaxAckPending:   2048,
			MaxDeliver:      10,
			ConnectTimeout:  "5s",
			ReconnectWait:   "1s",
			MaxReconnects:   -1,
			DrainTimeout:    "10s",
		},
		Registry: Registry{
			KeyID: "registry-key",
		},
		Batch: Batch{
			QueueSize:                1024,
			MaxRecords:               1024,
			MaxDelay:                 "500ms",
			ProofMode:                "inline",
			MaterializerWorkers:      2,
			MaterializerQueueSize:    4,
			MaterializerPollInterval: "250ms",
			ProofWorkers:             0,
		},
		WAL: WAL{
			FsyncMode:           "group",
			GroupCommitInterval: "10ms",
			MaxSegmentBytes:     0,
			KeepSegments:        0,
		},
		GlobalLog: GlobalLog{
			Enabled: true,
			LogID:   "trustdb-global-log",
		},
		Anchor: Anchor{
			Scope:        "global",
			MaxDelay:     "5m",
			PollInterval: "2s",
			Sink:         "",
			Path:         "",
			Plugin: AnchorPlugin{
				StartTimeout: "10s",
				RPCTimeout:   "30s",
			},
		},
		Crypto: Crypto{SignerPlugins: SignerPlugins{
			Remote: defaultSignerPlugin(),
			PKCS11: defaultSignerPlugin(),
			SDF:    defaultSignerPlugin(),
		}},
		History: History{
			TileSize:        256,
			HotWindowLeaves: 65536,
		},
		Backup: Backup{
			Compression: "gzip",
			KeyProvider: "passphrase-dev-v1",
			KeyID:       "development-backup-key",
			FrameBytes:  1 << 20,
		},
		Proofstore: Proofstore{
			ArtifactSyncMode: "chunk",
			RecordIndexMode:  "full",
			TiKVNamespace:    "default",
		},
		Admin: Admin{
			BasePath:         "/admin",
			PolicyPath:       ".trustdb/admin-policy.json",
			SessionTTL:       "8h",
			LoginMaxFailures: 5,
			LoginLockout:     "15m",
		},
		Audit: Audit{
			Path:             ".trustdb/audit/security.audit",
			CheckpointPath:   ".trustdb/audit/security.checkpoint",
			MaxBytes:         4 << 30,
			Retention:        "4380h",
			TimeMaxSampleAge: "2m",
			TimeMaxDrift:     "5s",
		},
		Log: Log{
			Level:  "warn",
			Format: "json",
			Output: "stderr",
			File: LogFile{
				Path:       ".trustdb/logs/trustdb.log",
				MaxSizeMB:  256,
				MaxBackups: 16,
				MaxAgeDays: 30,
				Compress:   true,
			},
			Async: LogAsync{
				BufferSize: 8192,
			},
		},
	}
}

func (c Config) Redacted() Config {
	c.Keys.ClientPrivate = redact(c.Keys.ClientPrivate)
	c.Keys.ClientPublic = redact(c.Keys.ClientPublic)
	c.Keys.ServerPrivate = redact(c.Keys.ServerPrivate)
	c.Keys.ServerPublic = redact(c.Keys.ServerPublic)
	c.Keys.RegistryPrivate = redact(c.Keys.RegistryPrivate)
	c.Keys.RegistryPublic = redact(c.Keys.RegistryPublic)
	c.NATS.Password = redact(c.NATS.Password)
	c.NATS.Token = redact(c.NATS.Token)
	c.Admin.SessionSecret = redact(c.Admin.SessionSecret)
	c.Server.Transport.KeyFile = redact(c.Server.Transport.KeyFile)
	c.Crypto.SignerPlugins.Remote.Args = redactArgs(c.Crypto.SignerPlugins.Remote.Args)
	c.Crypto.SignerPlugins.PKCS11.Args = redactArgs(c.Crypto.SignerPlugins.PKCS11.Args)
	c.Crypto.SignerPlugins.SDF.Args = redactArgs(c.Crypto.SignerPlugins.SDF.Args)
	return c
}

func defaultSignerPlugin() SignerPlugin {
	return SignerPlugin{StartTimeout: "10s", RPCTimeout: "30s"}
}

func redactArgs(args []string) []string {
	if len(args) == 0 {
		return nil
	}
	return []string{"<redacted>"}
}

func redact(value string) string {
	if value == "" {
		return ""
	}
	return "<redacted>"
}

func (c Config) Validate() error {
	if err := validateRunProfileField(c.RunProfile); err != nil {
		return err
	}
	if c.Paths.DataDir == "" {
		return fmt.Errorf("paths.data_dir is required")
	}
	if c.Paths.KeyRegistry == "" {
		return fmt.Errorf("paths.key_registry is required")
	}
	if c.Paths.WAL == "" {
		return fmt.Errorf("paths.wal is required")
	}
	if c.Paths.ProofDir == "" {
		return fmt.Errorf("paths.proof_dir is required")
	}
	if c.Identity.Tenant == "" {
		return fmt.Errorf("identity.tenant is required")
	}
	if c.Server.ID == "" {
		return fmt.Errorf("server.id is required")
	}
	if c.Server.KeyID == "" {
		return fmt.Errorf("server.key_id is required")
	}
	if c.Server.Listen == "" {
		return fmt.Errorf("server.listen is required")
	}
	if c.Server.QueueSize <= 0 {
		return fmt.Errorf("server.queue_size must be greater than 0")
	}
	if c.Server.Workers <= 0 {
		return fmt.Errorf("server.workers must be greater than 0")
	}
	if err := ValidateServerTransportPolicy(c.RunProfile, c.Server.Listen, c.Server.GRPCListen, c.Server.Transport); err != nil {
		return err
	}
	for _, tc := range []struct {
		name  string
		value string
	}{
		{name: "server.read_timeout", value: c.Server.ReadTimeout},
		{name: "server.read_header_timeout", value: c.Server.ReadHeaderTimeout},
		{name: "server.write_timeout", value: c.Server.WriteTimeout},
		{name: "server.idle_timeout", value: c.Server.IdleTimeout},
		{name: "server.shutdown_timeout", value: c.Server.ShutdownTimeout},
	} {
		if err := validateNonNegativeDuration(tc.name, tc.value); err != nil {
			return err
		}
	}
	if err := validateNATS(c.NATS); err != nil {
		return err
	}
	if c.Registry.KeyID == "" {
		return fmt.Errorf("registry.key_id is required")
	}
	if c.Batch.QueueSize <= 0 {
		return fmt.Errorf("batch.queue_size must be greater than 0")
	}
	if c.Batch.MaxRecords <= 0 {
		return fmt.Errorf("batch.max_records must be greater than 0")
	}
	if err := validatePositiveDuration("batch.max_delay", c.Batch.MaxDelay); err != nil {
		return err
	}
	if c.Batch.MaterializerWorkers <= 0 {
		return fmt.Errorf("batch.materializer_workers must be greater than 0")
	}
	if c.Batch.MaterializerQueueSize <= 0 {
		return fmt.Errorf("batch.materializer_queue_size must be greater than 0")
	}
	if err := validatePositiveDuration("batch.materializer_poll_interval", c.Batch.MaterializerPollInterval); err != nil {
		return err
	}
	if c.Batch.ProofWorkers < 0 {
		return fmt.Errorf("batch.proof_workers must be zero or greater")
	}
	switch strings.ToLower(c.Batch.ProofMode) {
	case "", "inline", "async", "on_demand":
	default:
		return fmt.Errorf("batch.proof_mode must be one of inline, async, or on_demand")
	}
	walMode := strings.ToLower(strings.TrimSpace(c.WAL.FsyncMode))
	switch walMode {
	case "strict", "group", "batch":
	default:
		return fmt.Errorf("wal.fsync_mode must be strict, group, or batch")
	}
	walGroupCommitInterval, err := time.ParseDuration(c.WAL.GroupCommitInterval)
	if err != nil {
		return fmt.Errorf("wal.group_commit_interval must be a valid duration: %w", err)
	}
	if walMode == "group" && walGroupCommitInterval <= 0 {
		return fmt.Errorf("wal.group_commit_interval must be greater than 0 when wal.fsync_mode is group")
	}
	if c.WAL.MaxSegmentBytes < 0 {
		return fmt.Errorf("wal.max_segment_bytes must be zero or greater")
	}
	if c.WAL.KeepSegments < 0 {
		return fmt.Errorf("wal.keep_segments must be zero or greater")
	}
	switch strings.ToLower(c.Anchor.Scope) {
	case "", "global":
	default:
		return fmt.Errorf("anchor.scope must be global")
	}
	if err := validatePositiveDuration("anchor.max_delay", c.Anchor.MaxDelay); err != nil {
		return err
	}
	if err := validatePositiveDuration("anchor.poll_interval", c.Anchor.PollInterval); err != nil {
		return err
	}
	if err := validatePositiveDuration("anchor.plugin.start_timeout", c.Anchor.Plugin.StartTimeout); err != nil {
		return err
	}
	if err := validatePositiveDuration("anchor.plugin.rpc_timeout", c.Anchor.Plugin.RPCTimeout); err != nil {
		return err
	}
	if strings.EqualFold(strings.TrimSpace(c.Anchor.Sink), "plugin") && strings.TrimSpace(c.Anchor.Plugin.Command) == "" {
		return fmt.Errorf("anchor.plugin.command is required when anchor.sink is plugin")
	}
	switch strings.ToLower(strings.TrimSpace(c.Anchor.Sink)) {
	case "fisco-bcos":
		if strings.TrimSpace(c.Anchor.FISCOBCOS.TrustConfigFile) == "" {
			return fmt.Errorf("anchor.fisco_bcos.trust_config_file is required when anchor.sink is fisco-bcos")
		}
	case "fisco-bcos-standard":
		return fmt.Errorf("anchor.sink fisco-bcos-standard is unsupported; use fisco-bcos with explicit crypto_mode")
	}
	for _, tc := range []struct {
		name   string
		plugin SignerPlugin
	}{
		{name: "remote", plugin: c.Crypto.SignerPlugins.Remote},
		{name: "pkcs11", plugin: c.Crypto.SignerPlugins.PKCS11},
		{name: "sdf", plugin: c.Crypto.SignerPlugins.SDF},
	} {
		if err := validateSignerPlugin(tc.name, tc.plugin); err != nil {
			return err
		}
	}
	if c.History.TileSize == 0 {
		return fmt.Errorf("history.tile_size must be greater than 0")
	}
	if c.History.HotWindowLeaves == 0 {
		return fmt.Errorf("history.hot_window_leaves must be greater than 0")
	}
	switch strings.ToLower(c.Backup.Compression) {
	case "", "gzip", "none":
	default:
		return fmt.Errorf("backup.compression must be gzip or none")
	}
	if strings.TrimSpace(c.Backup.KeyProvider) == "" || strings.TrimSpace(c.Backup.KeyID) == "" {
		return fmt.Errorf("backup.key_provider and backup.key_id are required")
	}
	if c.Backup.FrameBytes < 64<<10 || c.Backup.FrameBytes > 16<<20 {
		return fmt.Errorf("backup.frame_bytes must be between 65536 and 16777216")
	}
	switch strings.ToLower(c.Proofstore.ArtifactSyncMode) {
	case "", "chunk", "batch":
	default:
		return fmt.Errorf("proofstore.artifact_sync_mode must be chunk or batch")
	}
	switch strings.ToLower(c.Proofstore.RecordIndexMode) {
	case "", "full", "no_storage_tokens", "time_only":
	default:
		return fmt.Errorf("proofstore.record_index_mode must be one of full, no_storage_tokens, or time_only")
	}

	switch strings.ToLower(c.Log.Level) {
	case "", "debug", "info", "warn", "warning", "error":
	default:
		return fmt.Errorf("log.level must be one of debug, info, warn, warning, error")
	}
	switch strings.ToLower(c.Log.Format) {
	case "", "json", "console", "text":
	default:
		return fmt.Errorf("log.format must be json, console, or text")
	}
	switch strings.ToLower(c.Log.Output) {
	case "", "stderr", "file", "both":
	default:
		return fmt.Errorf("log.output must be stderr, file, or both")
	}
	if strings.EqualFold(c.Log.Output, "file") || strings.EqualFold(c.Log.Output, "both") {
		if c.Log.File.Path == "" {
			return fmt.Errorf("log.file.path is required when log.output is file or both")
		}
	}
	if c.Log.File.MaxSizeMB <= 0 {
		return fmt.Errorf("log.file.max_size_mb must be greater than 0")
	}
	if c.Log.File.MaxBackups < 0 {
		return fmt.Errorf("log.file.max_backups must be greater than or equal to 0")
	}
	if c.Log.File.MaxAgeDays < 0 {
		return fmt.Errorf("log.file.max_age_days must be greater than or equal to 0")
	}
	if c.Log.Async.BufferSize <= 0 {
		return fmt.Errorf("log.async.buffer_size must be greater than 0")
	}
	if err := validateAdmin(c.Admin); err != nil {
		return err
	}
	if err := validateAudit(c.RunProfile, c.Audit); err != nil {
		return err
	}
	if err := c.validateDeploymentPolicy(time.Now()); err != nil {
		return err
	}
	return nil
}

func validateAudit(runProfile string, audit Audit) error {
	profile := NormalizeRunProfile(runProfile)
	production := profile == RunProfileSingleNodeProduction || IsStrictDeploymentProfile(profile)
	if audit.Required && !audit.Enabled {
		return fmt.Errorf("audit.enabled must be true when audit.required is true")
	}
	if production && (!audit.Enabled || !audit.Required) {
		return fmt.Errorf("audit.enabled and audit.required must be true for %s", profile)
	}
	if !audit.Enabled {
		return nil
	}
	if strings.TrimSpace(audit.Path) == "" || strings.TrimSpace(audit.CheckpointPath) == "" || strings.TrimSpace(audit.SigningKey) == "" {
		return fmt.Errorf("audit.path, audit.checkpoint_path, and audit.signing_key are required when audit is enabled")
	}
	if filepath.Clean(audit.Path) == filepath.Clean(audit.CheckpointPath) {
		return fmt.Errorf("audit.path and audit.checkpoint_path must be different")
	}
	if audit.MaxBytes < 1<<20 {
		return fmt.Errorf("audit.max_bytes must be at least 1048576")
	}
	retention, err := time.ParseDuration(audit.Retention)
	if err != nil || retention < 24*time.Hour {
		return fmt.Errorf("audit.retention must be a valid duration of at least 24h")
	}
	if err := validatePositiveDuration("audit.time_max_sample_age", audit.TimeMaxSampleAge); err != nil {
		return err
	}
	if err := validatePositiveDuration("audit.time_max_drift", audit.TimeMaxDrift); err != nil {
		return err
	}
	if audit.RequireSynchronizedTime && strings.TrimSpace(audit.TimeReferencePath) == "" {
		return fmt.Errorf("audit.time_reference_path is required when synchronized time is required")
	}
	if production && !audit.RequireSynchronizedTime {
		return fmt.Errorf("audit.require_synchronized_time must be true for %s", profile)
	}
	return nil
}

// ValidateServerTransportPolicy validates TLS material policy and the narrow
// production plaintext exception. Production plaintext is accepted only when
// explicitly enabled and every active TCP listener is loopback-only.
func ValidateServerTransportPolicy(runProfile, httpListen, grpcListen string, config ServerTransport) error {
	if err := config.TLSConfig().Validate(); err != nil {
		return fmt.Errorf("server.transport: %w", err)
	}
	mode := strings.ToLower(strings.TrimSpace(config.Mode))
	if mode == "" {
		mode = transporttls.ModePlaintext
	}
	profile := NormalizeRunProfile(runProfile)
	production := profile == RunProfileSingleNodeProduction || IsStrictDeploymentProfile(profile)
	if mode != transporttls.ModePlaintext || !production {
		return nil
	}
	if !config.AllowLocalPlaintext {
		return fmt.Errorf("server.transport.allow_local_plaintext must be explicitly true for plaintext production listeners")
	}
	for name, address := range map[string]string{"server.listen": httpListen, "server.grpc_listen": grpcListen} {
		if strings.TrimSpace(address) == "" {
			continue
		}
		if !isLoopbackTCPAddress(address) {
			return fmt.Errorf("%s must be loopback-only when production plaintext exception is enabled", name)
		}
	}
	return nil
}

func validateSignerPlugin(name string, plugin SignerPlugin) error {
	prefix := "crypto.signer_plugins." + name
	if err := validatePositiveDuration(prefix+".start_timeout", plugin.StartTimeout); err != nil {
		return err
	}
	if err := validatePositiveDuration(prefix+".rpc_timeout", plugin.RPCTimeout); err != nil {
		return err
	}
	if plugin.MaxConcurrency < 0 || plugin.MaxConcurrency > 1024 {
		return fmt.Errorf("%s.max_concurrency must be between 0 and 1024", prefix)
	}
	if strings.TrimSpace(plugin.Command) == "" && (len(plugin.Args) > 0 || len(plugin.InheritEnv) > 0) {
		return fmt.Errorf("%s.command is required when args or inherit_env are configured", prefix)
	}
	seenEnv := make(map[string]struct{}, len(plugin.InheritEnv))
	for _, name := range plugin.InheritEnv {
		if !validEnvironmentName(name) {
			return fmt.Errorf("%s.inherit_env contains invalid variable name %q", prefix, name)
		}
		normalizedName := strings.ToUpper(name)
		if strings.HasPrefix(normalizedName, "TRUSTDB_SIGNER_PLUGIN_") {
			return fmt.Errorf("%s.inherit_env must not include reserved signer-plugin variables", prefix)
		}
		if _, exists := seenEnv[normalizedName]; exists {
			return fmt.Errorf("%s.inherit_env contains duplicate variable %q", prefix, name)
		}
		seenEnv[normalizedName] = struct{}{}
	}
	return nil
}

func isLoopbackTCPAddress(address string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return false
	}
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validEnvironmentName(name string) bool {
	if name == "" {
		return false
	}
	for index, r := range name {
		if index == 0 {
			if !(r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
				return false
			}
			continue
		}
		if !(r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func validateNATS(n NATS) error {
	if !n.Enabled {
		return nil
	}
	if len(n.URLs) == 0 {
		return fmt.Errorf("nats.urls must contain at least one URL when nats.enabled is true")
	}
	for _, raw := range n.URLs {
		if err := validateNATSURL(raw); err != nil {
			return err
		}
	}
	if err := validateNATSName("nats.stream", n.Stream); err != nil {
		return err
	}
	if err := validateNATSSubject(n.Subject); err != nil {
		return err
	}
	if err := validateNATSName("nats.durable", n.Durable); err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(n.StreamStorage)) {
	case "file", "memory":
	default:
		return fmt.Errorf("nats.stream_storage must be file or memory")
	}
	if n.StreamReplicas < 1 || n.StreamReplicas > 5 {
		return fmt.Errorf("nats.stream_replicas must be between 1 and 5")
	}
	if n.StreamMaxBytes <= 0 {
		return fmt.Errorf("nats.stream_max_bytes must be greater than 0")
	}
	if err := validateNonNegativeDuration("nats.stream_max_age", n.StreamMaxAge); err != nil {
		return err
	}
	for _, stream := range []struct {
		field string
		value string
	}{
		{field: "nats.result_stream", value: n.ResultStream},
		{field: "nats.dlq_stream", value: n.DLQStream},
	} {
		if err := validateNATSName(stream.field, stream.value); err != nil {
			return err
		}
	}
	if n.Stream == n.ResultStream || n.Stream == n.DLQStream || n.ResultStream == n.DLQStream {
		return fmt.Errorf("nats.stream, nats.result_stream, and nats.dlq_stream must be distinct")
	}
	if err := validateNATSOutcomeSubject("nats.result_subject", n.ResultSubject); err != nil {
		return err
	}
	if err := validateNATSOutcomeSubject("nats.dlq_subject", n.DLQSubject); err != nil {
		return err
	}
	if n.ResultSubject == n.DLQSubject || natsSubjectMatches(n.ResultSubject, n.Subject) || natsSubjectMatches(n.DLQSubject, n.Subject) {
		return fmt.Errorf("nats.subject, nats.result_subject, and nats.dlq_subject must not overlap")
	}
	if n.ResultMaxBytes <= 0 {
		return fmt.Errorf("nats.result_max_bytes must be greater than 0")
	}
	if err := validateNonNegativeDuration("nats.result_max_age", n.ResultMaxAge); err != nil {
		return err
	}
	if n.DLQMaxBytes <= 0 {
		return fmt.Errorf("nats.dlq_max_bytes must be greater than 0")
	}
	if err := validateNonNegativeDuration("nats.dlq_max_age", n.DLQMaxAge); err != nil {
		return err
	}
	if err := validatePositiveDuration("nats.duplicate_window", n.DuplicateWindow); err != nil {
		return err
	}
	if n.Workers < 0 {
		return fmt.Errorf("nats.workers must be zero or greater")
	}
	if n.FetchBatch <= 0 {
		return fmt.Errorf("nats.fetch_batch must be greater than 0")
	}
	if n.MaxAckPending <= 0 {
		return fmt.Errorf("nats.max_ack_pending must be greater than 0")
	}
	if n.MaxDeliver <= 0 {
		return fmt.Errorf("nats.max_deliver must be greater than 0")
	}
	if n.FetchBatch > n.MaxAckPending {
		return fmt.Errorf("nats.fetch_batch must not exceed nats.max_ack_pending")
	}
	if n.Workers > n.MaxAckPending {
		return fmt.Errorf("nats.workers must not exceed nats.max_ack_pending")
	}
	for _, tc := range []struct {
		name  string
		value string
	}{
		{name: "nats.fetch_wait", value: n.FetchWait},
		{name: "nats.ack_wait", value: n.AckWait},
		{name: "nats.nak_delay", value: n.NakDelay},
		{name: "nats.outcome_retry_wait", value: n.ResultRetryWait},
		{name: "nats.connect_timeout", value: n.ConnectTimeout},
		{name: "nats.reconnect_wait", value: n.ReconnectWait},
		{name: "nats.drain_timeout", value: n.DrainTimeout},
	} {
		if err := validatePositiveDuration(tc.name, tc.value); err != nil {
			return err
		}
	}
	if fetchWait, _ := time.ParseDuration(n.FetchWait); fetchWait < time.Second {
		return fmt.Errorf("nats.fetch_wait must be at least 1s")
	}
	if n.MaxReconnects < -1 {
		return fmt.Errorf("nats.max_reconnects must be -1 or greater")
	}
	if err := validateNATSAuth(n); err != nil {
		return err
	}
	if (strings.TrimSpace(n.TLS.CertFile) == "") != (strings.TrimSpace(n.TLS.KeyFile) == "") {
		return fmt.Errorf("nats.tls.cert_file and nats.tls.key_file must be configured together")
	}
	return nil
}

// Validate checks the optional NATS ingress configuration in isolation.
func (n NATS) Validate() error {
	return validateNATS(n)
}

func validateNATSURL(raw string) error {
	trimmed := strings.TrimSpace(raw)
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("nats.urls contains invalid URL %q", raw)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "nats", "tls", "ws", "wss":
	default:
		return fmt.Errorf("nats.urls contains unsupported scheme %q", parsed.Scheme)
	}
	if parsed.User != nil {
		return fmt.Errorf("nats.urls must not contain credentials; use nats authentication fields")
	}
	return nil
}

func validateNATSName(field, value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fmt.Errorf("%s is required when nats.enabled is true", field)
	}
	if strings.ContainsAny(trimmed, ".*>/\\") || strings.IndexFunc(trimmed, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\r' || r == '\n'
	}) >= 0 {
		return fmt.Errorf("%s contains characters that NATS does not allow", field)
	}
	return nil
}

func validateNATSSubject(value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fmt.Errorf("nats.subject is required when nats.enabled is true")
	}
	if strings.ContainsAny(trimmed, "*> \t\r\n") || strings.HasPrefix(trimmed, ".") || strings.HasSuffix(trimmed, ".") || strings.Contains(trimmed, "..") {
		return fmt.Errorf("nats.subject must be a concrete NATS subject without wildcards or empty tokens")
	}
	return nil
}

func validateNATSOutcomeSubject(field, value string) error {
	trimmed := strings.TrimSpace(value)
	if !strings.HasSuffix(trimmed, ".*") || strings.Count(trimmed, "*") != 1 || strings.Contains(trimmed, ">") {
		return fmt.Errorf("%s must be a NATS subject pattern ending in .*", field)
	}
	prefix := strings.TrimSuffix(trimmed, ".*")
	if err := validateNATSSubject(prefix); err != nil {
		return fmt.Errorf("%s must be a valid NATS subject pattern ending in .*", field)
	}
	return nil
}

func natsSubjectMatches(pattern, subject string) bool {
	prefix := strings.TrimSuffix(pattern, "*")
	if !strings.HasPrefix(subject, prefix) {
		return false
	}
	return !strings.Contains(strings.TrimPrefix(subject, prefix), ".")
}

func validateNATSAuth(n NATS) error {
	credentialsFile := strings.TrimSpace(n.CredentialsFile)
	username := strings.TrimSpace(n.Username)
	password := strings.TrimSpace(n.Password)
	token := strings.TrimSpace(n.Token)
	if (username == "") != (password == "") {
		return fmt.Errorf("nats.username and nats.password must be configured together")
	}
	modes := 0
	if credentialsFile != "" {
		modes++
	}
	if username != "" {
		modes++
	}
	if token != "" {
		modes++
	}
	if modes > 1 {
		return fmt.Errorf("nats authentication methods are mutually exclusive")
	}
	return nil
}

func validateAdmin(a Admin) error {
	if !a.Enabled && !a.CLIEnforce {
		return nil
	}
	if strings.TrimSpace(a.PolicyPath) == "" {
		return fmt.Errorf("admin.policy_path is required when administrative authorization is enabled")
	}
	if !a.Enabled {
		return nil
	}
	secret := strings.TrimSpace(a.SessionSecret)
	if len(secret) < 32 {
		return fmt.Errorf("admin.session_secret must be at least 32 bytes when admin.enabled is true")
	}
	webDir := strings.TrimSpace(a.WebDir)
	if webDir == "" {
		return fmt.Errorf("admin.web_dir is required when admin.enabled is true")
	}
	if _, err := os.Stat(filepath.Join(webDir, "index.html")); err != nil {
		return fmt.Errorf("admin.web_dir must contain index.html: %w", err)
	}
	if a.SessionTTL != "" {
		if err := validatePositiveDuration("admin.session_ttl", a.SessionTTL); err != nil {
			return err
		}
	}
	if a.LoginMaxFailures < 1 || a.LoginMaxFailures > 100 {
		return fmt.Errorf("admin.login_max_failures must be between 1 and 100")
	}
	if err := validatePositiveDuration("admin.login_lockout", a.LoginLockout); err != nil {
		return err
	}
	for index, pin := range a.OIDCGatewayPins {
		if len(pin) != 64 || strings.ToLower(pin) != pin {
			return fmt.Errorf("admin.oidc_gateway_spki_sha256[%d] must be lowercase SHA-256 hex", index)
		}
		if _, err := hex.DecodeString(pin); err != nil {
			return fmt.Errorf("admin.oidc_gateway_spki_sha256[%d] must be lowercase SHA-256 hex", index)
		}
		if index > 0 && a.OIDCGatewayPins[index-1] >= pin {
			return fmt.Errorf("admin.oidc_gateway_spki_sha256 must be sorted and unique")
		}
	}
	bp := strings.TrimSpace(a.BasePath)
	if bp == "" {
		return fmt.Errorf("admin.base_path is required when admin.enabled is true")
	}
	if !strings.HasPrefix(bp, "/") {
		return fmt.Errorf("admin.base_path must start with /")
	}
	return nil
}

func validateNonNegativeDuration(name, value string) error {
	d, err := time.ParseDuration(value)
	if err != nil {
		return fmt.Errorf("%s must be a valid duration: %w", name, err)
	}
	if d < 0 {
		return fmt.Errorf("%s must be greater than or equal to 0", name)
	}
	return nil
}

func validatePositiveDuration(name, value string) error {
	d, err := time.ParseDuration(value)
	if err != nil {
		return fmt.Errorf("%s must be a valid duration: %w", name, err)
	}
	if d <= 0 {
		return fmt.Errorf("%s must be greater than 0", name)
	}
	return nil
}
