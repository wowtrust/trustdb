package main

import (
	"context"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wowtrust/trustdb/internal/adminauth"
	trustbackup "github.com/wowtrust/trustdb/internal/backup"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/keyenvelope"
	"github.com/wowtrust/trustdb/internal/proofstore"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

const (
	backupPassphraseEnv     = "TRUSTDB_BACKUP_PASSPHRASE"
	backupPassphraseFileEnv = "TRUSTDB_BACKUP_PASSPHRASE_FILE"
)

func newBackupCommand(rt *runtimeConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Create, verify, and restore portable .tdbackup archives",
	}
	cmd.AddCommand(newBackupCreateCommand(rt))
	cmd.AddCommand(newBackupVerifyCommand(rt))
	cmd.AddCommand(newBackupRestoreCommand(rt))
	return cmd
}

func newBackupCreateCommand(rt *runtimeConfig) *cobra.Command {
	var metastoreKind, metastorePath, proofDir, outPath, compression, keyProvider, keyID, keyRegistryPath string
	var frameBytes int
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Export proofstore data into a portable .tdbackup archive",
		RunE: func(cmd *cobra.Command, args []string) error {
			if outPath == "" {
				return usageError("backup create requires --out")
			}
			compression = stringOrLiteral(cmd, "compression", compression, rt.cfg.Backup.Compression)
			keyProvider = stringOrLiteral(cmd, "key-provider", keyProvider, rt.cfg.Backup.KeyProvider)
			keyID = stringOrLiteral(cmd, "key-id", keyID, rt.cfg.Backup.KeyID)
			if !cmd.Flags().Changed("key-registry") {
				keyRegistryPath = rt.cfg.Paths.KeyRegistry
			}
			frameBytes = intOrLiteral(cmd, "frame-bytes", frameBytes, rt.cfg.Backup.FrameBytes)
			provider, err := backupKEKProvider(keyProvider)
			if err != nil {
				return err
			}
			store, closeFn, err := openProofStoreForCLI(cmd, rt, metastoreKind, metastorePath, proofDir, rt.cfg.Paths.ProofDir)
			if err != nil {
				return err
			}
			defer closeFn()
			report, err := trustbackup.Create(context.Background(), store, outPath, trustbackup.Options{
				Compression:     compression,
				FrameBytes:      frameBytes,
				KEKProvider:     provider,
				KEKKeyID:        keyID,
				KeyRegistryPath: keyRegistryPath,
			})
			if err != nil {
				return err
			}
			return rt.writeJSON(report)
		},
	}
	addProofStoreFlags(cmd, &metastoreKind, &metastorePath, &proofDir)
	cmd.Flags().StringVar(&outPath, "out", "", "output .tdbackup path")
	cmd.Flags().StringVar(&compression, "compression", "", "backup compression: gzip or none")
	cmd.Flags().StringVar(&keyProvider, "key-provider", "", "KEK provider name (built-in: passphrase-dev-v1)")
	cmd.Flags().StringVar(&keyID, "key-id", "", "non-secret KEK key reference stored in the backup header")
	cmd.Flags().IntVar(&frameBytes, "frame-bytes", 0, "encrypted frame plaintext bytes (65536..16777216)")
	cmd.Flags().StringVar(&keyRegistryPath, "key-registry", "", "V2 key registry audit file to include; use --key-registry= to omit it (defaults to paths.key_registry)")
	return requirePermission(cmd, adminauth.PermissionBackupCreate)
}

func newBackupVerifyCommand(rt *runtimeConfig) *cobra.Command {
	var filePath, keyProvider string
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify that a .tdbackup archive is readable and internally typed",
		RunE: func(cmd *cobra.Command, args []string) error {
			if filePath == "" {
				return usageError("backup verify requires --file")
			}
			keyProvider = stringOrLiteral(cmd, "key-provider", keyProvider, rt.cfg.Backup.KeyProvider)
			provider, err := backupKEKProvider(keyProvider)
			if err != nil {
				return err
			}
			report, err := trustbackup.Verify(context.Background(), filePath, provider)
			if err != nil {
				return err
			}
			return rt.writeJSON(report)
		},
	}
	cmd.Flags().StringVar(&filePath, "file", "", ".tdbackup path")
	cmd.Flags().StringVar(&keyProvider, "key-provider", "", "KEK provider name (built-in: passphrase-dev-v1)")
	return requirePermission(cmd, adminauth.PermissionBackupRead)
}

func newBackupRestoreCommand(rt *runtimeConfig) *cobra.Command {
	var metastoreKind, metastorePath, proofDir, filePath, keyProvider, recoveryDir string
	var resume bool
	var checkpointPath string
	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Restore a portable .tdbackup archive into a file, Pebble, or TiKV proofstore",
		RunE: func(cmd *cobra.Command, args []string) error {
			if filePath == "" {
				return usageError("backup restore requires --file")
			}
			keyProvider = stringOrLiteral(cmd, "key-provider", keyProvider, rt.cfg.Backup.KeyProvider)
			provider, err := backupKEKProvider(keyProvider)
			if err != nil {
				return err
			}
			if strings.TrimSpace(recoveryDir) == "" {
				recoveryDir = filePath + ".recovery"
			}
			store, closeFn, err := openProofStoreForCLI(cmd, rt, metastoreKind, metastorePath, proofDir, rt.cfg.Paths.ProofDir)
			if err != nil {
				return err
			}
			defer closeFn()
			report, err := trustbackup.RestoreWithOptions(context.Background(), store, filePath, trustbackup.RestoreOptions{
				Resume:         resume,
				CheckpointPath: checkpointPath,
				KEKProviders:   []keyenvelope.KEKProvider{provider},
				RecoveryDir:    recoveryDir,
			})
			if err != nil {
				return err
			}
			return rt.writeJSON(report)
		},
	}
	addProofStoreFlags(cmd, &metastoreKind, &metastorePath, &proofDir)
	cmd.Flags().StringVar(&filePath, "file", "", ".tdbackup path")
	cmd.Flags().BoolVar(&resume, "resume", true, "resume restore using a checkpoint file")
	cmd.Flags().StringVar(&checkpointPath, "checkpoint", "", "restore checkpoint path (defaults to <file>.restore-checkpoint.json)")
	cmd.Flags().StringVar(&keyProvider, "key-provider", "", "KEK provider name (built-in: passphrase-dev-v1)")
	cmd.Flags().StringVar(&recoveryDir, "recovery-dir", "", "directory for restored key registry audit evidence (defaults to <file>.recovery)")
	return requirePermission(cmd, adminauth.PermissionBackupRestore)
}

func backupKEKProvider(name string) (keyenvelope.KEKProvider, error) {
	switch strings.TrimSpace(name) {
	case keyenvelope.PassphraseProvider:
		return keyenvelope.NewPassphraseKEKProvider(
			keyenvelope.EnvironmentOrFilePassphraseSource(backupPassphraseEnv, backupPassphraseFileEnv),
		), nil
	case "":
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "backup key provider is required")
	default:
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "unsupported backup key provider")
	}
}

func addProofStoreFlags(cmd *cobra.Command, kind, path, proofDir *string) {
	cmd.Flags().StringVar(kind, "metastore", "", "proof store backend: file (default), pebble, or tikv")
	cmd.Flags().StringVar(path, "metastore-path", "", "proof store path; falls back to --proof-dir")
	cmd.Flags().StringVar(proofDir, "proof-dir", "", "file backend proof directory")
	cmd.Flags().String("crypto-suite", "", "expected proofstore cryptographic suite: INTL_V1 or CN_SM_V1 (required)")
}

func openProofStoreForCLI(cmd *cobra.Command, rt *runtimeConfig, kindText, path, proofDir, defaultProofDir string) (proofstore.Store, func(), error) {
	kind := proofstore.Backend(strings.TrimSpace(kindText))
	if kind == "" {
		kind = proofstore.BackendFile
	}
	storePath := strings.TrimSpace(path)
	if storePath == "" {
		storePath = strings.TrimSpace(proofDir)
	}
	if storePath == "" {
		storePath = defaultProofDir
	}
	if storePath == "" && kind != proofstore.BackendTiKV {
		return nil, nil, usageError("--metastore-path or --proof-dir is required")
	}
	tikvPDAddresses := append([]string(nil), rt.cfg.Proofstore.TiKVPDAddresses...)
	if kind == proofstore.BackendTiKV && storePath != "" {
		tikvPDAddresses = splitCommaValues(storePath)
	}
	if kind == proofstore.BackendTiKV && len(tikvPDAddresses) == 0 {
		return nil, nil, usageError("TiKV backup requires proofstore.tikv_pd_endpoints or --metastore-path with comma-separated PD endpoints")
	}
	suiteText, err := cmd.Flags().GetString("crypto-suite")
	if err != nil {
		return nil, nil, trusterr.Wrap(trusterr.CodeInternal, "read --crypto-suite", err)
	}
	suiteID := cryptosuite.ID(strings.TrimSpace(suiteText))
	if suiteID == "" {
		return nil, nil, usageError("--crypto-suite is required")
	}
	if _, err := cryptosuite.RequireKnown(suiteID); err != nil {
		return nil, nil, trusterr.Wrap(trusterr.CodeInvalidArgument, "validate --crypto-suite", err)
	}
	nodeID := strings.TrimSpace(rt.cfg.Server.ID)
	logID := strings.TrimSpace(rt.cfg.GlobalLog.LogID)
	if nodeID == "" || logID == "" {
		return nil, nil, trusterr.New(trusterr.CodeInvalidArgument, "configured server.id and global_log.log_id are required")
	}
	namespacePath := storePath
	if kind == proofstore.BackendTiKV {
		namespacePath = strings.Join(tikvPDAddresses, ",")
	}
	store, err := proofstore.Open(proofstore.Config{
		Kind:            kind,
		Path:            storePath,
		TiKVPDAddresses: tikvPDAddresses,
		TiKVKeyspace:    rt.cfg.Proofstore.TiKVKeyspace,
		TiKVNamespace:   rt.cfg.Proofstore.TiKVNamespace,
		CryptoSuite:     suiteID,
		NodeID:          nodeID,
		LogID:           logID,
		NamespaceID:     proofstoreNamespaceID(string(kind), namespacePath, rt.cfg.Proofstore.TiKVKeyspace, rt.cfg.Proofstore.TiKVNamespace),
	})
	if err != nil {
		return nil, nil, trusterr.Wrap(trusterr.CodeInternal, "open proofstore", err)
	}
	return store, func() { _ = store.Close() }, nil
}

func splitCommaValues(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
