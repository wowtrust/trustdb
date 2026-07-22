package main

import (
	"context"
	"strings"

	trustbackup "github.com/wowtrust/trustdb/internal/backup"
	"github.com/wowtrust/trustdb/internal/proofstore"
	"github.com/wowtrust/trustdb/internal/trusterr"
	"github.com/spf13/cobra"
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
	var metastoreKind, metastorePath, proofDir, outPath, compression string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Export proofstore data into a portable .tdbackup archive",
		RunE: func(cmd *cobra.Command, args []string) error {
			if outPath == "" {
				return usageError("backup create requires --out")
			}
			compression = stringOrLiteral(cmd, "compression", compression, rt.cfg.Backup.Compression)
			store, closeFn, err := openProofStoreForCLI(metastoreKind, metastorePath, proofDir, rt.cfg.Paths.ProofDir)
			if err != nil {
				return err
			}
			defer closeFn()
			report, err := trustbackup.Create(context.Background(), store, outPath, trustbackup.Options{
				Compression: compression,
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
	return cmd
}

func newBackupVerifyCommand(rt *runtimeConfig) *cobra.Command {
	var filePath string
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify that a .tdbackup archive is readable and internally typed",
		RunE: func(cmd *cobra.Command, args []string) error {
			if filePath == "" {
				return usageError("backup verify requires --file")
			}
			report, err := trustbackup.Verify(context.Background(), filePath)
			if err != nil {
				return err
			}
			return rt.writeJSON(report)
		},
	}
	cmd.Flags().StringVar(&filePath, "file", "", ".tdbackup path")
	return cmd
}

func newBackupRestoreCommand(rt *runtimeConfig) *cobra.Command {
	var metastoreKind, metastorePath, proofDir, filePath string
	var resume bool
	var checkpointPath string
	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Restore a portable .tdbackup archive into a file or Pebble proofstore",
		RunE: func(cmd *cobra.Command, args []string) error {
			if filePath == "" {
				return usageError("backup restore requires --file")
			}
			store, closeFn, err := openProofStoreForCLI(metastoreKind, metastorePath, proofDir, rt.cfg.Paths.ProofDir)
			if err != nil {
				return err
			}
			defer closeFn()
			report, err := trustbackup.RestoreWithOptions(context.Background(), store, filePath, trustbackup.RestoreOptions{
				Resume:         resume,
				CheckpointPath: checkpointPath,
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
	return cmd
}

func addProofStoreFlags(cmd *cobra.Command, kind, path, proofDir *string) {
	cmd.Flags().StringVar(kind, "metastore", "", "proof store backend: file (default) or pebble")
	cmd.Flags().StringVar(path, "metastore-path", "", "proof store path; falls back to --proof-dir")
	cmd.Flags().StringVar(proofDir, "proof-dir", "", "file backend proof directory")
}

func openProofStoreForCLI(kindText, path, proofDir, defaultProofDir string) (proofstore.Store, func(), error) {
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
	if storePath == "" {
		return nil, nil, usageError("--metastore-path or --proof-dir is required")
	}
	store, err := proofstore.Open(proofstore.Config{Kind: kind, Path: storePath})
	if err != nil {
		return nil, nil, trusterr.Wrap(trusterr.CodeInternal, "open proofstore", err)
	}
	return store, func() { _ = store.Close() }, nil
}
