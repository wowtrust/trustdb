package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/wowtrust/trustdb/internal/adminauth"
	"github.com/wowtrust/trustdb/internal/securityaudit"
)

func newAuditCommand(rt *runtimeConfig) *cobra.Command {
	command := &cobra.Command{Use: "audit", Short: "Inspect, export, and verify the immutable security audit trail"}
	command.AddCommand(newAuditStatusCommand(rt))
	command.AddCommand(newAuditExportCommand(rt))
	command.AddCommand(newAuditVerifyCommand(rt))
	command.AddCommand(newAuditCheckpointCommand(rt))
	return command
}

func newAuditCheckpointCommand(rt *runtimeConfig) *cobra.Command {
	command := &cobra.Command{Use: "checkpoint", Short: "Export or verify a signed audit checkpoint for external retention or anchoring"}
	command.AddCommand(newAuditCheckpointExportCommand(rt))
	command.AddCommand(newAuditCheckpointVerifyCommand(rt))
	return command
}

func newAuditCheckpointExportCommand(rt *runtimeConfig) *cobra.Command {
	var outputPath string
	command := &cobra.Command{
		Use: "export", Short: "Export the latest signed audit checkpoint",
		RunE: func(command *cobra.Command, _ []string) error {
			if rt.auditor == nil {
				return errors.New("security audit is not enabled")
			}
			if outputPath == "" {
				return usageError("--out is required")
			}
			artifact, err := rt.auditor.Checkpoint(command.Context())
			if err != nil {
				return err
			}
			if err := writeJSONFile(outputPath, artifact); err != nil {
				return err
			}
			return rt.writeJSON(map[string]any{"ok": true, "path": outputPath, "sequence": artifact.Checkpoint.Checkpoint.Sequence, "event_hash": artifact.Checkpoint.Checkpoint.EventHash})
		},
	}
	command.Flags().StringVar(&outputPath, "out", "", "destination signed checkpoint JSON file")
	return requirePermission(command, adminauth.PermissionAuditExport)
}

func newAuditCheckpointVerifyCommand(rt *runtimeConfig) *cobra.Command {
	var inputPath, publicKeyPath string
	command := &cobra.Command{
		Use: "verify", Short: "Verify a signed checkpoint without network access",
		RunE: func(command *cobra.Command, _ []string) error {
			if inputPath == "" || publicKeyPath == "" {
				return usageError("--file and --public-key are required")
			}
			publicKey, _, err := readPublicKeyDescriptor(publicKeyPath)
			if err != nil {
				return err
			}
			file, err := os.Open(inputPath)
			if err != nil {
				return err
			}
			defer file.Close()
			stats, err := securityaudit.VerifyCheckpointArtifact(command.Context(), file, publicKey)
			if err != nil {
				return err
			}
			return rt.writeJSON(map[string]any{"ok": true, "file": inputPath, "stats": stats, "network_used": false})
		},
	}
	command.Flags().StringVar(&inputPath, "file", "", "signed checkpoint JSON file")
	command.Flags().StringVar(&publicKeyPath, "public-key", "", "trusted local audit public-key descriptor")
	return command
}

func newAuditStatusCommand(rt *runtimeConfig) *cobra.Command {
	command := &cobra.Command{
		Use: "status", Short: "Verify the configured audit chain and signed checkpoint",
		RunE: func(command *cobra.Command, _ []string) error {
			if rt.auditor == nil {
				return errors.New("security audit is not enabled")
			}
			stats, err := rt.auditor.Verify(command.Context())
			if err != nil {
				return err
			}
			return rt.writeJSON(map[string]any{"ok": true, "stats": stats, "path": rt.cfg.Audit.Path, "checkpoint_path": rt.cfg.Audit.CheckpointPath})
		},
	}
	return requirePermission(command, adminauth.PermissionAuditRead)
}

func newAuditExportCommand(rt *runtimeConfig) *cobra.Command {
	var outputPath string
	command := &cobra.Command{
		Use: "export", Short: "Export a complete independently verifiable JSONL audit artifact",
		RunE: func(command *cobra.Command, _ []string) error {
			if rt.auditor == nil {
				return errors.New("security audit is not enabled")
			}
			if outputPath == "" {
				return usageError("--out is required")
			}
			stats, err := exportAuditAtomic(command.Context(), rt.auditor, outputPath)
			if err != nil {
				return err
			}
			return rt.writeJSON(map[string]any{"ok": true, "path": outputPath, "stats": stats})
		},
	}
	command.Flags().StringVar(&outputPath, "out", "", "destination JSONL file (required)")
	return requirePermission(command, adminauth.PermissionAuditExport)
}

func newAuditVerifyCommand(rt *runtimeConfig) *cobra.Command {
	var inputPath, publicKeyPath string
	command := &cobra.Command{
		Use: "verify", Short: "Verify an exported audit artifact without network access",
		RunE: func(command *cobra.Command, _ []string) error {
			if inputPath == "" || publicKeyPath == "" {
				return usageError("--file and --public-key are required")
			}
			publicKey, _, err := readPublicKeyDescriptor(publicKeyPath)
			if err != nil {
				return err
			}
			file, err := os.Open(inputPath)
			if err != nil {
				return err
			}
			defer file.Close()
			stats, err := securityaudit.VerifyExportJSONL(command.Context(), file, publicKey)
			if err != nil {
				return err
			}
			return rt.writeJSON(map[string]any{"ok": true, "file": inputPath, "stats": stats, "network_used": false})
		},
	}
	command.Flags().StringVar(&inputPath, "file", "", "exported audit JSONL file")
	command.Flags().StringVar(&publicKeyPath, "public-key", "", "trusted local audit public-key descriptor")
	return command
}

func exportAuditAtomic(ctx context.Context, auditor *securityaudit.Writer, target string) (securityaudit.Stats, error) {
	dir := filepath.Dir(target)
	if err := ensureDir(dir); err != nil {
		return securityaudit.Stats{}, err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(target)+".*.tmp")
	if err != nil {
		return securityaudit.Stats{}, err
	}
	tmpPath := tmp.Name()
	closed := false
	cleanup := true
	defer func() {
		if !closed {
			_ = tmp.Close()
		}
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return securityaudit.Stats{}, err
	}
	stats, err := auditor.ExportJSONL(ctx, tmp)
	if err != nil {
		return securityaudit.Stats{}, err
	}
	if err := tmp.Sync(); err != nil {
		return securityaudit.Stats{}, err
	}
	if err := tmp.Close(); err != nil {
		closed = true
		return securityaudit.Stats{}, err
	}
	closed = true
	if err := renameReplace(tmpPath, target); err != nil {
		return securityaudit.Stats{}, fmt.Errorf("install audit export: %w", err)
	}
	if err := syncDirectoryDurable(dir); err != nil {
		return securityaudit.Stats{}, err
	}
	cleanup = false
	return stats, nil
}
