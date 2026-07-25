package main

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wowtrust/trustdb/internal/adminauth"
	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/claim"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"github.com/wowtrust/trustdb/internal/trusterr"
	"github.com/wowtrust/trustdb/internal/wal"
)

// walIsDirectory returns true when the given path exists and is a directory.
// It returns a wrapped error for other stat failures; a missing path is
// treated as "not a directory" so an explicitly bound V2 single-file WAL can
// still be initialized by the caller.
func walIsDirectory(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, trusterr.Wrap(trusterr.CodeInternal, "stat wal path", err)
	}
	return info.IsDir(), nil
}

func newWALCommand(rt *runtimeConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "wal",
		Short: "Inspect and repair local WAL files",
	}
	cmd.AddCommand(newWALInspectCommand(rt))
	cmd.AddCommand(newWALRepairCommand(rt))
	cmd.AddCommand(newWALDumpCommand(rt))
	cmd.PersistentFlags().String("crypto-suite", "", "expected WAL cryptographic suite: INTL_V1 or CN_SM_V1 (required)")
	return cmd
}

func newWALInspectCommand(rt *runtimeConfig) *cobra.Command {
	var walPath string
	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Inspect WAL integrity and high-water mark",
		RunE: func(cmd *cobra.Command, args []string) error {
			walPath = stringOrConfig(cmd, rt, "wal", walPath, "wal")
			isDir, err := walIsDirectory(walPath)
			if err != nil {
				return err
			}
			opts, err := walOptionsForCLI(cmd, rt, walPath)
			if err != nil {
				return err
			}
			if isDir {
				result, err := wal.InspectDir(walPath, opts)
				if err != nil {
					return err
				}
				return rt.writeJSON(result)
			}
			result, err := wal.Inspect(walPath, opts)
			if err != nil {
				return err
			}
			return rt.writeJSON(result)
		},
	}
	cmd.Flags().StringVar(&walPath, "wal", "", "wal path (file or directory)")
	return requirePermission(cmd, adminauth.PermissionSystemRead)
}

func newWALDumpCommand(rt *runtimeConfig) *cobra.Command {
	var walPath string
	var limit int
	cmd := &cobra.Command{
		Use:   "dump",
		Short: "Dump WAL record summaries",
		RunE: func(cmd *cobra.Command, args []string) error {
			walPath = stringOrConfig(cmd, rt, "wal", walPath, "wal")
			isDir, err := walIsDirectory(walPath)
			if err != nil {
				return err
			}
			opts, err := walOptionsForCLI(cmd, rt, walPath)
			if err != nil {
				return err
			}
			var records []wal.Record
			if isDir {
				records, err = wal.ReadAllDir(walPath, opts)
			} else {
				records, err = wal.ReadAll(walPath, opts)
			}
			if err != nil {
				return err
			}
			provider, err := trustcrypto.ProviderForSuite(opts.CryptoSuite)
			if err != nil {
				return trusterr.Wrap(trusterr.CodeFailedPrecondition, "open WAL cryptographic suite", err)
			}
			if limit > 0 && len(records) > limit {
				records = records[:limit]
			}
			out := make([]map[string]any, len(records))
			for i, record := range records {
				item := map[string]any{
					"segment_id":  record.Position.SegmentID,
					"offset":      record.Position.Offset,
					"sequence":    record.Position.Sequence,
					"unix_nano":   record.UnixNano,
					"payload_len": len(record.Payload),
					"record_hash": base64.RawURLEncoding.EncodeToString(record.RecordHash[:]),
				}
				var signed model.SignedClaim
				if err := cborx.Unmarshal(record.Payload, &signed); err == nil {
					claimCBOR, err := claim.Canonical(signed.Claim)
					if err == nil {
						recordID, recordIDErr := claim.RecordIDWithProvider(provider, claimCBOR, signed.Signature)
						if recordIDErr == nil {
							item["record_id"] = recordID
						}
					}
					item["tenant"] = signed.Claim.TenantID
					item["client"] = signed.Claim.ClientID
					item["key_id"] = signed.Claim.KeyID
					item["content_length"] = signed.Claim.Content.ContentLength
					item["storage_uri"] = signed.Claim.Content.StorageURI
				}
				out[i] = item
			}
			return rt.writeJSON(out)
		},
	}
	cmd.Flags().StringVar(&walPath, "wal", "", "wal path (file or directory)")
	cmd.Flags().IntVar(&limit, "limit", 0, "maximum records to dump, 0 means all")
	return requirePermission(cmd, adminauth.PermissionAuditRead)
}

func newWALRepairCommand(rt *runtimeConfig) *cobra.Command {
	var walPath string
	cmd := &cobra.Command{
		Use:   "repair",
		Short: "Truncate WAL after the last valid record",
		RunE: func(cmd *cobra.Command, args []string) error {
			walPath = stringOrConfig(cmd, rt, "wal", walPath, "wal")
			isDir, err := walIsDirectory(walPath)
			if err != nil {
				return err
			}
			opts, err := walOptionsForCLI(cmd, rt, walPath)
			if err != nil {
				return err
			}
			if isDir {
				// Directory-mode repair only truncates the tail
				// segment. A chain break in any earlier segment
				// causes RepairDir to return FAILED_PRECONDITION
				// without touching disk so the operator can escalate
				// to manual recovery instead of cascade-invalidating
				// later segments.
				result, err := wal.RepairDir(walPath, opts)
				if err != nil {
					return err
				}
				return rt.writeJSON(result)
			}
			result, err := wal.Repair(walPath, opts)
			if err != nil {
				return err
			}
			return rt.writeJSON(result)
		},
	}
	cmd.Flags().StringVar(&walPath, "wal", "", "wal path (file or directory)")
	return requirePermission(cmd, adminauth.PermissionSystemOperate)
}

func walOptionsForCLI(cmd *cobra.Command, rt *runtimeConfig, walPath string) (wal.Options, error) {
	flag := cmd.Flag("crypto-suite")
	if flag == nil {
		return wal.Options{}, trusterr.New(trusterr.CodeInternal, "wal command is missing --crypto-suite")
	}
	suiteID := cryptosuite.ID(strings.TrimSpace(flag.Value.String()))
	if suiteID == "" {
		return wal.Options{}, usageError("--crypto-suite is required")
	}
	options, _, err := bindWALNamespaceOptions(
		wal.Options{},
		suiteID,
		rt.cfg.Server.ID,
		rt.cfg.GlobalLog.LogID,
		walPath,
	)
	if err != nil {
		return wal.Options{}, err
	}
	return options, nil
}

func bindWALNamespaceOptions(opts wal.Options, suiteID cryptosuite.ID, nodeID, configuredLogID, walPath string) (wal.Options, string, error) {
	if _, err := cryptosuite.RequireKnown(suiteID); err != nil {
		return wal.Options{}, "", trusterr.Wrap(trusterr.CodeInvalidArgument, "validate WAL cryptographic suite", err)
	}
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return wal.Options{}, "", trusterr.New(trusterr.CodeInvalidArgument, "WAL node_id is required")
	}
	logID := strings.TrimSpace(configuredLogID)
	if logID == "" {
		logID = nodeID
	}
	absolutePath, err := filepath.Abs(filepath.Clean(walPath))
	if err != nil {
		return wal.Options{}, "", trusterr.Wrap(trusterr.CodeInvalidArgument, "resolve WAL namespace identity", err)
	}
	opts.CryptoSuite = suiteID
	opts.NodeID = nodeID
	opts.LogID = logID
	opts.NamespaceID = "wal:" + absolutePath
	return opts, absolutePath, nil
}
