package main

import (
	"encoding/base64"
	"errors"
	"os"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/claim"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trusterr"
	"github.com/wowtrust/trustdb/internal/wal"
	"github.com/spf13/cobra"
)

// walIsDirectory returns true when the given path exists and is a directory.
// It returns a wrapped error for other stat failures; a missing path is
// treated as "not a directory" so a freshly-created single-file WAL still
// follows the legacy code path.
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
			if isDir {
				result, err := wal.InspectDir(walPath)
				if err != nil {
					return err
				}
				return rt.writeJSON(result)
			}
			result, err := wal.Inspect(walPath)
			if err != nil {
				return err
			}
			return rt.writeJSON(result)
		},
	}
	cmd.Flags().StringVar(&walPath, "wal", "", "wal path (file or directory)")
	return cmd
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
			var records []wal.Record
			if isDir {
				records, err = wal.ReadAllDir(walPath)
			} else {
				records, err = wal.ReadAll(walPath)
			}
			if err != nil {
				return err
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
						item["record_id"] = claim.RecordID(claimCBOR, signed.Signature)
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
	return cmd
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
			if isDir {
				// Directory-mode repair only truncates the tail
				// segment. A chain break in any earlier segment
				// causes RepairDir to return FAILED_PRECONDITION
				// without touching disk so the operator can escalate
				// to manual recovery instead of cascade-invalidating
				// later segments.
				result, err := wal.RepairDir(walPath)
				if err != nil {
					return err
				}
				return rt.writeJSON(result)
			}
			result, err := wal.Repair(walPath)
			if err != nil {
				return err
			}
			return rt.writeJSON(result)
		},
	}
	cmd.Flags().StringVar(&walPath, "wal", "", "wal path (file or directory)")
	return cmd
}
