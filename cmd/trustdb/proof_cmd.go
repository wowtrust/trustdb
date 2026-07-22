package main

import (
	"encoding/base64"

	"github.com/wowtrust/trustdb/internal/model"
	"github.com/spf13/cobra"
)

func newProofCommand(rt *runtimeConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "proof",
		Short: "Inspect proof bundles",
	}
	cmd.AddCommand(newProofInspectCommand(rt))
	return cmd
}

func newProofInspectCommand(rt *runtimeConfig) *cobra.Command {
	var proofPath string
	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Inspect a TrustDB proof bundle",
		RunE: func(cmd *cobra.Command, args []string) error {
			if proofPath == "" {
				return usageError("proof inspect requires proof")
			}
			var bundle model.ProofBundle
			if err := readCBORFile(proofPath, &bundle); err != nil {
				return err
			}
			return rt.writeJSON(map[string]any{
				"path":                    proofPath,
				"schema_version":          bundle.SchemaVersion,
				"record_id":               bundle.RecordID,
				"tenant":                  bundle.SignedClaim.Claim.TenantID,
				"client":                  bundle.SignedClaim.Claim.ClientID,
				"key_id":                  bundle.SignedClaim.Claim.KeyID,
				"content_hash_alg":        bundle.SignedClaim.Claim.Content.HashAlg,
				"content_hash":            base64.RawURLEncoding.EncodeToString(bundle.SignedClaim.Claim.Content.ContentHash),
				"content_length":          bundle.SignedClaim.Claim.Content.ContentLength,
				"storage_uri":             bundle.SignedClaim.Claim.Content.StorageURI,
				"accepted_status":         bundle.AcceptedReceipt.Status,
				"server_id":               bundle.AcceptedReceipt.ServerID,
				"server_received_at_unix": bundle.AcceptedReceipt.ReceivedAtUnixN,
				"batch_id":                bundle.CommittedReceipt.BatchID,
				"batch_root":              base64.RawURLEncoding.EncodeToString(bundle.CommittedReceipt.BatchRoot),
				"tree_alg":                bundle.BatchProof.TreeAlg,
				"tree_size":               bundle.BatchProof.TreeSize,
				"leaf_index":              bundle.BatchProof.LeafIndex,
				"audit_path_len":          len(bundle.BatchProof.AuditPath),
			})
		},
	}
	cmd.Flags().StringVar(&proofPath, "proof", "", "proof bundle path")
	return cmd
}
