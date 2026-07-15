package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ryan-wong-coder/trustdb/internal/app"
	"github.com/ryan-wong-coder/trustdb/internal/cborx"
	"github.com/ryan-wong-coder/trustdb/internal/keystore"
	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/prooflevel"
	"github.com/ryan-wong-coder/trustdb/internal/wal"
	"github.com/spf13/cobra"
)

func newCommitCommand(rt *runtimeConfig) *cobra.Command {
	var claimPath, clientPubPath, registryPath, registryPubPath, serverKeyPath, walPath, outPath string
	cmd := &cobra.Command{
		Use:   "commit",
		Short: "Commit a signed claim into a local WAL and Merkle proof",
		RunE: func(cmd *cobra.Command, args []string) error {
			registryPath = stringOrConfig(cmd, rt, "key-registry", registryPath, "key_registry")
			registryPubPath = stringOrConfig(cmd, rt, "registry-public-key", registryPubPath, "keys.registry_public")
			clientPubPath = stringOrConfig(cmd, rt, "client-public-key", clientPubPath, "keys.client_public")
			serverKeyPath = stringOrConfig(cmd, rt, "server-private-key", serverKeyPath, "keys.server_private")
			walPath = stringOrConfig(cmd, rt, "wal", walPath, "wal")
			serverID := stringValue(cmd, rt, "server-id", "server_id")
			serverKeyID := stringValue(cmd, rt, "server-key-id", "server_key_id")
			if claimPath == "" || serverKeyPath == "" {
				return usageError("commit requires claim and server-private-key")
			}
			if clientPubPath == "" && registryPath == "" {
				return usageError("commit requires either client-public-key or key-registry")
			}
			var signed model.SignedClaim
			if err := readCBORFile(claimPath, &signed); err != nil {
				return err
			}
			clientPub, clientKeys, err := resolveClientKeys(clientPubPath, registryPath, registryPubPath, cmd.Flags().Changed("key-registry"))
			if err != nil {
				return err
			}
			serverPriv, err := readPrivateKey(serverKeyPath)
			if err != nil {
				return err
			}
			writer, err := wal.OpenWriter(walPath, 1)
			if err != nil {
				return err
			}
			defer writer.Close()
			engine := app.LocalEngine{
				ServerID:         serverID,
				ServerKeyID:      serverKeyID,
				ClientPublicKey:  clientPub,
				ClientKeys:       clientKeys,
				ServerPrivateKey: serverPriv,
				WAL:              writer,
			}
			record, accepted, _, err := engine.Submit(context.Background(), signed)
			if err != nil {
				return err
			}
			bundles, err := engine.CommitBatch("local-batch-1", time.Now().UTC(), []model.SignedClaim{signed}, []model.ServerRecord{record}, []model.AcceptedReceipt{accepted})
			if err != nil {
				return err
			}
			data, err := cborx.Marshal(bundles[0])
			if err != nil {
				return err
			}
			if err := os.WriteFile(outPath, data, 0o600); err != nil {
				return err
			}
			rt.logger.Info().
				Str("record_id", record.RecordID).
				Str("proof", outPath).
				Msg("committed claim")
			return rt.writeJSON(map[string]string{
				"record_id": record.RecordID,
				"proof":     outPath,
				"level":     prooflevel.L3.String(),
			})
		},
	}
	addServerFlags(cmd)
	cmd.Flags().StringVar(&claimPath, "claim", "", "signed claim path")
	cmd.Flags().StringVar(&clientPubPath, "client-public-key", "", "client public key")
	cmd.Flags().StringVar(&registryPath, "key-registry", "", "key registry path")
	cmd.Flags().StringVar(&registryPubPath, "registry-public-key", "", "registry public key")
	cmd.Flags().StringVar(&serverKeyPath, "server-private-key", "", "server private key")
	cmd.Flags().StringVar(&walPath, "wal", "", "wal path")
	cmd.Flags().StringVar(&outPath, "out", "proof.tdproof", "proof output path")
	return cmd
}

func newCommitBatchCommand(rt *runtimeConfig) *cobra.Command {
	var claimPaths multiFlag
	var clientPubPath, registryPath, registryPubPath, serverKeyPath, walPath, outDir, batchID string
	cmd := &cobra.Command{
		Use:   "commit-batch",
		Short: "Commit multiple signed claims into one Merkle batch",
		RunE: func(cmd *cobra.Command, args []string) error {
			registryPath = stringOrConfig(cmd, rt, "key-registry", registryPath, "key_registry")
			registryPubPath = stringOrConfig(cmd, rt, "registry-public-key", registryPubPath, "keys.registry_public")
			clientPubPath = stringOrConfig(cmd, rt, "client-public-key", clientPubPath, "keys.client_public")
			serverKeyPath = stringOrConfig(cmd, rt, "server-private-key", serverKeyPath, "keys.server_private")
			walPath = stringOrConfig(cmd, rt, "wal", walPath, "wal")
			serverID := stringValue(cmd, rt, "server-id", "server_id")
			serverKeyID := stringValue(cmd, rt, "server-key-id", "server_key_id")
			if len(claimPaths) == 0 || serverKeyPath == "" {
				return usageError("commit-batch requires at least one claim and server-private-key")
			}
			if clientPubPath == "" && registryPath == "" {
				return usageError("commit-batch requires either client-public-key or key-registry")
			}
			signed := make([]model.SignedClaim, len(claimPaths))
			for i, path := range claimPaths {
				if err := readCBORFile(path, &signed[i]); err != nil {
					return fmt.Errorf("read claim %s: %w", path, err)
				}
			}
			clientPub, clientKeys, err := resolveClientKeys(clientPubPath, registryPath, registryPubPath, cmd.Flags().Changed("key-registry"))
			if err != nil {
				return err
			}
			serverPriv, err := readPrivateKey(serverKeyPath)
			if err != nil {
				return err
			}
			writer, err := wal.OpenWriter(walPath, 1)
			if err != nil {
				return err
			}
			defer writer.Close()
			engine := app.LocalEngine{
				ServerID:         serverID,
				ServerKeyID:      serverKeyID,
				ClientPublicKey:  clientPub,
				ClientKeys:       clientKeys,
				ServerPrivateKey: serverPriv,
				WAL:              writer,
			}
			records := make([]model.ServerRecord, len(signed))
			accepted := make([]model.AcceptedReceipt, len(signed))
			for i := range signed {
				records[i], accepted[i], _, err = engine.Submit(context.Background(), signed[i])
				if err != nil {
					return fmt.Errorf("submit claim %d: %w", i, err)
				}
			}
			bundles, err := engine.CommitBatch(batchID, time.Now().UTC(), signed, records, accepted)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return err
			}
			outputs := make([]map[string]string, len(bundles))
			for i := range bundles {
				outPath := filepath.Join(outDir, safeOutputFileName(bundles[i].RecordID)+".tdproof")
				data, err := cborx.Marshal(bundles[i])
				if err != nil {
					return err
				}
				if err := os.WriteFile(outPath, data, 0o600); err != nil {
					return err
				}
				outputs[i] = map[string]string{
					"record_id": bundles[i].RecordID,
					"proof":     outPath,
					"level":     prooflevel.L3.String(),
				}
			}
			rt.logger.Info().
				Str("batch_id", batchID).
				Int("records", len(bundles)).
				Str("out_dir", outDir).
				Msg("committed batch")
			return rt.writeJSON(outputs)
		},
	}
	addServerFlags(cmd)
	cmd.Flags().Var(&claimPaths, "claim", "signed claim path, repeatable")
	cmd.Flags().StringVar(&clientPubPath, "client-public-key", "", "client public key")
	cmd.Flags().StringVar(&registryPath, "key-registry", "", "key registry path")
	cmd.Flags().StringVar(&registryPubPath, "registry-public-key", "", "registry public key")
	cmd.Flags().StringVar(&serverKeyPath, "server-private-key", "", "server private key")
	cmd.Flags().StringVar(&walPath, "wal", "", "wal path")
	cmd.Flags().StringVar(&outDir, "out-dir", "proofs", "proof output directory")
	cmd.Flags().StringVar(&batchID, "batch-id", "local-batch-1", "batch id")
	return cmd
}

// resolveClientKeys picks between the single-key (--client-public-key) and
// registry (--key-registry) trust anchors. Because `paths.key_registry` has
// a non-empty default (".trustdb/keys.tdkeys"), naive "registry first" logic
// silently ignored an explicit --client-public-key when the registry file did
// not even exist. The rule we use now:
//
//  1. If the caller explicitly asked for a registry (registryExplicit==true)
//     we always load it, even if a client-public-key is also present — the
//     operator opted in to the registry on purpose.
//  2. Otherwise, a non-empty --client-public-key wins (fixes the default-path
//     footgun).
//  3. Otherwise, we fall back to registryPath if it has been set (possibly by
//     config/defaults). This preserves the pre-existing behaviour for
//     deployments that rely on the default registry location.
//  4. If none of the above is satisfied the caller must already have bailed
//     out via the "requires either client-public-key or key-registry" check.
func resolveClientKeys(clientPubPath, registryPath, registryPubPath string, registryExplicit bool) (ed25519.PublicKey, app.ClientKeyResolver, error) {
	useRegistry := registryPath != "" && (registryExplicit || clientPubPath == "")
	if useRegistry {
		var registryPub ed25519.PublicKey
		var err error
		if registryPubPath != "" {
			registryPub, err = readPublicKey(registryPubPath)
			if err != nil {
				return nil, nil, err
			}
		}
		clientKeys, err := keystore.Open(registryPath, "", nil, registryPub)
		return nil, clientKeys, err
	}
	clientPub, err := readPublicKey(clientPubPath)
	return clientPub, nil, err
}
