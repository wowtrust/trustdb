package main

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/claim"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/objectstore"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
)

func newClaimFileCommand(rt *runtimeConfig) *cobra.Command {
	var filePath, privateKeyPath, outPath, objectDir string
	cmd := &cobra.Command{
		Use:   "claim-file",
		Short: "Create and sign a claim for a file",
		RunE: func(cmd *cobra.Command, args []string) error {
			tenantID := stringValue(cmd, rt, "tenant", "tenant")
			clientID := stringValue(cmd, rt, "client", "client")
			keyID := stringValue(cmd, rt, "key-id", "key_id")
			privateKeyPath = stringOrConfig(cmd, rt, "private-key", privateKeyPath, "keys.client_private")
			objectDir = stringOrConfig(cmd, rt, "object-dir", objectDir, "object_dir")
			if filePath == "" || clientID == "" || keyID == "" || privateKeyPath == "" {
				return usageError("claim-file requires file, client, key-id, and private-key")
			}
			signer, key, err := readSigner(cmd.Context(), privateKeyPath)
			if err != nil {
				return err
			}
			if err := requireKeyID(keyID, key); err != nil {
				return err
			}
			provider, err := trustcrypto.ProviderForSuite(key.CryptoSuite)
			if err != nil {
				return err
			}
			var sum []byte
			var n int64
			storageURI := filePath
			if objectDir != "" {
				put, err := objectstore.LocalStore{Root: objectDir}.PutFile(context.Background(), filePath)
				if err != nil {
					return err
				}
				sum = put.ContentHash
				n = put.ContentLength
				storageURI = put.URI
			} else {
				f, err := os.Open(filePath)
				if err != nil {
					return err
				}
				sum, n, err = trustcrypto.HashReader(model.DefaultHashAlg, f)
				closeErr := f.Close()
				if err != nil {
					return err
				}
				if closeErr != nil {
					return closeErr
				}
			}
			nonce, err := trustcrypto.NewNonce(16)
			if err != nil {
				return err
			}
			idem, err := trustcrypto.NewNonce(16)
			if err != nil {
				return err
			}
			c, err := claim.NewFileClaim(
				tenantID,
				clientID,
				keyID,
				time.Now().UTC(),
				nonce,
				base64.RawURLEncoding.EncodeToString(idem),
				model.Content{
					HashAlg:       model.DefaultHashAlg,
					ContentHash:   sum,
					ContentLength: n,
					MediaType:     "application/octet-stream",
					StorageURI:    storageURI,
				},
				model.Metadata{
					EventType: "file.snapshot",
					Source:    clientID,
					Custom: map[string]string{
						"file_name": filepath.Base(filePath),
					},
				},
			)
			if err != nil {
				return err
			}
			signed, err := claim.SignWithProvider(cmd.Context(), provider, c, signer)
			if err != nil {
				return err
			}
			data, err := cborx.Marshal(signed)
			if err != nil {
				return err
			}
			if err := writeFileAtomic(outPath, data, 0o600); err != nil {
				return err
			}
			publicKey, err := signer.PublicKey(cmd.Context())
			if err != nil {
				return err
			}
			verified, err := claim.VerifyWithProvider(cmd.Context(), signed, publicKey, provider)
			if err != nil {
				return err
			}
			rt.logger.Info().
				Str("record_id", verified.RecordID).
				Str("claim", outPath).
				Msg("created signed claim")
			return rt.writeJSON(map[string]string{
				"record_id": verified.RecordID,
				"claim":     outPath,
			})
		},
	}
	addCommonIdentityFlags(cmd)
	cmd.Flags().StringVar(&filePath, "file", "", "file to claim")
	cmd.Flags().StringVar(&privateKeyPath, "private-key", "", "client signer descriptor")
	cmd.Flags().StringVar(&objectDir, "object-dir", "", "optional local object store directory")
	cmd.Flags().StringVar(&outPath, "out", "claim.tdclaim", "output signed claim")
	return cmd
}
