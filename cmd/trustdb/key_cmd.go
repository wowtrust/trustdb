package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/ryan-wong-coder/trustdb/internal/keystore"
	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/trustcrypto"
	"github.com/spf13/cobra"
)

func newKeyCommand(rt *runtimeConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key",
		Short: "Manage client and registry keys",
	}
	cmd.AddCommand(newKeygenCommand(rt, false))
	cmd.AddCommand(newKeyRegisterCommand(rt, false))
	cmd.AddCommand(newKeyRevokeCommand(rt, false))
	cmd.AddCommand(newKeyListCommand(rt, false))
	cmd.AddCommand(newKeyInspectCommand(rt))
	return cmd
}

func newKeygenCommand(rt *runtimeConfig, hidden bool) *cobra.Command {
	var outDir, prefix string
	cmd := &cobra.Command{
		Use:     "keygen",
		Aliases: []string{"gen"},
		Short:   "Generate an Ed25519 key pair",
		Hidden:  hidden,
		RunE: func(cmd *cobra.Command, args []string) error {
			pub, priv, err := trustcrypto.GenerateEd25519Key()
			if err != nil {
				return err
			}
			if err := ensureDir(outDir); err != nil {
				return err
			}
			prefixName := safeOutputFileName(prefix)
			pubPath := joinPath(outDir, prefixName+".pub")
			privPath := joinPath(outDir, prefixName+".key")
			if err := writeKey(pubPath, pub); err != nil {
				return err
			}
			if err := writeKey(privPath, priv); err != nil {
				return err
			}
			rt.logger.Info().
				Str("public_key", pubPath).
				Str("private_key", privPath).
				Msg("generated key pair")
			return rt.writeJSON(map[string]string{
				"public_key":  pubPath,
				"private_key": privPath,
			})
		},
	}
	cmd.Flags().StringVar(&outDir, "out", ".", "output directory")
	cmd.Flags().StringVar(&prefix, "prefix", "client", "key filename prefix")
	return cmd
}

func newKeyInspectCommand(rt *runtimeConfig) *cobra.Command {
	var keyPath string
	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Inspect an Ed25519 public or private key file",
		RunE: func(cmd *cobra.Command, args []string) error {
			if keyPath == "" {
				return usageError("key inspect requires key")
			}
			key, err := readKey(keyPath)
			if err != nil {
				return err
			}
			var kind string
			var pub ed25519.PublicKey
			switch len(key) {
			case ed25519.PublicKeySize:
				kind = "public"
				pub = ed25519.PublicKey(key)
			case ed25519.PrivateKeySize:
				kind = "private"
				priv := ed25519.PrivateKey(key)
				pub = priv.Public().(ed25519.PublicKey)
			default:
				return fmt.Errorf("invalid Ed25519 key size %d", len(key))
			}
			fp := sha256.Sum256(pub)
			return rt.writeJSON(map[string]string{
				"path":        keyPath,
				"kind":        kind,
				"alg":         model.DefaultSignatureAlg,
				"public_key":  base64.RawURLEncoding.EncodeToString(pub),
				"fingerprint": base64.RawURLEncoding.EncodeToString(fp[:]),
			})
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "key file to inspect")
	return cmd
}

func newKeyRegisterCommand(rt *runtimeConfig, hidden bool) *cobra.Command {
	var registryPrivate, publicKeyPath string
	var validFromUnix, validUntilUnix int64
	cmd := &cobra.Command{
		Use:    "key-register",
		Short:  "Register a client public key in the append-only registry",
		Hidden: hidden,
		RunE: func(cmd *cobra.Command, args []string) error {
			registryPath := stringValue(cmd, rt, "registry", "key_registry")
			registryKeyID := stringValue(cmd, rt, "registry-key-id", "registry_key_id")
			registryPrivate = stringOrConfig(cmd, rt, "registry-private-key", registryPrivate, "keys.registry_private")
			publicKeyPath = stringOrConfig(cmd, rt, "public-key", publicKeyPath, "keys.client_public")
			tenantID := stringValue(cmd, rt, "tenant", "tenant")
			clientID := stringValue(cmd, rt, "client", "client")
			keyID := stringValue(cmd, rt, "key-id", "key_id")
			if registryPrivate == "" || clientID == "" || keyID == "" || publicKeyPath == "" {
				return usageError("key-register requires registry-private-key, client, key-id, and public-key")
			}
			regPriv, err := readPrivateKey(registryPrivate)
			if err != nil {
				return err
			}
			clientPub, err := readPublicKey(publicKeyPath)
			if err != nil {
				return err
			}
			reg, err := keystore.Open(registryPath, registryKeyID, regPriv, regPriv.Public().(ed25519.PublicKey))
			if err != nil {
				return err
			}
			var validUntil time.Time
			if validUntilUnix != 0 {
				validUntil = time.Unix(validUntilUnix, 0).UTC()
			}
			ev, err := reg.RegisterClientKey(tenantID, clientID, keyID, clientPub, time.Unix(validFromUnix, 0).UTC(), validUntil)
			if err != nil {
				return err
			}
			rt.logger.Info().
				Str("tenant", tenantID).
				Str("client", clientID).
				Str("key_id", keyID).
				Uint64("sequence", ev.Sequence).
				Msg("registered client key")
			return rt.writeJSON(map[string]any{
				"sequence":   ev.Sequence,
				"event_hash": base64.RawURLEncoding.EncodeToString(ev.EventHash),
				"registry":   registryPath,
			})
		},
	}
	addRegistryFlags(cmd)
	addCommonIdentityFlags(cmd)
	cmd.Flags().String("registry-key-id", "", "registry signing key id")
	cmd.Flags().StringVar(&registryPrivate, "registry-private-key", "", "registry private key")
	cmd.Flags().StringVar(&publicKeyPath, "public-key", "", "client public key")
	cmd.Flags().Int64Var(&validFromUnix, "valid-from-unix", time.Now().UTC().Unix(), "valid from unix seconds")
	cmd.Flags().Int64Var(&validUntilUnix, "valid-until-unix", 0, "valid until unix seconds, 0 means no expiry")
	return cmd
}

func newKeyRevokeCommand(rt *runtimeConfig, hidden bool) *cobra.Command {
	var registryPrivate, registryPublic, reason string
	var revokedAtUnix int64
	cmd := &cobra.Command{
		Use:    "key-revoke",
		Short:  "Revoke a client key in the append-only registry",
		Hidden: hidden,
		RunE: func(cmd *cobra.Command, args []string) error {
			registryPath := stringValue(cmd, rt, "registry", "key_registry")
			registryKeyID := stringValue(cmd, rt, "registry-key-id", "registry_key_id")
			registryPrivate = stringOrConfig(cmd, rt, "registry-private-key", registryPrivate, "keys.registry_private")
			registryPublic = stringOrConfig(cmd, rt, "registry-public-key", registryPublic, "keys.registry_public")
			tenantID := stringValue(cmd, rt, "tenant", "tenant")
			clientID := stringValue(cmd, rt, "client", "client")
			keyID := stringValue(cmd, rt, "key-id", "key_id")
			if registryPrivate == "" || clientID == "" || keyID == "" {
				return usageError("key-revoke requires registry-private-key, client, and key-id")
			}
			regPriv, err := readPrivateKey(registryPrivate)
			if err != nil {
				return err
			}
			regPub := regPriv.Public().(ed25519.PublicKey)
			if registryPublic != "" {
				regPub, err = readPublicKey(registryPublic)
				if err != nil {
					return err
				}
			}
			reg, err := keystore.Open(registryPath, registryKeyID, regPriv, regPub)
			if err != nil {
				return err
			}
			ev, err := reg.RevokeClientKey(tenantID, clientID, keyID, time.Unix(revokedAtUnix, 0).UTC(), reason)
			if err != nil {
				return err
			}
			rt.logger.Info().
				Str("tenant", tenantID).
				Str("client", clientID).
				Str("key_id", keyID).
				Uint64("sequence", ev.Sequence).
				Msg("revoked client key")
			return rt.writeJSON(map[string]any{
				"sequence":   ev.Sequence,
				"event_hash": base64.RawURLEncoding.EncodeToString(ev.EventHash),
				"registry":   registryPath,
			})
		},
	}
	addRegistryFlags(cmd)
	addCommonIdentityFlags(cmd)
	cmd.Flags().String("registry-key-id", "", "registry signing key id")
	cmd.Flags().StringVar(&registryPrivate, "registry-private-key", "", "registry private key")
	cmd.Flags().StringVar(&reason, "reason", "", "revocation reason")
	cmd.Flags().Int64Var(&revokedAtUnix, "revoked-at-unix", time.Now().UTC().Unix(), "revoked at unix seconds")
	return cmd
}

func newKeyListCommand(rt *runtimeConfig, hidden bool) *cobra.Command {
	cmd := &cobra.Command{
		Use:    "key-list",
		Short:  "List registry events",
		Hidden: hidden,
		RunE: func(cmd *cobra.Command, args []string) error {
			registryPath := stringValue(cmd, rt, "registry", "key_registry")
			registryPublic := stringOrConfig(cmd, rt, "registry-public-key", "", "keys.registry_public")
			var regPub ed25519.PublicKey
			var err error
			if registryPublic != "" {
				regPub, err = readPublicKey(registryPublic)
				if err != nil {
					return err
				}
			}
			reg, err := keystore.Open(registryPath, "", nil, regPub)
			if err != nil {
				return err
			}
			return rt.writeJSON(reg.Events())
		},
	}
	addRegistryFlags(cmd)
	return cmd
}
