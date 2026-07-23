package main

import (
	"bytes"
	"encoding/base64"
	"time"

	"github.com/spf13/cobra"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/keydescriptor"
	"github.com/wowtrust/trustdb/internal/keystore"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
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
	var outDir, prefix, keyID string
	cmd := &cobra.Command{
		Use:     "keygen",
		Aliases: []string{"gen"},
		Short:   "Generate an Ed25519 key descriptor pair",
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
			materialName := prefixName + ".material"
			materialPath := joinPath(outDir, materialName)
			resolvedKeyID := keyID
			if resolvedKeyID == "" {
				resolvedKeyID = prefixName + "-key"
			}
			signerDescriptor := keydescriptor.Descriptor{
				SchemaVersion: keydescriptor.SchemaV1,
				Kind:          keydescriptor.KindSigner,
				Provider:      keydescriptor.ProviderSoftware,
				CryptoSuite:   cryptosuite.INTLV1,
				KeyID:         resolvedKeyID,
				Algorithm:     cryptosuite.SignatureEd25519,
				PublicKey: keydescriptor.PublicKeyMaterial{
					Encoding: cryptosuite.Ed25519PublicKeyEncoding,
					Bytes:    append([]byte(nil), pub...),
				},
				Software: &keydescriptor.SoftwareKeyReference{
					MaterialPath: materialName,
					Encoding:     cryptosuite.Ed25519PrivateKeyEncoding,
					Protection:   keydescriptor.SoftwareProtectionPlaintextDev,
				},
			}
			verifierDescriptor := signerDescriptor.Clone()
			verifierDescriptor.Kind = keydescriptor.KindVerifier
			verifierDescriptor.Provider = keydescriptor.ProviderPublic
			verifierDescriptor.Software = nil
			if err := writeFileAtomic(materialPath, []byte(base64.RawURLEncoding.EncodeToString(priv)), 0o600); err != nil {
				return err
			}
			if err := writeKeyDescriptor(privPath, signerDescriptor); err != nil {
				return err
			}
			if err := writeKeyDescriptor(pubPath, verifierDescriptor); err != nil {
				return err
			}
			rt.logger.Info().
				Str("verifier_descriptor", pubPath).
				Str("signer_descriptor", privPath).
				Str("key_id", resolvedKeyID).
				Msg("generated key pair")
			return rt.writeJSON(map[string]string{
				"verifier_descriptor": pubPath,
				"signer_descriptor":   privPath,
				"key_id":              resolvedKeyID,
			})
		},
	}
	cmd.Flags().StringVar(&outDir, "out", ".", "output directory")
	cmd.Flags().StringVar(&prefix, "prefix", "client", "key filename prefix")
	cmd.Flags().StringVar(&keyID, "key-id", "", "descriptor key ID (defaults to <prefix>-key)")
	return cmd
}

func newKeyInspectCommand(rt *runtimeConfig) *cobra.Command {
	var keyPath string
	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Inspect a key descriptor without opening private material",
		RunE: func(cmd *cobra.Command, args []string) error {
			if keyPath == "" {
				return usageError("key inspect requires key")
			}
			descriptor, err := keydescriptor.ReadFile(keyPath)
			if err != nil {
				return err
			}
			suite, err := cryptosuite.RequireKnown(descriptor.CryptoSuite)
			if err != nil {
				return err
			}
			fingerprint, err := trustcrypto.HashBytesForSuite(descriptor.CryptoSuite, suite.KeyFingerprintHash.Algorithm, descriptor.PublicKey.Bytes)
			if err != nil {
				return err
			}
			kind := descriptor.Kind
			if descriptor.Kind == keydescriptor.KindVerifier {
				kind = "public"
			}
			return rt.writeJSON(map[string]any{
				"path":              keyPath,
				"schema_version":    descriptor.SchemaVersion,
				"kind":              kind,
				"provider":          descriptor.Provider,
				"crypto_suite":      descriptor.CryptoSuite,
				"key_id":            descriptor.KeyID,
				"alg":               descriptor.Algorithm,
				"public_key":        base64.RawURLEncoding.EncodeToString(descriptor.PublicKey.Bytes),
				"fingerprint":       base64.RawURLEncoding.EncodeToString(fingerprint),
				"certificate_count": len(descriptor.CertificateChain),
				"descriptor":        descriptor,
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
			registrySigner, registryKey, err := readSigner(cmd.Context(), registryPrivate)
			if err != nil {
				return err
			}
			if err := requireKeyID(registryKeyID, registryKey); err != nil {
				return err
			}
			clientPub, clientKey, err := readPublicKeyDescriptor(publicKeyPath)
			if err != nil {
				return err
			}
			if err := requireKeyID(keyID, clientKey); err != nil {
				return err
			}
			registryPub, err := registrySigner.PublicKey(cmd.Context())
			if err != nil {
				return err
			}
			reg, err := keystore.Open(registryPath, registrySigner, registryPub)
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
	cmd.Flags().StringVar(&registryPrivate, "registry-private-key", "", "registry signer descriptor")
	cmd.Flags().StringVar(&publicKeyPath, "public-key", "", "client verifier descriptor")
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
			registrySigner, registryKey, err := readSigner(cmd.Context(), registryPrivate)
			if err != nil {
				return err
			}
			if err := requireKeyID(registryKeyID, registryKey); err != nil {
				return err
			}
			regPub, err := registrySigner.PublicKey(cmd.Context())
			if err != nil {
				return err
			}
			if registryPublic != "" {
				configuredPub, _, err := readPublicKeyDescriptor(registryPublic)
				if err != nil {
					return err
				}
				if configuredPub.Suite != regPub.Suite || configuredPub.Algorithm != regPub.Algorithm || configuredPub.Encoding != regPub.Encoding || !bytes.Equal(configuredPub.Bytes, regPub.Bytes) {
					return usageError("registry public descriptor does not match registry signer descriptor")
				}
			}
			reg, err := keystore.Open(registryPath, registrySigner, regPub)
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
	cmd.Flags().StringVar(&registryPrivate, "registry-private-key", "", "registry signer descriptor")
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
			registryDescriptor := trustcrypto.PublicKeyDescriptor{}
			if registryPublic != "" {
				var err error
				registryDescriptor, _, err = readPublicKeyDescriptor(registryPublic)
				if err != nil {
					return err
				}
			}
			reg, err := keystore.Open(registryPath, nil, registryDescriptor)
			if err != nil {
				return err
			}
			return rt.writeJSON(reg.Events())
		},
	}
	addRegistryFlags(cmd)
	return cmd
}
