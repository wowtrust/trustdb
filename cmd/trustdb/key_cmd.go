package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"time"

	"github.com/spf13/cobra"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/keydescriptor"
	"github.com/wowtrust/trustdb/internal/keystore"
	"github.com/wowtrust/trustdb/internal/model"
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
	cmd.AddCommand(newKeyCompromiseCommand(rt))
	cmd.AddCommand(newKeyRotateCommand(rt))
	cmd.AddCommand(newKeyListCommand(rt, false))
	cmd.AddCommand(newKeyInspectCommand(rt))
	return cmd
}

func newKeygenCommand(rt *runtimeConfig, hidden bool) *cobra.Command {
	var outDir, prefix, keyID, suiteID string
	cmd := &cobra.Command{
		Use:     "keygen",
		Aliases: []string{"gen", "generate"},
		Short:   "Generate a development signing key descriptor pair",
		Hidden:  hidden,
		RunE: func(cmd *cobra.Command, args []string) error {
			suite, err := cryptosuite.RequireKnown(cryptosuite.ID(suiteID))
			if err != nil {
				return err
			}
			var pub, priv []byte
			switch suite.ID {
			case cryptosuite.INTLV1:
				generatedPub, generatedPriv, err := trustcrypto.GenerateEd25519Key()
				if err != nil {
					return err
				}
				pub, priv = generatedPub, generatedPriv
			case cryptosuite.CNSMV1:
				pub, priv, err = trustcrypto.GenerateSM2Key()
				if err != nil {
					return err
				}
			default:
				return usageError("unsupported key generation suite")
			}
			defer clear(priv)
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
				CryptoSuite:   suite.ID,
				KeyID:         resolvedKeyID,
				Algorithm:     suite.Signature.Algorithm,
				SM2UserID:     suite.Signature.SM2UserID,
				PublicKey: keydescriptor.PublicKeyMaterial{
					Encoding: suite.Signature.PublicKeyEncoding,
					Bytes:    append([]byte(nil), pub...),
				},
				Software: &keydescriptor.SoftwareKeyReference{
					MaterialPath: materialName,
					Encoding:     suite.Signature.PrivateKeyEncoding,
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
				Str("crypto_suite", string(suite.ID)).
				Bool("development_only", true).
				Msg("generated key pair")
			return rt.writeJSON(map[string]string{
				"verifier_descriptor": pubPath,
				"signer_descriptor":   privPath,
				"key_id":              resolvedKeyID,
				"crypto_suite":        string(suite.ID),
				"algorithm":           suite.Signature.Algorithm,
			})
		},
	}
	cmd.Flags().StringVar(&outDir, "out", ".", "output directory")
	cmd.Flags().StringVar(&prefix, "prefix", "client", "key filename prefix")
	cmd.Flags().StringVar(&keyID, "key-id", "", "descriptor key ID (defaults to <prefix>-key)")
	cmd.Flags().StringVar(&suiteID, "suite", string(cryptosuite.INTLV1), "cryptographic suite (INTL_V1 or CN_SM_V1)")
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
			certificates, err := descriptor.CertificateMetadata()
			if err != nil {
				return err
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
				"certificates":      certificates,
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
		Use:     "key-register",
		Aliases: []string{"import", "register"},
		Short:   "Import a client descriptor into the append-only V2 registry",
		Hidden:  hidden,
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
			registrySigner, registryKey, err := readLifecycleSigner(cmd.Context(), registryPrivate)
			if err != nil {
				return err
			}
			if err := requireKeyID(registryKeyID, registryKey); err != nil {
				return err
			}
			clientKey, err := keydescriptor.ReadFile(publicKeyPath)
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
			ev, err := reg.RegisterClientKey(tenantID, clientID, clientKey, time.Unix(validFromUnix, 0).UTC(), validUntil)
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
				"sequence":     ev.Sequence,
				"event_hash":   base64.RawURLEncoding.EncodeToString(ev.EventHash),
				"registry":     registryPath,
				"crypto_suite": string(ev.CryptoSuite),
				"provider":     clientKey.Provider,
			})
		},
	}
	addRegistryFlags(cmd)
	addCommonIdentityFlags(cmd)
	cmd.Flags().String("registry-key-id", "", "registry signing key id")
	cmd.Flags().StringVar(&registryPrivate, "registry-private-key", "", "registry signer descriptor")
	cmd.Flags().StringVar(&publicKeyPath, "public-key", "", "client signer or verifier descriptor to import")
	cmd.Flags().Int64Var(&validFromUnix, "valid-from-unix", time.Now().UTC().Unix(), "valid from unix seconds")
	cmd.Flags().Int64Var(&validUntilUnix, "valid-until-unix", 0, "valid until unix seconds, 0 means no expiry")
	return cmd
}

func newKeyRevokeCommand(rt *runtimeConfig, hidden bool) *cobra.Command {
	var registryPrivate, registryPublic, reason string
	var revokedAtUnix int64
	cmd := &cobra.Command{
		Use:     "key-revoke",
		Aliases: []string{"revoke"},
		Short:   "Revoke a client key in the append-only V2 registry",
		Hidden:  hidden,
		RunE: func(cmd *cobra.Command, args []string) error {
			registryPath := stringValue(cmd, rt, "registry", "key_registry")
			registryKeyID := stringValue(cmd, rt, "registry-key-id", "registry_key_id")
			registryPrivate = stringOrConfig(cmd, rt, "registry-private-key", registryPrivate, "keys.registry_private")
			registryPublic = stringValue(cmd, rt, "registry-public-key", "keys.registry_public")
			tenantID := stringValue(cmd, rt, "tenant", "tenant")
			clientID := stringValue(cmd, rt, "client", "client")
			keyID := stringValue(cmd, rt, "key-id", "key_id")
			if registryPrivate == "" || clientID == "" || keyID == "" {
				return usageError("key-revoke requires registry-private-key, client, and key-id")
			}
			registrySigner, registryKey, err := readLifecycleSigner(cmd.Context(), registryPrivate)
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

func newKeyCompromiseCommand(rt *runtimeConfig) *cobra.Command {
	var registryPrivate, registryPublic, reason string
	var compromisedAtUnix int64
	cmd := &cobra.Command{
		Use:   "compromise",
		Short: "Mark a client key compromised at an effective time",
		RunE: func(cmd *cobra.Command, args []string) error {
			registryPath := stringValue(cmd, rt, "registry", "key_registry")
			registryKeyID := stringValue(cmd, rt, "registry-key-id", "registry_key_id")
			registryPrivate = stringOrConfig(cmd, rt, "registry-private-key", registryPrivate, "keys.registry_private")
			registryPublic = stringValue(cmd, rt, "registry-public-key", "keys.registry_public")
			tenantID := stringValue(cmd, rt, "tenant", "tenant")
			clientID := stringValue(cmd, rt, "client", "client")
			keyID := stringValue(cmd, rt, "key-id", "key_id")
			if registryPrivate == "" || clientID == "" || keyID == "" {
				return usageError("key compromise requires registry-private-key, client, and key-id")
			}
			registry, err := openLifecycleRegistry(cmd.Context(), registryPath, registryPrivate, registryPublic, registryKeyID)
			if err != nil {
				return err
			}
			event, err := registry.MarkClientKeyCompromised(tenantID, clientID, keyID, time.Unix(compromisedAtUnix, 0).UTC(), reason)
			if err != nil {
				return err
			}
			return rt.writeJSON(map[string]any{
				"sequence":     event.Sequence,
				"event_hash":   base64.RawURLEncoding.EncodeToString(event.EventHash),
				"registry":     registryPath,
				"crypto_suite": string(event.CryptoSuite),
			})
		},
	}
	addRegistryFlags(cmd)
	addCommonIdentityFlags(cmd)
	cmd.Flags().String("registry-key-id", "", "registry signing key id")
	cmd.Flags().StringVar(&registryPrivate, "registry-private-key", "", "registry signer descriptor")
	cmd.Flags().StringVar(&reason, "reason", "", "compromise reason")
	cmd.Flags().Int64Var(&compromisedAtUnix, "compromised-at-unix", time.Now().UTC().Unix(), "compromise effective time in unix seconds")
	return cmd
}

func newKeyRotateCommand(rt *runtimeConfig) *cobra.Command {
	var registryPrivate, registryPublic, descriptorPath, previousKeyID, reason string
	var rotatedAtUnix, validUntilUnix int64
	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "Atomically retire one client key and register its replacement",
		RunE: func(cmd *cobra.Command, args []string) error {
			registryPath := stringValue(cmd, rt, "registry", "key_registry")
			registryKeyID := stringValue(cmd, rt, "registry-key-id", "registry_key_id")
			registryPrivate = stringOrConfig(cmd, rt, "registry-private-key", registryPrivate, "keys.registry_private")
			registryPublic = stringValue(cmd, rt, "registry-public-key", "keys.registry_public")
			tenantID := stringValue(cmd, rt, "tenant", "tenant")
			clientID := stringValue(cmd, rt, "client", "client")
			keyID := stringValue(cmd, rt, "key-id", "key_id")
			if registryPrivate == "" || descriptorPath == "" || clientID == "" || keyID == "" || previousKeyID == "" {
				return usageError("key rotate requires registry-private-key, descriptor, client, key-id, and previous-key-id")
			}
			descriptor, err := keydescriptor.ReadFile(descriptorPath)
			if err != nil {
				return err
			}
			if err := requireKeyID(keyID, descriptor); err != nil {
				return err
			}
			registry, err := openLifecycleRegistry(cmd.Context(), registryPath, registryPrivate, registryPublic, registryKeyID)
			if err != nil {
				return err
			}
			var validUntil time.Time
			if validUntilUnix != 0 {
				validUntil = time.Unix(validUntilUnix, 0).UTC()
			}
			event, err := registry.RotateClientKey(
				tenantID,
				clientID,
				previousKeyID,
				descriptor,
				time.Unix(rotatedAtUnix, 0).UTC(),
				validUntil,
				reason,
			)
			if err != nil {
				return err
			}
			return rt.writeJSON(map[string]any{
				"sequence":        event.Sequence,
				"event_hash":      base64.RawURLEncoding.EncodeToString(event.EventHash),
				"registry":        registryPath,
				"crypto_suite":    string(event.CryptoSuite),
				"previous_key_id": previousKeyID,
				"key_id":          descriptor.KeyID,
			})
		},
	}
	addRegistryFlags(cmd)
	addCommonIdentityFlags(cmd)
	cmd.Flags().String("registry-key-id", "", "registry signing key id")
	cmd.Flags().StringVar(&registryPrivate, "registry-private-key", "", "registry signer descriptor")
	cmd.Flags().StringVar(&descriptorPath, "descriptor", "", "replacement signer or verifier descriptor")
	cmd.Flags().StringVar(&previousKeyID, "previous-key-id", "", "key ID retired by this rotation")
	cmd.Flags().StringVar(&reason, "reason", "rotation", "rotation reason")
	cmd.Flags().Int64Var(&rotatedAtUnix, "rotated-at-unix", time.Now().UTC().Unix(), "rotation effective time in unix seconds")
	cmd.Flags().Int64Var(&validUntilUnix, "valid-until-unix", 0, "replacement validity end in unix seconds, 0 means no expiry")
	return cmd
}

func openLifecycleRegistry(ctx context.Context, registryPath, registryPrivate, registryPublic, registryKeyID string) (*keystore.Registry, error) {
	registrySigner, registryDescriptor, err := readLifecycleSigner(ctx, registryPrivate)
	if err != nil {
		return nil, err
	}
	if err := requireKeyID(registryKeyID, registryDescriptor); err != nil {
		return nil, err
	}
	registryPub, err := registrySigner.PublicKey(ctx)
	if err != nil {
		return nil, err
	}
	if registryPublic != "" {
		configuredPub, _, err := readPublicKeyDescriptor(registryPublic)
		if err != nil {
			return nil, err
		}
		if configuredPub.Suite != registryPub.Suite || configuredPub.KeyID != registryPub.KeyID || configuredPub.Algorithm != registryPub.Algorithm || configuredPub.Encoding != registryPub.Encoding || !bytes.Equal(configuredPub.Bytes, registryPub.Bytes) {
			return nil, usageError("registry public descriptor does not match registry signer descriptor")
		}
	}
	return keystore.Open(registryPath, registrySigner, registryPub)
}

func newKeyListCommand(rt *runtimeConfig, hidden bool) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "key-list",
		Aliases: []string{"list"},
		Short:   "List verified V2 registry events",
		Hidden:  hidden,
		RunE: func(cmd *cobra.Command, args []string) error {
			registryPath := stringValue(cmd, rt, "registry", "key_registry")
			registryPublic := stringValue(cmd, rt, "registry-public-key", "keys.registry_public")
			if registryPublic == "" {
				return usageError("key list requires registry-public-key as an external trust root")
			}
			registryDescriptor, _, err := readPublicKeyDescriptor(registryPublic)
			if err != nil {
				return err
			}
			reg, err := keystore.Open(registryPath, nil, registryDescriptor)
			if err != nil {
				return err
			}
			events := reg.Events()
			views := make([]map[string]any, 0, len(events))
			for _, event := range events {
				view, err := registryEventView(event)
				if err != nil {
					return err
				}
				views = append(views, view)
			}
			return rt.writeJSON(map[string]any{
				"manifest": reg.Manifest(),
				"events":   views,
			})
		},
	}
	addRegistryFlags(cmd)
	return cmd
}

func registryEventView(event model.KeyEvent) (map[string]any, error) {
	view := map[string]any{
		"schema_version":           event.SchemaVersion,
		"crypto_suite":             event.CryptoSuite,
		"sequence":                 event.Sequence,
		"type":                     event.Type,
		"tenant_id":                event.TenantID,
		"client_id":                event.ClientID,
		"key_id":                   event.KeyID,
		"previous_key_id":          event.PreviousKeyID,
		"valid_from_unix_nano":     event.ValidFromUnixN,
		"valid_until_unix_nano":    event.ValidUntilUnixN,
		"rotated_at_unix_nano":     event.RotatedAtUnixN,
		"revoked_at_unix_nano":     event.RevokedAtUnixN,
		"compromised_at_unix_nano": event.CompromisedAtUnixN,
		"reason":                   event.Reason,
		"prev_event_hash":          base64.RawURLEncoding.EncodeToString(event.PrevEventHash),
		"event_hash":               base64.RawURLEncoding.EncodeToString(event.EventHash),
		"registry_signature":       event.RegistrySignature,
	}
	if len(event.KeyDescriptor) != 0 {
		descriptor, err := keydescriptor.Unmarshal(event.KeyDescriptor)
		if err != nil {
			return nil, err
		}
		view["key_descriptor"] = descriptor.Redacted()
	}
	return view, nil
}
