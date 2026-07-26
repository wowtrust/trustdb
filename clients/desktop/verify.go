package main

import (
	"bytes"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/wowtrust/trustdb/v2/internal/cborx"
	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/keydescriptor"
	"github.com/wowtrust/trustdb/v2/internal/model"
	"github.com/wowtrust/trustdb/v2/internal/sproof"
	"github.com/wowtrust/trustdb/v2/sdk"
)

// VerifyRequest covers both verify modes the UI offers:
//
//   - local: the user picks the recommended .sproof single proof, or
//     the lower-level .tdproof (+ optional .tdgproof / .tdanchor-result)
//     split files, plus a content file to check.
//   - remote: the user gives a record_id and we acquire one complete proof
//     from the configured server before running the same local verifier.
type VerifyRequest struct {
	Mode                       string `json:"mode"` // "local" or "remote"
	FilePath                   string `json:"file_path"`
	SingleProofPath            string `json:"single_proof_path,omitempty"`
	ProofPath                  string `json:"proof_path,omitempty"`
	GlobalProofPath            string `json:"global_proof_path,omitempty"`
	AnchorPath                 string `json:"anchor_path,omitempty"`
	ServerURL                  string `json:"server_url,omitempty"`
	RecordID                   string `json:"record_id,omitempty"`
	SkipAnchor                 bool   `json:"skip_anchor,omitempty"`
	ClientPubKeyB64            string `json:"client_public_key_b64,omitempty"`
	ServerPubKeyB64            string `json:"server_public_key_b64,omitempty"`
	ClientVerifierDescriptors  string `json:"client_verifier_descriptors,omitempty"`
	ServerVerifierDescriptors  string `json:"server_verifier_descriptors,omitempty"`
	RegistryVerifierDescriptor string `json:"registry_verifier_descriptor,omitempty"`
	ClientCertificateRoots     string `json:"client_certificate_roots,omitempty"`
	ServerCertificateRoots     string `json:"server_certificate_roots,omitempty"`
	RequireIdentityEvidence    bool   `json:"require_identity_evidence,omitempty"`
	RequireCertificateStatus   bool   `json:"require_certificate_status,omitempty"`
}

type VerificationStageView struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type IdentityVerificationView struct {
	EvidenceCount               int `json:"evidence_count"`
	PublicKeyBindingsVerified   int `json:"public_key_bindings_verified"`
	LifecycleBindingsVerified   int `json:"lifecycle_bindings_verified"`
	CertificateChainsVerified   int `json:"certificate_chains_verified"`
	CertificateStatusesVerified int `json:"certificate_statuses_verified"`
}

// VerifyResponse is the rich, user-facing outcome. We include the
// underlying ProofBundle so the UI can render a breakdown (batch id,
// leaf index, tree size, batch root hex, anchor sink) without an
// additional round-trip.
type VerifyResponse struct {
	Valid                       bool                     `json:"valid"`
	Level                       string                   `json:"level"`
	RecordID                    string                   `json:"record_id"`
	CryptoSuite                 string                   `json:"crypto_suite"`
	HashAlg                     string                   `json:"hash_alg"`
	AnchorSink                  string                   `json:"anchor_sink,omitempty"`
	AnchorID                    string                   `json:"anchor_id,omitempty"`
	Bundle                      *model.ProofBundle       `json:"bundle,omitempty"`
	GlobalProof                 *model.GlobalLogProof    `json:"global_proof,omitempty"`
	Anchor                      *model.STHAnchorResult   `json:"anchor,omitempty"`
	ContentBytes                int64                    `json:"content_bytes,omitempty"`
	Stages                      []VerificationStageView  `json:"stages"`
	Identity                    IdentityVerificationView `json:"identity"`
	EvidenceCertificateCount    int                      `json:"evidence_certificate_count"`
	LocalTrustRootCount         int                      `json:"local_trust_root_count"`
	EvidenceCertificatesTrusted bool                     `json:"evidence_certificates_trusted"`
	ExternalNetworkAccess       bool                     `json:"external_network_access"`
	ExternalProviderAccess      bool                     `json:"external_provider_access"`
	TrustNotice                 string                   `json:"trust_notice"`
	Error                       string                   `json:"error,omitempty"`
}

// VerifyProof is the sole verify entry point exposed to the frontend.
// It dispatches to local-file or remote-http input acquisition, then
// calls into the shared Go SDK verification routine, so desktop callers use the
// same verification surface as external applications.
func (a *App) VerifyProof(req VerifyRequest) (*VerifyResponse, error) {
	if _, err := a.requireStore(); err != nil {
		return nil, err
	}
	if req.FilePath == "" {
		return nil, errors.New("file_path is required")
	}

	var proof model.SingleProof
	networkAcquisition := false
	switch req.Mode {
	case "", "local":
		if req.SingleProofPath != "" {
			if err := readSingleProofFile(req.SingleProofPath, &proof); err != nil {
				return nil, err
			}
		} else {
			if req.ProofPath == "" {
				return nil, errors.New("single_proof_path or proof_path is required in local mode")
			}
			var bundle model.ProofBundle
			if err := readProofBundleFile(req.ProofPath, &bundle); err != nil {
				return nil, err
			}
			var globalProof *model.GlobalLogProof
			if req.GlobalProofPath != "" {
				var global model.GlobalLogProof
				if err := readGlobalProofFile(req.GlobalProofPath, &global); err != nil {
					return nil, err
				}
				globalProof = &global
			}
			var anchor *model.STHAnchorResult
			if !req.SkipAnchor && req.AnchorPath != "" {
				if globalProof == nil {
					return nil, errors.New("anchor_path requires global_proof_path")
				}
				var ar model.STHAnchorResult
				if err := readAnchorResultFile(req.AnchorPath, &ar); err != nil {
					return nil, err
				}
				anchor = &ar
			}
			proof = model.SingleProof{
				SchemaVersion:   model.SchemaSingleProof,
				FormatVersion:   sproof.FormatVersion,
				CryptoSuite:     bundle.CryptoSuite,
				RecordID:        bundle.RecordID,
				ProofLevel:      "",
				NodeID:          bundle.NodeID,
				LogID:           bundle.LogID,
				ProofBundle:     bundle,
				GlobalProof:     globalProof,
				AnchorResult:    anchor,
				ExportedAtUnixN: time.Now().UTC().UnixNano(),
			}
			proof.ProofLevel = sproof.Level(proof).String()
		}
	case "remote":
		if req.RecordID == "" {
			return nil, errors.New("record_id is required in remote mode")
		}
		c, err := a.remoteClient(req.ServerURL)
		if err != nil {
			return nil, err
		}
		defer c.close()
		proof, err = c.exportSingleProof(a.ensureCtx(), req.RecordID)
		if err != nil {
			return nil, fmt.Errorf("fetch single proof: %w", err)
		}
		networkAcquisition = true
	default:
		return nil, fmt.Errorf("unsupported mode: %s", req.Mode)
	}

	trust, localRootCount, err := a.desktopOfflineTrust(proof, req)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(req.FilePath)
	if err != nil {
		return nil, fmt.Errorf("open content file: %w", err)
	}
	defer f.Close()

	result, verifyErr := sdk.VerifySingleProofOffline(
		f,
		proof,
		trust,
		sdk.OfflineVerifyOptions{SkipAnchor: req.SkipAnchor},
	)
	response := offlineVerifyResponse(proof, result, localRootCount, evidenceCertificateCount(proof))
	response.ExternalNetworkAccess = response.ExternalNetworkAccess || networkAcquisition
	if verifyErr != nil {
		response.Error = verifyErr.Error()
	}
	return response, nil
}

func (a *App) desktopOfflineTrust(
	proof model.SingleProof,
	req VerifyRequest,
) (sdk.OfflineTrust, int, error) {
	if _, err := cryptosuite.RequireAvailable(proof.CryptoSuite); err != nil {
		return sdk.OfflineTrust{}, 0, err
	}
	store, err := a.requireStore()
	if err != nil {
		return sdk.OfflineTrust{}, 0, err
	}
	settings := store.getSettings()

	clientPaths := req.ClientVerifierDescriptors
	if strings.TrimSpace(clientPaths) == "" {
		clientPaths = settings.ClientVerifierDescriptor
	}
	serverPaths := req.ServerVerifierDescriptors
	if strings.TrimSpace(serverPaths) == "" {
		serverPaths = settings.ServerVerifierDescriptor
	}
	registryPath := req.RegistryVerifierDescriptor
	if strings.TrimSpace(registryPath) == "" {
		registryPath = settings.RegistryVerifierDescriptor
	}
	clientRootPaths := req.ClientCertificateRoots
	if strings.TrimSpace(clientRootPaths) == "" {
		clientRootPaths = settings.ClientCertificateRoots
	}
	serverRootPaths := req.ServerCertificateRoots
	if strings.TrimSpace(serverRootPaths) == "" {
		serverRootPaths = settings.ServerCertificateRoots
	}

	var clientKeys []sdk.KeyDescriptor
	switch {
	case strings.TrimSpace(req.ClientPubKeyB64) != "":
		raw, decodeErr := decodeKeyField(req.ClientPubKeyB64)
		if decodeErr != nil {
			return sdk.OfflineTrust{}, 0, fmt.Errorf("client public key: %w", decodeErr)
		}
		key, keyErr := desktopPublicKeyDescriptor(proof.CryptoSuite, proof.ProofBundle.SignedClaim.Signature.KeyID, raw)
		if keyErr != nil {
			return sdk.OfflineTrust{}, 0, fmt.Errorf("client public key: %w", keyErr)
		}
		clientKeys = []sdk.KeyDescriptor{key}
	case strings.TrimSpace(clientPaths) != "":
		clientKeys, err = readDesktopVerifierDescriptors(clientPaths, proof.CryptoSuite)
		if err != nil {
			return sdk.OfflineTrust{}, 0, fmt.Errorf("client verifier descriptors: %w", err)
		}
	default:
		id := store.getIdentity()
		if id == nil {
			return sdk.OfflineTrust{}, 0, errors.New("no verifier-local client key configured")
		}
		descriptor, descriptorErr := loadDesktopIdentityDescriptor(*id)
		if descriptorErr != nil {
			return sdk.OfflineTrust{}, 0, descriptorErr
		}
		key, keyErr := sdkDescriptorFromCanonical(descriptor)
		if keyErr != nil {
			return sdk.OfflineTrust{}, 0, keyErr
		}
		clientKeys = []sdk.KeyDescriptor{key}
	}

	serverKeyIDs := proofServerKeyIDs(proof)
	var serverKeys []sdk.KeyDescriptor
	switch {
	case strings.TrimSpace(req.ServerPubKeyB64) != "":
		raw, decodeErr := decodeKeyField(req.ServerPubKeyB64)
		if decodeErr != nil {
			return sdk.OfflineTrust{}, 0, fmt.Errorf("server public key: %w", decodeErr)
		}
		serverKeys, err = rawDesktopVerifierDescriptors(proof.CryptoSuite, serverKeyIDs, raw)
	case strings.TrimSpace(serverPaths) != "":
		serverKeys, err = readDesktopVerifierDescriptors(serverPaths, proof.CryptoSuite)
	case strings.TrimSpace(settings.ServerPubKeyB64) != "":
		configuredSuite, suiteErr := requireDesktopSuite(settings.ServerCryptoSuite)
		if suiteErr != nil {
			return sdk.OfflineTrust{}, 0, suiteErr
		}
		if configuredSuite.ID != proof.CryptoSuite {
			return sdk.OfflineTrust{}, 0, fmt.Errorf(
				"configured server crypto_suite %s does not match proof %s",
				configuredSuite.ID,
				proof.CryptoSuite,
			)
		}
		raw, decodeErr := decodeKeyField(settings.ServerPubKeyB64)
		if decodeErr != nil {
			return sdk.OfflineTrust{}, 0, fmt.Errorf("server public key: %w", decodeErr)
		}
		serverKeys, err = rawDesktopVerifierDescriptors(proof.CryptoSuite, serverKeyIDs, raw)
	default:
		return sdk.OfflineTrust{}, 0, errors.New("no verifier-local server key configured")
	}
	if err != nil {
		return sdk.OfflineTrust{}, 0, fmt.Errorf("server verifier keys: %w", err)
	}

	clientProofKey, err := requireDesktopVerifierKey(clientKeys, proof.ProofBundle.SignedClaim.Signature.KeyID)
	if err != nil {
		return sdk.OfflineTrust{}, 0, fmt.Errorf("client proof key: %w", err)
	}
	acceptedKey, err := requireDesktopVerifierKey(serverKeys, proof.ProofBundle.AcceptedReceipt.ServerSig.KeyID)
	if err != nil {
		return sdk.OfflineTrust{}, 0, fmt.Errorf("accepted receipt key: %w", err)
	}
	committedKey, err := requireDesktopVerifierKey(serverKeys, proof.ProofBundle.CommittedReceipt.ServerSig.KeyID)
	if err != nil {
		return sdk.OfflineTrust{}, 0, fmt.Errorf("committed receipt key: %w", err)
	}
	proofKeys := sdk.TrustedKeys{
		ClientPublicKey:           clientProofKey,
		AcceptedReceiptPublicKey:  acceptedKey,
		CommittedReceiptPublicKey: committedKey,
	}
	if proof.GlobalProof != nil {
		sthKey, keyErr := requireDesktopVerifierKey(serverKeys, proof.GlobalProof.STH.Signature.KeyID)
		if keyErr != nil {
			return sdk.OfflineTrust{}, 0, fmt.Errorf("signed tree head key: %w", keyErr)
		}
		proofKeys.SignedTreeHeadPublicKey = sthKey
	}

	clientRoots, err := readDesktopCertificateRoots(clientRootPaths)
	if err != nil {
		return sdk.OfflineTrust{}, 0, fmt.Errorf("client certificate roots: %w", err)
	}
	serverRoots, err := readDesktopCertificateRoots(serverRootPaths)
	if err != nil {
		return sdk.OfflineTrust{}, 0, fmt.Errorf("server certificate roots: %w", err)
	}
	var registryKey sdk.KeyDescriptor
	if strings.TrimSpace(registryPath) != "" {
		keys, keyErr := readDesktopVerifierDescriptors(registryPath, proof.CryptoSuite)
		if keyErr != nil {
			return sdk.OfflineTrust{}, 0, fmt.Errorf("registry verifier descriptor: %w", keyErr)
		}
		if len(keys) != 1 {
			return sdk.OfflineTrust{}, 0, errors.New("registry verifier descriptor must contain exactly one path")
		}
		registryKey = keys[0]
	}
	return sdk.OfflineTrust{
		Proof: proofKeys,
		Identity: sdk.OfflineIdentityTrust{
			ClientPublicKeys:         clientKeys,
			ServerPublicKeys:         serverKeys,
			ClientCertificateRoots:   clientRoots,
			ServerCertificateRoots:   serverRoots,
			RegistryPublicKey:        registryKey,
			RequireEvidence:          req.RequireIdentityEvidence || settings.RequireIdentityEvidence,
			RequireCertificateStatus: req.RequireCertificateStatus || settings.RequireCertificateStatus,
		},
	}, len(clientRoots) + len(serverRoots), nil
}

func readDesktopVerifierDescriptors(paths string, suite cryptosuite.ID) ([]sdk.KeyDescriptor, error) {
	items := desktopPathList(paths)
	if len(items) == 0 {
		return nil, errors.New("no descriptor path supplied")
	}
	keys := make([]sdk.KeyDescriptor, 0, len(items))
	for _, path := range items {
		descriptor, err := keydescriptor.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if descriptor.CryptoSuite != suite {
			return nil, fmt.Errorf("descriptor key_id=%s has crypto_suite %s, want %s", descriptor.KeyID, descriptor.CryptoSuite, suite)
		}
		key, err := sdkDescriptorFromCanonical(descriptor)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func sdkDescriptorFromCanonical(descriptor keydescriptor.Descriptor) (sdk.KeyDescriptor, error) {
	public, err := descriptor.PublicKeyDescriptor()
	if err != nil {
		return sdk.KeyDescriptor{}, err
	}
	out := sdk.KeyDescriptor{
		CryptoSuite:       public.Suite,
		Provider:          keydescriptor.ProviderPublic,
		KeyID:             public.KeyID,
		Algorithm:         public.Algorithm,
		PublicKeyEncoding: public.Encoding,
		PublicKey:         append([]byte(nil), public.Bytes...),
		SM2UserID:         descriptor.SM2UserID,
		CertificateChain:  cloneByteSlices(descriptor.CertificateChain),
	}
	if err := out.Validate(); err != nil {
		return sdk.KeyDescriptor{}, err
	}
	return out, nil
}

func rawDesktopVerifierDescriptors(
	suite cryptosuite.ID,
	keyIDs []string,
	raw []byte,
) ([]sdk.KeyDescriptor, error) {
	seen := make(map[string]struct{}, len(keyIDs))
	keys := make([]sdk.KeyDescriptor, 0, len(keyIDs))
	for _, keyID := range keyIDs {
		if keyID == "" {
			continue
		}
		if _, exists := seen[keyID]; exists {
			continue
		}
		seen[keyID] = struct{}{}
		key, err := desktopPublicKeyDescriptor(suite, keyID, raw)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func proofServerKeyIDs(proof model.SingleProof) []string {
	keyIDs := []string{
		proof.ProofBundle.AcceptedReceipt.ServerSig.KeyID,
		proof.ProofBundle.CommittedReceipt.ServerSig.KeyID,
	}
	if proof.GlobalProof != nil {
		keyIDs = append(keyIDs, proof.GlobalProof.STH.Signature.KeyID)
	}
	return keyIDs
}

func requireDesktopVerifierKey(keys []sdk.KeyDescriptor, keyID string) (sdk.KeyDescriptor, error) {
	var match *sdk.KeyDescriptor
	for index := range keys {
		if keys[index].KeyID != keyID {
			continue
		}
		if match != nil {
			return sdk.KeyDescriptor{}, fmt.Errorf("key_id %s has multiple verifier-local descriptors", keyID)
		}
		copy := keys[index].Clone()
		match = &copy
	}
	if match == nil {
		return sdk.KeyDescriptor{}, fmt.Errorf("key_id %s has no verifier-local descriptor", keyID)
	}
	return match.Clone(), nil
}

func readDesktopCertificateRoots(paths string) ([][]byte, error) {
	items := desktopPathList(paths)
	roots := make([][]byte, 0, len(items))
	for _, path := range items {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		const maxRootFileBytes = 4 << 20
		data, readErr := io.ReadAll(io.LimitReader(file, maxRootFileBytes+1))
		closeErr := file.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if len(data) > maxRootFileBytes {
			return nil, errors.New("certificate root file exceeds 4 MiB")
		}
		rest := bytes.TrimSpace(data)
		if len(rest) == 0 {
			return nil, errors.New("certificate root file is empty")
		}
		decodedPEM := false
		for len(rest) != 0 {
			block, next := pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				return nil, fmt.Errorf("certificate root PEM contains block type %q", block.Type)
			}
			roots = append(roots, append([]byte(nil), block.Bytes...))
			decodedPEM = true
			rest = bytes.TrimSpace(next)
		}
		if decodedPEM {
			if len(rest) != 0 {
				return nil, errors.New("certificate root PEM contains trailing data")
			}
			continue
		}
		roots = append(roots, append([]byte(nil), data...))
	}
	return roots, nil
}

func desktopPathList(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ';'
	})
}

func evidenceCertificateCount(proof model.SingleProof) int {
	count := 0
	for _, evidence := range proof.IdentityEvidence {
		descriptor, err := keydescriptor.Unmarshal(evidence.KeyDescriptor)
		if err == nil {
			count += len(descriptor.CertificateChain)
		}
	}
	return count
}

func offlineVerifyResponse(
	proof model.SingleProof,
	result sdk.OfflineVerifyResult,
	localRootCount, evidenceCertificates int,
) *VerifyResponse {
	stages := make([]VerificationStageView, len(result.Stages))
	for index := range result.Stages {
		stages[index] = VerificationStageView{
			Name:   result.Stages[index].Name,
			Status: string(result.Stages[index].Status),
			Error:  result.Stages[index].Error,
		}
	}
	return &VerifyResponse{
		Valid:        result.Valid,
		Level:        result.ProofLevel,
		RecordID:     result.RecordID,
		CryptoSuite:  string(proof.CryptoSuite),
		HashAlg:      proof.ProofBundle.SignedClaim.Claim.Content.HashAlg,
		AnchorSink:   result.AnchorSink,
		AnchorID:     result.AnchorID,
		Bundle:       &proof.ProofBundle,
		GlobalProof:  proof.GlobalProof,
		Anchor:       proof.AnchorResult,
		ContentBytes: proof.ProofBundle.SignedClaim.Claim.Content.ContentLength,
		Stages:       stages,
		Identity: IdentityVerificationView{
			EvidenceCount:               result.Identity.EvidenceCount,
			PublicKeyBindingsVerified:   result.Identity.PublicKeyBindingsVerified,
			LifecycleBindingsVerified:   result.Identity.LifecycleBindingsVerified,
			CertificateChainsVerified:   result.Identity.CertificateChainsVerified,
			CertificateStatusesVerified: result.Identity.CertificateStatusesVerified,
		},
		EvidenceCertificateCount:    evidenceCertificates,
		LocalTrustRootCount:         localRootCount,
		EvidenceCertificatesTrusted: false,
		ExternalNetworkAccess:       result.ExternalNetworkAccess,
		ExternalProviderAccess:      result.ExternalProviderAccess,
		TrustNotice:                 "Certificates carried by the evidence are evidence only; trust roots come exclusively from verifier-local settings.",
	}
}

func (a *App) remoteClient(override string) (*serverClient, error) {
	if override == "" {
		return a.serverClient()
	}
	s, err := a.requireStore()
	if err != nil {
		return nil, err
	}
	cfg := s.getSettings()
	cfg.ServerURL = override
	suite, err := requireDesktopSuite(cfg.ServerCryptoSuite)
	if err != nil {
		return nil, err
	}
	return newServerClientWithTLSForSuite(cfg.ServerTransport, cfg.ServerURL, tlsConfigFromSettings(cfg), suite.ID)
}

func readProofBundleFile(path string, out *model.ProofBundle) error {
	data, err := readCBORFileLimit(path, cborx.DefaultMaxBytes)
	if err != nil {
		return fmt.Errorf("read proof: %w", err)
	}
	if err := cborx.Unmarshal(data, out); err != nil {
		return typedProofFileError("proof", path, model.SchemaProofBundle, data, err)
	}
	if out.SchemaVersion != model.SchemaProofBundle {
		return schemaMismatchError("proof", path, model.SchemaProofBundle, out.SchemaVersion)
	}
	return nil
}

func readSingleProofFile(path string, out *model.SingleProof) error {
	data, err := readCBORFileLimit(path, sproof.MaxBytes)
	if err != nil {
		return fmt.Errorf("read single proof: %w", err)
	}
	if err := cborx.UnmarshalLimit(data, out, sproof.MaxBytes); err != nil {
		return typedProofFileError("single proof", path, model.SchemaSingleProof, data, err)
	}
	if out.SchemaVersion != model.SchemaSingleProof {
		return schemaMismatchError("single proof", path, model.SchemaSingleProof, out.SchemaVersion)
	}
	if err := sproof.Validate(*out); err != nil {
		return fmt.Errorf("decode single proof: %s: %w", filepath.Base(path), err)
	}
	return nil
}
func readGlobalProofFile(path string, out *model.GlobalLogProof) error {
	data, err := readCBORFileLimit(path, cborx.DefaultMaxBytes)
	if err != nil {
		return fmt.Errorf("read global proof: %w", err)
	}
	if err := cborx.Unmarshal(data, out); err != nil {
		return typedProofFileError("global proof", path, model.SchemaGlobalLogProof, data, err)
	}
	if out.SchemaVersion != model.SchemaGlobalLogProof {
		return schemaMismatchError("global proof", path, model.SchemaGlobalLogProof, out.SchemaVersion)
	}
	return nil
}

func readAnchorResultFile(path string, out *model.STHAnchorResult) error {
	data, err := readCBORFileLimit(path, cborx.DefaultMaxBytes)
	if err != nil {
		return fmt.Errorf("read anchor: %w", err)
	}
	if err := cborx.Unmarshal(data, out); err != nil {
		return typedProofFileError("anchor", path, model.SchemaSTHAnchorResult, data, err)
	}
	if out.SchemaVersion != model.SchemaSTHAnchorResult {
		return schemaMismatchError("anchor", path, model.SchemaSTHAnchorResult, out.SchemaVersion)
	}
	return nil
}

func readCBORFileLimit(path string, maxBytes int) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("max bytes must be positive")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, int64(maxBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxBytes {
		return nil, fmt.Errorf("payload too large: %d > %d", len(data), maxBytes)
	}
	return data, nil
}

func schemaMismatchError(kind, path, want, got string) error {
	name := filepath.Base(path)
	if got == "" {
		return fmt.Errorf("decode %s: %s has no schema_version; want %s", kind, name, want)
	}
	if got != want {
		return wrongSchemaHint(kind, name, want, got)
	}
	return fmt.Errorf("decode %s: %s schema_version=%q, want %q", kind, name, got, want)
}

func typedProofFileError(kind, path, want string, data []byte, decodeErr error) error {
	name := filepath.Base(path)
	if isJSONLike(data) {
		return fmt.Errorf("decode %s: %s is JSON text, not a TrustDB CBOR proof file", kind, name)
	}
	fields, ok := cborTopLevelMap(data)
	if ok {
		schema := stringField(fields, "schema_version")
		switch {
		case schema == want:
			return fmt.Errorf("decode %s: %s has schema %s but cannot be decoded: %w", kind, name, want, decodeErr)
		case schema != "":
			return wrongSchemaHint(kind, name, want, schema)
		case looksLikeSTHAnchorResult(fields):
			return wrongSchemaHint(kind, name, want, model.SchemaSTHAnchorResult)
		case looksLikeLegacyBatchAnchor(fields):
			return fmt.Errorf("decode %s: %s looks like a legacy batch anchor result, not GlobalLogProof; current L5 only accepts STH/global root, export .tdgproof and STHAnchorResult again", kind, name)
		}
	}
	return fmt.Errorf("decode %s: %w", kind, decodeErr)
}

func wrongSchemaHint(kind, name, want, got string) error {
	if got == model.SchemaSingleProof && kind != "single proof" {
		return fmt.Errorf("decode %s: %s is a .sproof single proof; use the main .sproof input, not the %s input that expects %q", kind, name, kind, want)
	}
	if kind == "single proof" {
		switch got {
		case model.SchemaProofBundle:
			return fmt.Errorf("decode single proof: %s is a .tdproof split proof bundle; use .sproof or put it in the advanced .tdproof input", name)
		case model.SchemaGlobalLogProof:
			return fmt.Errorf("decode single proof: %s is a .tdgproof GlobalLogProof; use .sproof or put it in the advanced .tdgproof input", name)
		case model.SchemaSTHAnchorResult:
			return fmt.Errorf("decode single proof: %s is a .tdanchor-result STHAnchorResult; use .sproof or put it in the advanced .tdanchor-result input", name)
		}
	}
	if kind == "global proof" && got == model.SchemaSTHAnchorResult {
		return fmt.Errorf("decode global proof: %s is an STHAnchorResult L5 anchor file; put it in the .tdanchor-result input; .tdgproof must be exported as GlobalLogProof", name)
	}
	if kind == "anchor" && got == model.SchemaGlobalLogProof {
		return fmt.Errorf("decode anchor: %s is a GlobalLogProof L4 file; put it in the .tdgproof input; L5 also needs STHAnchorResult", name)
	}
	return fmt.Errorf("decode %s: %s schema_version=%q, want %q", kind, name, got, want)
}
func isJSONLike(data []byte) bool {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return false
	}
	return trimmed[0] == '{' || trimmed[0] == '['
}

func cborTopLevelMap(data []byte) (map[string]any, bool) {
	var fields map[string]any
	if err := cborx.Unmarshal(data, &fields); err != nil {
		return nil, false
	}
	return fields, true
}

func stringField(fields map[string]any, name string) string {
	if v, ok := fields[name].(string); ok {
		return v
	}
	return ""
}

func looksLikeSTHAnchorResult(fields map[string]any) bool {
	return hasField(fields, "sth") && hasField(fields, "anchor_id") && hasField(fields, "root_hash")
}

func looksLikeLegacyBatchAnchor(fields map[string]any) bool {
	return hasField(fields, "anchor_id") && hasField(fields, "proof") && hasField(fields, "batch_root")
}

func hasField(fields map[string]any, name string) bool {
	_, ok := fields[name]
	return ok
}
