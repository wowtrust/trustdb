package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/sproof"
	"github.com/wowtrust/trustdb/sdk"
)

// VerifyRequest covers both verify modes the UI offers:
//
//   - local: the user picks the recommended .sproof single proof, or
//     the lower-level .tdproof (+ optional .tdgproof / .tdanchor-result)
//     split files, plus a content file to check.
//   - remote: the user gives a record_id and we fetch the bundle
//     plus global/STH artefacts from the configured server, so field
//     auditors can verify a claim without downloading anything.
//
// ClientPublicKeyB64 is optional 鈥?if empty we fall back to the
// desktop's own identity public key, which is the common case for
// verifying your own submissions.
type VerifyRequest struct {
	Mode            string `json:"mode"` // "local" or "remote"
	FilePath        string `json:"file_path"`
	SingleProofPath string `json:"single_proof_path,omitempty"`
	ProofPath       string `json:"proof_path,omitempty"`
	GlobalProofPath string `json:"global_proof_path,omitempty"`
	AnchorPath      string `json:"anchor_path,omitempty"`
	ServerURL       string `json:"server_url,omitempty"`
	RecordID        string `json:"record_id,omitempty"`
	SkipAnchor      bool   `json:"skip_anchor,omitempty"`
	ClientPubKeyB64 string `json:"client_public_key_b64,omitempty"`
	ServerPubKeyB64 string `json:"server_public_key_b64,omitempty"`
}

// VerifyResponse is the rich, user-facing outcome. We include the
// underlying ProofBundle so the UI can render a breakdown (batch id,
// leaf index, tree size, batch root hex, anchor sink) without an
// additional round-trip.
type VerifyResponse struct {
	Valid        bool                   `json:"valid"`
	Level        string                 `json:"level"`
	RecordID     string                 `json:"record_id"`
	AnchorSink   string                 `json:"anchor_sink,omitempty"`
	AnchorID     string                 `json:"anchor_id,omitempty"`
	Bundle       *model.ProofBundle     `json:"bundle,omitempty"`
	GlobalProof  *model.GlobalLogProof  `json:"global_proof,omitempty"`
	Anchor       *model.STHAnchorResult `json:"anchor,omitempty"`
	ContentBytes int64                  `json:"content_bytes,omitempty"`
	Error        string                 `json:"error,omitempty"`
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

	var bundle model.ProofBundle
	var globalProof *model.GlobalLogProof
	var anchor *model.STHAnchorResult
	switch req.Mode {
	case "", "local":
		if req.SingleProofPath != "" {
			var proof model.SingleProof
			if err := readSingleProofFile(req.SingleProofPath, &proof); err != nil {
				return nil, err
			}
			bundle = proof.ProofBundle
			globalProof = proof.GlobalProof
			if !req.SkipAnchor {
				anchor = proof.AnchorResult
			}
			if anchor != nil && globalProof == nil {
				return nil, errors.New(".sproof contains anchor_result but no global_proof; cannot verify L5")
			}
		} else {
			if req.ProofPath == "" {
				return nil, errors.New("single_proof_path or proof_path is required in local mode")
			}
			if err := readProofBundleFile(req.ProofPath, &bundle); err != nil {
				return nil, err
			}
			if req.GlobalProofPath != "" {
				var proof model.GlobalLogProof
				if err := readGlobalProofFile(req.GlobalProofPath, &proof); err != nil {
					return nil, err
				}
				globalProof = &proof
			}
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
		bundle, err = c.getProof(a.ensureCtx(), req.RecordID)
		if err != nil {
			return nil, fmt.Errorf("fetch proof: %w", err)
		}
		proof, err := c.getGlobalProof(a.ensureCtx(), bundle.CommittedReceipt.BatchID)
		if err == nil {
			globalProof = &proof
			if !req.SkipAnchor {
				env, err := c.getAnchor(a.ensureCtx(), proof.STH.TreeSize)
				if err == nil && env.Result != nil {
					anchor = env.Result
				}
			}
		}
	default:
		return nil, fmt.Errorf("unsupported mode: %s", req.Mode)
	}

	clientPub, err := a.resolveClientPub(bundle, req.ClientPubKeyB64)
	if err != nil {
		return nil, err
	}
	serverPub, err := a.resolveServerPub(req.ServerPubKeyB64)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(req.FilePath)
	if err != nil {
		return nil, fmt.Errorf("open content file: %w", err)
	}
	defer f.Close()

	res, err := sdk.VerifyArtifacts(f, sdk.ProofArtifacts{
		Bundle:       bundle,
		GlobalProof:  globalProof,
		AnchorResult: anchor,
	}, sdk.TrustedKeys{
		ClientPublicKey: clientPub,
		ServerPublicKey: serverPub,
	}, sdk.VerifyOptions{SkipAnchor: req.SkipAnchor})
	if err != nil {
		return &VerifyResponse{
			Valid:        false,
			Level:        "",
			Bundle:       &bundle,
			GlobalProof:  globalProof,
			Anchor:       anchor,
			ContentBytes: bundle.SignedClaim.Claim.Content.ContentLength,
			Error:        err.Error(),
		}, nil
	}
	return &VerifyResponse{
		Valid:        res.Valid,
		Level:        res.ProofLevel,
		RecordID:     res.RecordID,
		AnchorSink:   res.AnchorSink,
		AnchorID:     res.AnchorID,
		Bundle:       &bundle,
		GlobalProof:  globalProof,
		Anchor:       anchor,
		ContentBytes: bundle.SignedClaim.Claim.Content.ContentLength,
	}, nil
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
	return newServerClient(cfg.ServerTransport, cfg.ServerURL)
}

func (a *App) resolveClientPub(bundle model.ProofBundle, override string) (ed25519.PublicKey, error) {
	if override != "" {
		raw, err := decodeKeyField(override)
		if err != nil {
			return nil, fmt.Errorf("client public key: %w", err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("client public key wrong size: %d", len(raw))
		}
		return ed25519.PublicKey(raw), nil
	}
	// Fall back to our own key. This is the right default when the
	// user is verifying their own submissions 鈥?it's the public
	// half of the same key that signed them 鈥?but it will fail
	// with a clean error if the bundle's key_id does not match.
	st, err := a.requireStore()
	if err != nil {
		return nil, err
	}
	id := st.getIdentity()
	if id == nil || id.PublicKeyB64 == "" {
		return nil, errors.New("no client public key available; paste one into Verify or create an identity")
	}
	if id.KeyID != bundle.SignedClaim.Claim.KeyID {
		return nil, fmt.Errorf("bundle signed with key_id=%s but desktop identity is key_id=%s; paste the right public key",
			bundle.SignedClaim.Claim.KeyID, id.KeyID)
	}
	raw, err := decodeKeyField(id.PublicKeyB64)
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(raw), nil
}

func (a *App) resolveServerPub(override string) (ed25519.PublicKey, error) {
	if override != "" {
		raw, err := decodeKeyField(override)
		if err != nil {
			return nil, fmt.Errorf("server public key: %w", err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("server public key wrong size: %d", len(raw))
		}
		return ed25519.PublicKey(raw), nil
	}
	return a.serverPublicKey()
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
