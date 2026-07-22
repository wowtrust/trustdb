package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/wowtrust/trustdb/internal/anchor"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/prooflevel"
	"github.com/wowtrust/trustdb/internal/sproof"
)

// SubmitRequest is the single, JSON-friendly shape the UI uses to
// describe a pending attestation. media_type / event_type / source
// are optional overrides; empty strings fall back to the settings
// defaults or the file's sniffed content-type.
type SubmitRequest struct {
	Path      string `json:"path"`
	MediaType string `json:"media_type,omitempty"`
	EventType string `json:"event_type,omitempty"`
	Source    string `json:"source,omitempty"`
}

// SubmitResult is what SubmitFile returns to the Vue side — it
// carries both the persisted LocalRecord (for list updates) and a
// couple of server-reported flags the UI can surface as toasts
// ("duplicate, already accepted earlier" / "batch queued").
type SubmitResult struct {
	Record      LocalRecord `json:"record"`
	ProofLevel  string      `json:"proof_level"`
	Idempotent  bool        `json:"idempotent"`
	BatchQueued bool        `json:"batch_queued"`
	BatchError  string      `json:"batch_error,omitempty"`
}

// SubmitFile hashes, signs and submits one file through the shared Go SDK to the
// configured TrustDB server. On success we persist a LocalRecord so
// the Records page can resume tracking (L2→L3→L5) across restarts.
// Any error leaves the store untouched — a half-submitted attestation
// is worse than no record at all because it would make subsequent
// retries look like duplicates.
func (a *App) SubmitFile(req SubmitRequest) (*SubmitResult, error) {
	st, err := a.requireStore()
	if err != nil {
		return nil, err
	}
	if req.Path == "" {
		return nil, errors.New("path is required")
	}
	id := st.getIdentity()
	if id == nil {
		return nil, errors.New("identity not configured — create or import a key first")
	}
	_, priv, err := loadSigningKeys(*id)
	if err != nil {
		return nil, err
	}

	infos, err := a.describeFiles([]string{req.Path})
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	if len(infos) == 0 {
		return nil, fmt.Errorf("no file found at %s", req.Path)
	}
	info := infos[0]

	cfg := st.getSettings()
	media := req.MediaType
	if media == "" {
		media = info.MediaType
	}
	if media == "" {
		media = cfg.DefaultMedia
	}
	event := req.EventType
	if event == "" {
		event = cfg.DefaultEvent
	}

	signed, idempotency, err := buildSignedClaim(priv, *id, info, media, event, req.Source)
	if err != nil {
		return nil, err
	}

	c, err := a.serverClient()
	if err != nil {
		return nil, err
	}
	defer c.close()
	resp, err := c.submitSignedClaim(a.ensureCtx(), signed)
	if err != nil {
		return nil, err
	}

	rec := LocalRecord{
		RecordID:        resp.RecordID,
		FilePath:        info.Path,
		FileName:        info.Name,
		ContentHashHex:  info.ContentHash,
		ContentLength:   info.Size,
		MediaType:       media,
		EventType:       event,
		Source:          req.Source,
		IdempotencyKey:  idempotency,
		TenantID:        id.TenantID,
		ClientID:        id.ClientID,
		KeyID:           id.KeyID,
		ProofLevel:      prooflevel.L2.String(),
		ServerRecord:    &resp.ServerRecord,
		AcceptedReceipt: &resp.AcceptedReceipt,
	}
	setLocalRecordSubmittedAt(&rec, time.Now().UTC())
	if existing, ok := st.getRecord(resp.RecordID); ok && resp.Idempotent {
		// Preserve earlier progress (L3 proof / L5 anchor) on a
		// duplicate replay so the user's list doesn't visually
		// regress from L5 back to L2.
		rec.ProofLevel = existing.ProofLevel
		rec.BatchID = existing.BatchID
		rec.AnchorStatus = existing.AnchorStatus
		rec.AnchorSink = existing.AnchorSink
		rec.AnchorID = existing.AnchorID
		rec.CommittedReceipt = existing.CommittedReceipt
		rec.GlobalProof = existing.GlobalProof
		rec.AnchorResult = existing.AnchorResult
	}
	if err := st.upsertRecord(rec); err != nil {
		return nil, err
	}
	return &SubmitResult{
		Record:      rec,
		ProofLevel:  resp.ProofLevel,
		Idempotent:  resp.Idempotent,
		BatchQueued: resp.BatchEnqueued,
		BatchError:  resp.BatchError,
	}, nil
}

// SubmitBatch is a convenience wrapper the "drop multiple files"
// flow calls. Errors on individual files are surfaced per-result so
// partial successes show up in the UI instead of aborting the whole
// batch on the first failure.
type BatchItemResult struct {
	Path    string        `json:"path"`
	Success bool          `json:"success"`
	Error   string        `json:"error,omitempty"`
	Result  *SubmitResult `json:"result,omitempty"`
}

func (a *App) SubmitBatch(reqs []SubmitRequest) []BatchItemResult {
	out := make([]BatchItemResult, 0, len(reqs))
	for _, r := range reqs {
		item := BatchItemResult{Path: r.Path}
		res, err := a.SubmitFile(r)
		if err != nil {
			item.Error = err.Error()
		} else {
			item.Success = true
			item.Result = res
		}
		out = append(out, item)
	}
	return out
}

// RefreshRecord re-polls /v1/proofs, /v1/global-log/inclusion and
// /v1/anchors/sth for one record
// and updates its persisted state accordingly. Returns the freshly
// merged LocalRecord so the UI can bind to a single source of
// truth.
func (a *App) RefreshRecord(recordID string) (*LocalRecord, error) {
	st, err := a.requireStore()
	if err != nil {
		return nil, err
	}
	rec, ok := st.getRecord(recordID)
	c, err := a.serverClient()
	if err != nil {
		return nil, err
	}
	defer c.close()
	if !ok {
		idx, err := c.getRecordIndex(a.ensureCtx(), recordID)
		if err != nil {
			return nil, fmt.Errorf("record %s not found locally or on server: %w", recordID, err)
		}
		rec = localRecordFromIndex(idx)
	}
	rec.LastError = ""
	setLocalRecordLastSyncedAt(&rec, time.Now().UTC())

	bundle, err := c.getProof(a.ensureCtx(), recordID)
	if err != nil {
		// A 404 means the batch hasn't been committed yet — that
		// is an expected intermediate state so we don't treat it
		// as a hard failure, just leave the record at L2.
		if se, ok := err.(*ServerError); ok && se.StatusCode == 404 {
			_ = st.upsertRecord(rec)
			return &rec, nil
		}
		rec.LastError = err.Error()
		_ = st.upsertRecord(rec)
		return &rec, err
	}
	cr := bundle.CommittedReceipt
	evidence := prooflevel.EvidenceFor(prooflevel.L3)
	rec.ProofLevel = prooflevel.Evaluate(evidence).String()
	rec.BatchID = cr.BatchID
	rec.CommittedReceipt = &cr

	globalProof, err := c.getGlobalProof(a.ensureCtx(), cr.BatchID)
	if err == nil {
		rec.GlobalProof = &globalProof
		evidence.GlobalLogProof = true
		rec.ProofLevel = prooflevel.Evaluate(evidence).String()
		anchor, err := c.getAnchor(a.ensureCtx(), globalProof.STH.TreeSize)
		if err == nil {
			rec.AnchorStatus = anchor.Status
			if anchor.Result != nil {
				rec.AnchorResult = anchor.Result
				rec.AnchorSink = anchor.Result.SinkName
				rec.AnchorID = anchor.Result.AnchorID
				evidence.STHAnchorResult = true
				rec.ProofLevel = prooflevel.Evaluate(evidence).String()
			}
		}
	}
	if err := st.upsertRecord(rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// ExportProofBundle writes the server-sent ProofBundle to disk as
// canonical CBOR — matching the .tdproof format that the CLI
// verify subcommand can consume directly.
func (a *App) ExportProofBundle(recordID, outPath string) error {
	if outPath == "" {
		return errors.New("output path required")
	}
	c, err := a.serverClient()
	if err != nil {
		return err
	}
	defer c.close()
	bundle, err := c.getProof(a.ensureCtx(), recordID)
	if err != nil {
		return err
	}
	raw, err := marshalCBOR(bundle)
	if err != nil {
		return err
	}
	return a.writeAuthorizedFile(outPath, raw, 0o644)
}

// ExportGlobalProof writes the batch->STH inclusion proof needed for L4/L5
// offline verification.
func (a *App) ExportGlobalProof(recordID, outPath string) error {
	if outPath == "" {
		return errors.New("output path required")
	}
	c, err := a.serverClient()
	if err != nil {
		return err
	}
	defer c.close()
	bundle, err := c.getProof(a.ensureCtx(), recordID)
	if err != nil {
		return err
	}
	proof, err := c.getGlobalProof(a.ensureCtx(), bundle.CommittedReceipt.BatchID)
	if err != nil {
		return err
	}
	raw, err := marshalCBOR(proof)
	if err != nil {
		return err
	}
	return a.writeAuthorizedFile(outPath, raw, 0o644)
}

// ExportSingleProof writes the recommended .sproof artifact: one CBOR file
// containing the L1-L3 ProofBundle plus any currently available L4 GlobalLog
// proof and L5 STH anchor result.
func (a *App) ExportSingleProof(recordID, outPath string) error {
	if outPath == "" {
		return errors.New("output path required")
	}
	proof, err := a.buildSingleProof(recordID)
	if err != nil {
		return err
	}
	raw, err := sproof.Marshal(proof)
	if err != nil {
		return err
	}
	return a.writeAuthorizedFile(outPath, raw, 0o644)
}

func (a *App) buildSingleProof(recordID string) (model.SingleProof, error) {
	c, err := a.serverClient()
	if err != nil {
		return model.SingleProof{}, err
	}
	defer c.close()
	proof, err := c.exportSingleProof(a.ensureCtx(), recordID)
	if err != nil {
		return model.SingleProof{}, err
	}
	a.mergeExportedProofState(recordID, proof.ProofBundle, proof.GlobalProof, proof.AnchorResult)
	return proof, nil
}

func (a *App) mergeExportedProofState(recordID string, bundle model.ProofBundle, global *model.GlobalLogProof, anchor *model.STHAnchorResult) {
	st, err := a.requireStore()
	if err != nil {
		return
	}
	rec, ok := st.getRecord(recordID)
	if !ok {
		return
	}
	rec.LastError = ""
	setLocalRecordLastSyncedAt(&rec, time.Now().UTC())
	evidence := prooflevel.EvidenceFor(prooflevel.L3)
	rec.ProofLevel = prooflevel.Evaluate(evidence).String()
	rec.BatchID = bundle.CommittedReceipt.BatchID
	cr := bundle.CommittedReceipt
	rec.CommittedReceipt = &cr
	if global != nil {
		rec.GlobalProof = global
		evidence.GlobalLogProof = true
		rec.ProofLevel = prooflevel.Evaluate(evidence).String()
	}
	if anchor != nil {
		rec.AnchorResult = anchor
		rec.AnchorStatus = model.AnchorStatePublished
		rec.AnchorSink = anchor.SinkName
		rec.AnchorID = anchor.AnchorID
		evidence.STHAnchorResult = true
		rec.ProofLevel = prooflevel.Evaluate(evidence).String()
	}
	_ = st.upsertRecord(rec)
}

// UpgradeOtsAnchor re-queries every calendar in the record's locally
// stored OpenTimestamps proof and, if any calendar has folded the
// commitment into a Bitcoin block, rewrites STHAnchorResult.Proof with
// the upgraded bytes and persists the record. The returned summary is
// the same shape as `trustdb anchor upgrade --json` so the UI can
// surface per-calendar progress without re-decoding the envelope.
//
// This function intentionally mutates ONLY the client-side copy. The
// server's authoritative STHAnchorResult (returned by
// `GET /v1/anchors/sth/<tree_size>`) remains the server's responsibility;
// operators should run `trustdb anchor upgrade` on the server to keep
// the two in sync. The desktop is free to upgrade its local copy
// whenever the user asks — verification always walks through
// `root_hash` which is pinned by the sink at publish time.
func (a *App) UpgradeOtsAnchor(recordID string) (*anchor.OtsUpgradeSummary, error) {
	st, err := a.requireStore()
	if err != nil {
		return nil, err
	}
	rec, ok := st.getRecord(recordID)
	if !ok {
		return nil, fmt.Errorf("record %s not found", recordID)
	}
	if rec.AnchorResult == nil {
		return nil, errors.New("record has no anchor result yet")
	}
	if rec.AnchorResult.SinkName != anchor.OtsSinkName {
		return nil, fmt.Errorf("record sink is %q, not ots", rec.AnchorResult.SinkName)
	}
	updated, summary, err := anchor.UpgradeAnchorResult(a.ensureCtx(), *rec.AnchorResult, anchor.OtsUpgradeOptions{})
	if err != nil {
		return nil, err
	}
	if summary.Changed {
		rec.AnchorResult = &updated
		if err := st.upsertRecord(rec); err != nil {
			return nil, err
		}
	}
	return &summary, nil
}

// ExportAnchorResult mirrors ExportProofBundle for L5 artifacts.
// Emitting a separate file keeps each level independently verifiable
// (you can hand out the ProofBundle without the anchor).
func (a *App) ExportAnchorResult(recordID, outPath string) error {
	if outPath == "" {
		return errors.New("output path required")
	}
	st, err := a.requireStore()
	if err != nil {
		return err
	}
	rec, ok := st.getRecord(recordID)
	var anchor *model.STHAnchorResult
	if ok {
		anchor = rec.AnchorResult
	}
	if anchor == nil {
		proof, err := a.buildSingleProof(recordID)
		if err != nil {
			return err
		}
		anchor = proof.AnchorResult
	}
	if anchor == nil {
		return errors.New("record has no STH anchor result yet")
	}
	raw, err := marshalCBOR(*anchor)
	if err != nil {
		return err
	}
	return a.writeAuthorizedFile(outPath, raw, 0o644)
}

// GetProofBundle exposes the latest server-side bundle to the UI
// (verify page uses it so the user doesn't have to export-then-
// re-import just to view the batch details).
func (a *App) GetProofBundle(recordID string) (model.ProofBundle, error) {
	c, err := a.serverClient()
	if err != nil {
		return model.ProofBundle{}, err
	}
	defer c.close()
	return c.getProof(a.ensureCtx(), recordID)
}
