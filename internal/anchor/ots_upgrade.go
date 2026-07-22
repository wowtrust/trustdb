package anchor

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/wowtrust/trustdb/internal/anchorschedule"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/proofstore"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

const maxOtsUpgradePersistAttempts = 16

// OtsUpgradeOptions configures the OTS proof-upgrade HTTP client.
// Zero values are replaced with sensible defaults so the common
// "upgrade one batch" path needs no configuration.
type OtsUpgradeOptions struct {
	// HTTPClient lets tests inject a fake transport. nil => build a
	// fresh http.Client with the Timeout applied.
	HTTPClient *http.Client
	// Timeout bounds a single calendar GET. Defaults to 30s — OTS
	// upgrades occasionally wait on calendar-side lookups and 20s
	// has proven too tight in the field.
	Timeout time.Duration
	// UserAgent is sent on every calendar request. Empty => a
	// sensible default that identifies trustdb.
	UserAgent string
	// Clock makes ElapsedMillis deterministic in tests. nil => time.Now.
	Clock func() time.Time
}

// OtsUpgradeResult reports what happened for a single calendar GET
// during an upgrade run. Changed=true means the calendar returned a
// longer / different byte stream than the stored pending timestamp,
// which in practice indicates the commitment has been folded into a
// Bitcoin block and the upgraded proof is now self-verifying
// offline. Changed=false + Error=="" means the calendar is still
// returning the original pending commitment (not upgraded yet).
type OtsUpgradeResult struct {
	URL           string `json:"url"`
	Changed       bool   `json:"changed"`
	StatusCode    int    `json:"status_code,omitempty"`
	OldLength     int    `json:"old_length,omitempty"`
	NewLength     int    `json:"new_length,omitempty"`
	Error         string `json:"error,omitempty"`
	ElapsedMillis int64  `json:"elapsed_ms,omitempty"`
}

// OtsUpgradeSummary collects the per-calendar outcomes of one upgrade
// run so callers (CLI report, UI progress panel, automation) can make
// a single decision without re-walking the proof envelope.
type OtsUpgradeSummary struct {
	TreeSize    uint64             `json:"tree_size"`
	Digest      string             `json:"digest"`
	Changed     bool               `json:"changed"`
	Calendars   []OtsUpgradeResult `json:"calendars"`
	InspectedAt int64              `json:"inspected_at_unix_nano"`
}

// UpgradeOtsProof queries each calendar that previously accepted the
// digest and, if the server now returns a different byte stream,
// replaces the stored raw_timestamp in-place. The proof envelope is
// mutated directly so the caller can re-marshal it back into
// STHAnchorResult.Proof.
//
// Calendars that failed originally (Accepted=false) are skipped — we
// never try to "promote" a previously-rejected calendar here because
// the original Publish already decided whether we have quorum, and a
// fresh submission belongs in the anchor worker, not the upgrader.
//
// The function is best-effort per calendar: a GET failure on one
// calendar does NOT abort the run; its error is recorded in the
// returned summary and other calendars are still inspected. Only a
// context cancellation or a truly invalid proof envelope (no digest
// or no tree_size) returns a non-nil error.
func UpgradeOtsProof(ctx context.Context, proof *OtsAnchorProof, opts OtsUpgradeOptions) (OtsUpgradeSummary, error) {
	if proof == nil {
		return OtsUpgradeSummary{}, trusterr.New(trusterr.CodeInvalidArgument, "ots upgrade: nil proof")
	}
	if err := ctx.Err(); err != nil {
		return OtsUpgradeSummary{}, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "ots upgrade canceled", err)
	}
	if len(proof.Digest) == 0 {
		return OtsUpgradeSummary{}, trusterr.New(trusterr.CodeInvalidArgument, "ots upgrade: proof has empty digest")
	}
	if proof.TreeSize == 0 {
		return OtsUpgradeSummary{}, trusterr.New(trusterr.CodeInvalidArgument, "ots upgrade: proof has empty tree_size")
	}

	clock := opts.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	ua := strings.TrimSpace(opts.UserAgent)
	if ua == "" {
		ua = "trustdb-anchor-ots-upgrade/1.0"
	}

	digestHex := hex.EncodeToString(proof.Digest)
	summary := OtsUpgradeSummary{
		TreeSize:    proof.TreeSize,
		Digest:      digestHex,
		Calendars:   make([]OtsUpgradeResult, 0, len(proof.Calendars)),
		InspectedAt: clock().UnixNano(),
	}

	for i := range proof.Calendars {
		cal := &proof.Calendars[i]
		if !cal.Accepted {
			summary.Calendars = append(summary.Calendars, OtsUpgradeResult{
				URL:       cal.URL,
				OldLength: len(cal.RawTimestamp),
				Error:     "skipped: calendar never accepted this digest",
			})
			continue
		}
		if cal.Upgraded {
			// Terminal state: a previous run already pulled the
			// Bitcoin-attested bytes for this calendar. Avoid the
			// HTTP round-trip — the long-running upgrader would
			// otherwise hammer every calendar forever once a batch
			// was attested.
			summary.Calendars = append(summary.Calendars, OtsUpgradeResult{
				URL:       cal.URL,
				OldLength: len(cal.RawTimestamp),
				NewLength: len(cal.RawTimestamp),
			})
			continue
		}
		res := upgradeOneCalendar(ctx, client, cal, digestHex, ua, clock)
		if res.Changed {
			summary.Changed = true
		}
		summary.Calendars = append(summary.Calendars, res)
	}
	return summary, nil
}

// upgradeOneCalendar performs the HTTP GET that drives a single
// pending-to-attested upgrade. It mutates cal.RawTimestamp in place
// when the calendar returns a different byte stream; callers rely on
// this so the caller's *OtsAnchorProof is ready to be re-marshaled
// into STHAnchorResult.Proof without a second loop.
func upgradeOneCalendar(
	ctx context.Context,
	client *http.Client,
	cal *OtsCalendarTimestamp,
	digestHex, userAgent string,
	clock func() time.Time,
) OtsUpgradeResult {
	out := OtsUpgradeResult{URL: cal.URL, OldLength: len(cal.RawTimestamp)}
	endpoint := strings.TrimRight(cal.URL, "/") + "/timestamp/" + digestHex
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		out.Error = fmt.Sprintf("build request: %v", err)
		return out
	}
	req.Header.Set("Accept", "application/vnd.opentimestamps.v1")
	req.Header.Set("User-Agent", userAgent)

	start := clock()
	resp, err := client.Do(req)
	out.ElapsedMillis = clock().Sub(start).Milliseconds()
	if err != nil {
		out.Error = err.Error()
		return out
	}
	defer resp.Body.Close()
	body, readErr := readOtsBodyLimit(resp.Body)
	out.StatusCode = resp.StatusCode
	if readErr != nil {
		out.Error = fmt.Sprintf("read body: %v", readErr)
		return out
	}
	if resp.StatusCode == http.StatusNotFound {
		// Calendar doesn't know about this digest anymore (or we're
		// pointing at a wrong calendar for this proof). Treat as a
		// neutral "no upgrade available", not a hard error — that's
		// consistent with how `ots upgrade` CLI presents it.
		out.Error = "calendar returned 404 (not indexed)"
		return out
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := strings.TrimSpace(string(body))
		if len(snippet) > 160 {
			snippet = snippet[:160] + "…"
		}
		out.Error = fmt.Sprintf("HTTP %d: %s", resp.StatusCode, snippet)
		return out
	}
	if len(body) == 0 {
		out.Error = "calendar returned empty body"
		return out
	}
	out.NewLength = len(body)
	if bytes.Equal(body, cal.RawTimestamp) {
		return out
	}
	cal.RawTimestamp = body
	// A different byte stream from the same calendar is, in
	// practice, a Bitcoin-attested upgrade: pending OTS proofs are
	// the calendar's commitment and stay byte-identical across
	// GETs until the calendar splices in a block header. We mark
	// the calendar terminal so future ticks skip it. If a calendar
	// ever rolls back (very unusual), the worst case is we miss
	// one tick — operators can manually clear the flag with a
	// fresh `trustdb anchor upgrade --tree-size` if needed.
	cal.Upgraded = true
	out.Changed = true
	return out
}

// UpgradeAnchorResult is a convenience wrapper that unwraps
// STHAnchorResult.Proof into an OtsAnchorProof, calls UpgradeOtsProof,
// and re-marshals the (possibly mutated) envelope back. It returns
// the new proof bytes and the summary; the caller is responsible for
// persisting the new STHAnchorResult (typically via
// proofstore.STHAnchorResultUpdater).
//
// ErrPermanent-style failures are NOT returned here because a
// partial upgrade (some calendars upgraded, some still pending) is
// the normal, expected state during the 1-6 hours between
// calendar-side commitment and Bitcoin-block confirmation.
func UpgradeAnchorResult(ctx context.Context, ar model.STHAnchorResult, opts OtsUpgradeOptions) (model.STHAnchorResult, OtsUpgradeSummary, error) {
	if ar.SinkName != OtsSinkName {
		return ar, OtsUpgradeSummary{}, trusterr.New(trusterr.CodeFailedPrecondition,
			"ots upgrade: anchor result is not from the ots sink: "+ar.SinkName)
	}
	var proof OtsAnchorProof
	if err := json.Unmarshal(ar.Proof, &proof); err != nil {
		return ar, OtsUpgradeSummary{}, trusterr.Wrap(trusterr.CodeDataLoss,
			"ots upgrade: decode proof envelope", err)
	}
	summary, err := UpgradeOtsProof(ctx, &proof, opts)
	if err != nil {
		return ar, summary, err
	}
	if !summary.Changed {
		return ar, summary, nil
	}
	newBytes, err := json.Marshal(&proof)
	if err != nil {
		return ar, summary, trusterr.Wrap(trusterr.CodeInternal,
			"ots upgrade: re-marshal proof envelope", err)
	}
	ar.Proof = newBytes
	return ar, summary, nil
}

// PersistOtsAnchorResultUpgrade conditionally publishes an enriched OTS proof.
// If another upgrader wins the compare-and-swap, its calendar attestations are
// merged with candidate and the combined proof is retried without regressing
// any already-upgraded calendar.
func PersistOtsAnchorResultUpgrade(
	ctx context.Context,
	reader proofstore.STHAnchorResultKeyedReader,
	updater proofstore.STHAnchorResultUpdater,
	expected model.STHAnchorResult,
	candidate model.STHAnchorResult,
) (model.STHAnchorResult, bool, error) {
	if reader == nil || updater == nil {
		return model.STHAnchorResult{}, false, trusterr.New(trusterr.CodeInvalidArgument, "ots upgrade: result reader and updater are required")
	}
	if !anchorschedule.SameResultBinding(expected, candidate) {
		return model.STHAnchorResult{}, false, trusterr.New(trusterr.CodeDataLoss, "ots upgrade: candidate changes immutable anchor binding")
	}
	if bytes.Equal(expected.Proof, candidate.Proof) {
		return expected, false, nil
	}

	for attempt := 0; attempt < maxOtsUpgradePersistAttempts; attempt++ {
		if err := updater.UpdateSTHAnchorResult(ctx, expected, candidate); err == nil {
			return candidate, true, nil
		} else if trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
			return model.STHAnchorResult{}, false, err
		}

		current, found, err := reader.GetSTHAnchorResultForKey(ctx, anchorschedule.ResultKey(expected))
		if err != nil {
			return model.STHAnchorResult{}, false, err
		}
		if !found {
			return model.STHAnchorResult{}, false, trusterr.New(trusterr.CodeNotFound, "ots upgrade: anchor result disappeared during concurrent update")
		}
		merged, changed, err := mergeOtsAnchorResultUpgrade(current, candidate)
		if err != nil {
			return model.STHAnchorResult{}, false, err
		}
		if !changed {
			return current, false, nil
		}
		expected = current
		candidate = merged
	}
	return model.STHAnchorResult{}, false, trusterr.New(trusterr.CodeFailedPrecondition, "ots upgrade: concurrent result updates did not converge")
}

func mergeOtsAnchorResultUpgrade(current, candidate model.STHAnchorResult) (model.STHAnchorResult, bool, error) {
	if !anchorschedule.SameResultBinding(current, candidate) || current.SinkName != OtsSinkName {
		return model.STHAnchorResult{}, false, trusterr.New(trusterr.CodeDataLoss, "ots upgrade: concurrent result changes immutable binding")
	}
	var currentProof, candidateProof OtsAnchorProof
	if err := json.Unmarshal(current.Proof, &currentProof); err != nil {
		return model.STHAnchorResult{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "ots upgrade: decode current proof", err)
	}
	if err := json.Unmarshal(candidate.Proof, &candidateProof); err != nil {
		return model.STHAnchorResult{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "ots upgrade: decode candidate proof", err)
	}
	if currentProof.SchemaVersion != SchemaOtsAnchorProof ||
		candidateProof.SchemaVersion != SchemaOtsAnchorProof ||
		currentProof.TreeSize != current.TreeSize ||
		candidateProof.TreeSize != candidate.TreeSize ||
		currentProof.HashAlg != candidateProof.HashAlg ||
		currentProof.HashAlg != "sha256" ||
		!bytes.Equal(currentProof.Digest, current.RootHash) ||
		!bytes.Equal(candidateProof.Digest, candidate.RootHash) ||
		currentProof.SubmittedAtN != candidateProof.SubmittedAtN ||
		len(currentProof.Calendars) != len(candidateProof.Calendars) {
		return model.STHAnchorResult{}, false, trusterr.New(trusterr.CodeDataLoss, "ots upgrade: concurrent proof envelopes are inconsistent")
	}

	changed := false
	for i := range currentProof.Calendars {
		stored := &currentProof.Calendars[i]
		incoming := candidateProof.Calendars[i]
		if stored.URL != incoming.URL ||
			stored.Accepted != incoming.Accepted ||
			stored.StatusCode != incoming.StatusCode ||
			stored.Error != incoming.Error ||
			stored.ElapsedMillis != incoming.ElapsedMillis {
			return model.STHAnchorResult{}, false, trusterr.New(trusterr.CodeDataLoss, "ots upgrade: concurrent calendar envelopes are inconsistent")
		}
		if !incoming.Upgraded {
			continue
		}
		if !incoming.Accepted || len(incoming.RawTimestamp) == 0 {
			return model.STHAnchorResult{}, false, trusterr.New(trusterr.CodeDataLoss, "ots upgrade: invalid upgraded calendar proof")
		}
		if stored.Upgraded {
			if !bytes.Equal(stored.RawTimestamp, incoming.RawTimestamp) {
				return model.STHAnchorResult{}, false, trusterr.New(trusterr.CodeDataLoss, "ots upgrade: conflicting upgraded calendar proof")
			}
			continue
		}
		stored.RawTimestamp = bytes.Clone(incoming.RawTimestamp)
		stored.Upgraded = true
		changed = true
	}
	if !changed {
		return current, false, nil
	}
	proofBytes, err := json.Marshal(currentProof)
	if err != nil {
		return model.STHAnchorResult{}, false, trusterr.Wrap(trusterr.CodeInternal, "ots upgrade: encode merged proof", err)
	}
	current.Proof = proofBytes
	return current, true, nil
}
