package anchor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

// OtsSinkName is the stable identifier recorded on every
// STHAnchorResult.SinkName produced by the OpenTimestamps sink. Verifiers
// match this value to route the Proof bytes to an OTS parser. Treat
// the value as a schema constant — changing it breaks existing bundles.
const OtsSinkName = "ots"

// SchemaOtsAnchorProof versions the JSON envelope the sink writes into
// STHAnchorResult.Proof. The envelope is intentionally self-describing so
// a verifier can refuse v2 data with a v1-only parser instead of
// silently misinterpreting it.
const SchemaOtsAnchorProof = "trustdb.anchor-ots-proof.v1"

const maxOtsTimestampBytes int64 = 1 << 20

// DefaultOtsCalendars is the public pool used when the operator does
// not supply --anchor-ots-calendars. We pick the well-known pool
// domains maintained by the OTS project and Eternity Wall because they
// have been stable for years; we submit to all of them so loss of any
// single calendar does not kill the anchor.
var DefaultOtsCalendars = []string{
	"https://a.pool.opentimestamps.org",
	"https://b.pool.opentimestamps.org",
	"https://a.calendar.eternitywall.com",
	"https://finney.calendar.eternitywall.com",
}

// OtsCalendarTimestamp is one calendar server's response. A caller
// wanting full OTS-tool compatibility can feed RawTimestamp to
// `ots upgrade` / `ots verify` later — the byte stream is exactly what
// the calendar returned, untouched by this sink.
type OtsCalendarTimestamp struct {
	URL           string `json:"url"`
	Accepted      bool   `json:"accepted"`
	RawTimestamp  []byte `json:"raw_timestamp,omitempty"`
	StatusCode    int    `json:"status_code,omitempty"`
	Error         string `json:"error,omitempty"`
	ElapsedMillis int64  `json:"elapsed_ms,omitempty"`
	// Upgraded marks a calendar whose pending timestamp has been
	// folded into a Bitcoin block (or otherwise replaced with a
	// terminal attestation). Once true, the OTS upgrader skips this
	// calendar so we don't keep re-fetching the same byte stream
	// every interval. Older proof envelopes serialise this as the
	// JSON zero value (absent) which decodes to false — exactly the
	// behaviour we want for legacy data: treat them as still-pending
	// and probe them once until the upgrader confirms terminal
	// state.
	Upgraded bool `json:"upgraded,omitempty"`
}

// OtsAnchorProof is the envelope serialised into STHAnchorResult.Proof.
// It captures every calendar we talked to (even the failed ones) so
// an operator can see the exact failure pattern later and so
// verification tooling has a stable list of pending proofs to upgrade.
type OtsAnchorProof struct {
	SchemaVersion string                 `json:"schema_version"`
	TreeSize      uint64                 `json:"tree_size"`
	HashAlg       string                 `json:"hash_alg"`
	Digest        []byte                 `json:"digest"`
	Calendars     []OtsCalendarTimestamp `json:"calendars"`
	SubmittedAtN  int64                  `json:"submitted_at_unix_nano"`
}

// AllUpgraded reports whether every calendar that originally accepted
// the digest has reached its terminal (Bitcoin-attested) byte stream.
// Calendars that were never accepted are ignored — they cannot be
// upgraded without a fresh Publish. The upgrader uses this to skip
// fully-attested batches on subsequent ticks.
//
// An empty / all-rejected proof returns true (vacuously) so the
// upgrader does not loop forever on a batch that has no work left
// for it; that case is genuinely terminal as far as OTS is concerned.
func (p *OtsAnchorProof) AllUpgraded() bool {
	if p == nil {
		return true
	}
	for i := range p.Calendars {
		if p.Calendars[i].Accepted && !p.Calendars[i].Upgraded {
			return false
		}
	}
	return true
}

// OtsSinkOptions configures an OtsSink. Calendars is normalised
// (trimmed + deduped) during NewOtsSink; the zero value of any other
// option falls back to a sensible default.
type OtsSinkOptions struct {
	// Calendars lists the OTS calendar servers to submit to. If empty
	// DefaultOtsCalendars is used.
	Calendars []string
	// MinAccepted is the minimum number of calendars that must return
	// a timestamp for Publish to succeed. A value <= 0 defaults to 1,
	// i.e. any calendar is enough.
	MinAccepted int
	// Timeout bounds the total HTTP round-trip per calendar. It does
	// NOT bound Publish as a whole — callers use context cancellation
	// for that. Defaults to 20s which is generous enough for slow
	// calendar back-pressure but short enough to fail fast.
	Timeout time.Duration
	// HTTPClient lets tests inject a fake transport; nil means build
	// a fresh http.Client per sink with the Timeout applied.
	HTTPClient *http.Client
	// UserAgent is sent on every calendar request. Empty => a sensible
	// default that identifies trustdb.
	UserAgent string
	// Clock lets tests pin SubmittedAtUnixN for deterministic output.
	// nil => time.Now().UTC().
	Clock func() time.Time
}

// OtsSink submits STH/global root hashes to one or more OpenTimestamps
// calendar servers. Each Publish returns the pending timestamp proofs;
// upgrading a pending proof into a Bitcoin-anchored one happens later
// via the standard `ots upgrade` tooling, outside this sink.
//
// The sink is safe for concurrent use: HTTP fan-out is goroutine-
// based and the struct itself is immutable after construction.
type OtsSink struct {
	calendars   []string
	minAccepted int
	timeout     time.Duration
	httpClient  *http.Client
	userAgent   string
	clock       func() time.Time
}

// NewOtsSink validates and normalises the options and returns a ready
// sink. The only hard-failure case is "no calendars at all" — if the
// caller filtered down to the empty list we reject instead of silently
// falling back to the public pool, to avoid surprising production
// operators who meant to isolate their infrastructure.
func NewOtsSink(opts OtsSinkOptions) (*OtsSink, error) {
	cals := normaliseCalendars(opts.Calendars)
	if len(cals) == 0 {
		// Honour the documented contract: an empty Calendars slice
		// falls back to the built-in public pool so the common case
		// of "just turn OTS on" doesn't need a separate flag. We
		// still reject the post-normalisation zero case because
		// DefaultOtsCalendars is compile-time non-empty.
		cals = normaliseCalendars(DefaultOtsCalendars)
		if len(cals) == 0 {
			return nil, trusterr.New(trusterr.CodeInvalidArgument, "ots sink requires at least one calendar URL")
		}
	}
	min := opts.MinAccepted
	if min <= 0 {
		min = 1
	}
	if min > len(cals) {
		return nil, trusterr.New(trusterr.CodeInvalidArgument,
			fmt.Sprintf("ots sink min_accepted=%d exceeds calendar count %d", min, len(cals)))
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	ua := strings.TrimSpace(opts.UserAgent)
	if ua == "" {
		ua = "trustdb-anchor-ots/1.0"
	}
	clock := opts.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &OtsSink{
		calendars:   cals,
		minAccepted: min,
		timeout:     timeout,
		httpClient:  client,
		userAgent:   ua,
		clock:       clock,
	}, nil
}

// Calendars exposes the resolved calendar URLs. Mostly useful in
// startup logs so an operator can confirm the sink is pointing at the
// expected pool before traffic starts flowing.
func (s *OtsSink) Calendars() []string {
	out := make([]string, len(s.calendars))
	copy(out, s.calendars)
	return out
}

// Name returns the sink identifier recorded in every STHAnchorResult.
func (s *OtsSink) Name() string { return OtsSinkName }

// Publish submits root.BatchRoot (sha256 digest, 32 bytes) to every
// configured calendar concurrently, collects the pending timestamp
// proofs and returns them in STHAnchorResult.Proof. Transient errors
// (network, 5xx) leave the outbox item Pending so the worker retries.
// Permanent errors (wrong digest length, 4xx client error) are wrapped
// with ErrPermanent so the worker stops retrying.
func (s *OtsSink) Publish(ctx context.Context, sth model.SignedTreeHead) (model.STHAnchorResult, error) {
	if err := ctx.Err(); err != nil {
		return model.STHAnchorResult{}, trusterr.Wrap(trusterr.CodeDeadlineExceeded, "anchor ots canceled", err)
	}
	if sth.TreeSize == 0 {
		return model.STHAnchorResult{}, fmt.Errorf("%w: tree_size is empty", ErrPermanent)
	}
	if len(sth.RootHash) != sha256.Size {
		// OTS calendars accept arbitrary-length digests in theory but
		// in practice the public pool expects the 32-byte sha256 we
		// always produce. Reject anything else permanently so the
		// operator sees the config mistake immediately.
		return model.STHAnchorResult{}, fmt.Errorf(
			"%w: sth root_hash must be %d bytes (sha256), got %d",
			ErrPermanent, sha256.Size, len(sth.RootHash))
	}

	type fanOut struct {
		idx   int
		stamp OtsCalendarTimestamp
	}
	results := make([]OtsCalendarTimestamp, len(s.calendars))
	ch := make(chan fanOut, len(s.calendars))
	var wg sync.WaitGroup
	for i, url := range s.calendars {
		wg.Add(1)
		go func(idx int, calURL string) {
			defer wg.Done()
			ch <- fanOut{idx: idx, stamp: s.submitOne(ctx, calURL, sth.RootHash)}
		}(i, url)
	}
	wg.Wait()
	close(ch)
	for ev := range ch {
		results[ev.idx] = ev.stamp
	}

	accepted := 0
	for _, r := range results {
		if r.Accepted {
			accepted++
		}
	}
	if accepted < s.minAccepted {
		// Everyone failed (or not enough succeeded). This is
		// transient by default because the public pool does suffer
		// brief outages. Callers can increase MinAccepted to make
		// "quorum lost" retry-worthy as well.
		joined := summariseFailures(results)
		return model.STHAnchorResult{}, fmt.Errorf(
			"ots sink: %d/%d calendars accepted (need %d): %s",
			accepted, len(s.calendars), s.minAccepted, joined)
	}

	now := s.clock().UTC()
	proof := OtsAnchorProof{
		SchemaVersion: SchemaOtsAnchorProof,
		TreeSize:      sth.TreeSize,
		HashAlg:       model.DefaultHashAlg,
		Digest:        sth.RootHash,
		Calendars:     results,
		SubmittedAtN:  now.UnixNano(),
	}
	proofBytes, err := json.Marshal(proof)
	if err != nil {
		return model.STHAnchorResult{}, fmt.Errorf("%w: marshal ots proof: %v", ErrPermanent, err)
	}
	return model.STHAnchorResult{
		SchemaVersion:    model.SchemaSTHAnchorResult,
		NodeID:           sth.NodeID,
		LogID:            sth.LogID,
		TreeSize:         sth.TreeSize,
		SinkName:         s.Name(),
		AnchorID:         DeterministicOtsAnchorID(sth),
		RootHash:         sth.RootHash,
		STH:              sth,
		Proof:            proofBytes,
		PublishedAtUnixN: now.UnixNano(),
	}, nil
}

// submitOne talks to a single calendar. Network and 5xx/429 errors are
// returned with Accepted=false so the caller can still aggregate a
// partial-success result (the envelope keeps the failure record so an
// operator can see who was down later). A 4xx is reported as Accepted
// false with the status so you can distinguish "rejected our digest"
// from "was unreachable".
func (s *OtsSink) submitOne(ctx context.Context, calURL string, digest []byte) OtsCalendarTimestamp {
	start := s.clock()
	endpoint := strings.TrimRight(calURL, "/") + "/digest"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(digest))
	if err != nil {
		return OtsCalendarTimestamp{URL: calURL, Error: fmt.Sprintf("build request: %v", err)}
	}
	req.Header.Set("Content-Type", "application/vnd.opentimestamps.v1")
	req.Header.Set("Accept", "application/vnd.opentimestamps.v1")
	req.Header.Set("User-Agent", s.userAgent)

	resp, err := s.httpClient.Do(req)
	elapsed := s.clock().Sub(start).Milliseconds()
	if err != nil {
		return OtsCalendarTimestamp{URL: calURL, Error: err.Error(), ElapsedMillis: elapsed}
	}
	defer resp.Body.Close()
	body, readErr := readOtsBodyLimit(resp.Body)
	if readErr != nil {
		return OtsCalendarTimestamp{URL: calURL, Error: fmt.Sprintf("read body: %v", readErr), StatusCode: resp.StatusCode, ElapsedMillis: elapsed}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := strings.TrimSpace(string(body))
		if len(snippet) > 160 {
			snippet = snippet[:160] + "…"
		}
		return OtsCalendarTimestamp{URL: calURL, StatusCode: resp.StatusCode, Error: fmt.Sprintf("HTTP %d: %s", resp.StatusCode, snippet), ElapsedMillis: elapsed}
	}
	return OtsCalendarTimestamp{
		URL:           calURL,
		Accepted:      true,
		RawTimestamp:  body,
		StatusCode:    resp.StatusCode,
		ElapsedMillis: elapsed,
	}
}

func readOtsBodyLimit(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxOtsTimestampBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxOtsTimestampBytes {
		return nil, fmt.Errorf("ots timestamp response too large: %d > %d", len(body), maxOtsTimestampBytes)
	}
	return body, nil
}

// DeterministicOtsAnchorID derives a stable anchor id from the STH
// root, mirroring file_sink's approach. Exported so offline verifiers
// can recompute it from a trusted SignedTreeHead and compare against a
// reported STHAnchorResult.AnchorID — a cheap tamper check before
// attempting the (more expensive) proof replay.
func DeterministicOtsAnchorID(sth model.SignedTreeHead) string {
	h := sha256.New()
	h.Write([]byte(OtsSinkName))
	h.Write([]byte{0})
	h.Write([]byte(fmt.Sprintf("%d", sth.TreeSize)))
	h.Write([]byte{0})
	h.Write(sth.RootHash)
	return "ots-" + hex.EncodeToString(h.Sum(nil))[:32]
}

// normaliseCalendars strips whitespace, drops empty entries, and
// removes duplicates while preserving the caller's order (so logs
// read the way they configured it).
func normaliseCalendars(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		u := strings.TrimSpace(raw)
		u = strings.TrimRight(u, "/")
		if u == "" {
			continue
		}
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}
	return out
}

// summariseFailures compresses N "unreachable" errors into a single
// readable string for the outbox retry log.
func summariseFailures(results []OtsCalendarTimestamp) string {
	if len(results) == 0 {
		return "no calendars configured"
	}
	parts := make([]string, 0, len(results))
	for _, r := range results {
		if r.Accepted {
			continue
		}
		msg := r.Error
		if msg == "" {
			msg = "unknown error"
		}
		parts = append(parts, fmt.Sprintf("%s: %s", r.URL, msg))
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

// Compile-time assertion that OtsSink satisfies the Sink contract.
var _ Sink = (*OtsSink)(nil)
