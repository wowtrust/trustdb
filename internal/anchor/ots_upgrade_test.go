package anchor

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

// newUpgradeCalendar returns a test server that serves
// /timestamp/<digest> with the configured reply based on the request
// digest. The `responses` map is keyed by the hex-encoded digest so
// tests can make different calendars return different payloads.
func newUpgradeCalendar(t *testing.T, name string, responses map[string]struct {
	Status int
	Body   []byte
}) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/timestamp/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		digestHex := strings.TrimPrefix(r.URL.Path, "/timestamp/")
		resp, ok := responses[digestHex]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if resp.Status == 0 {
			resp.Status = http.StatusOK
		}
		w.WriteHeader(resp.Status)
		_, _ = w.Write(resp.Body)
	})
	return httptest.NewServer(mux)
}

func TestUpgradeOtsProof_ReplacesUpgradedBytes(t *testing.T) {
	t.Parallel()

	digest := newTestDigest("upg-replace")
	digestHex := hex.EncodeToString(digest)
	oldPending := []byte("pending-ts-v1")
	upgraded := []byte("attested-ts-v2-with-block-header-payload")

	cal := newUpgradeCalendar(t, "c1", map[string]struct {
		Status int
		Body   []byte
	}{
		digestHex: {Status: http.StatusOK, Body: upgraded},
	})
	defer cal.Close()

	proof := &OtsAnchorProof{
		SchemaVersion: SchemaOtsAnchorProof,
		TreeSize:      1,
		HashAlg:       "sha256",
		Digest:        digest,
		Calendars: []OtsCalendarTimestamp{
			{URL: cal.URL, Accepted: true, RawTimestamp: oldPending},
		},
		SubmittedAtN: time.Now().UnixNano(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	summary, err := UpgradeOtsProof(ctx, proof, OtsUpgradeOptions{HTTPClient: cal.Client(), Clock: fixedClock(time.Unix(0, 0).UTC())})
	if err != nil {
		t.Fatalf("UpgradeOtsProof: %v", err)
	}
	if !summary.Changed {
		t.Fatal("expected summary.Changed=true")
	}
	if got := len(summary.Calendars); got != 1 {
		t.Fatalf("unexpected calendar count: %d", got)
	}
	cs := summary.Calendars[0]
	if !cs.Changed {
		t.Fatal("expected per-calendar Changed=true")
	}
	if cs.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", cs.StatusCode)
	}
	if cs.OldLength != len(oldPending) || cs.NewLength != len(upgraded) {
		t.Fatalf("unexpected lengths old=%d new=%d", cs.OldLength, cs.NewLength)
	}
	if got := string(proof.Calendars[0].RawTimestamp); got != string(upgraded) {
		t.Fatalf("raw_timestamp not upgraded, got %q", got)
	}
}

func TestUpgradeOtsProof_UnchangedWhenServerReturnsSame(t *testing.T) {
	t.Parallel()

	digest := newTestDigest(t.Name())
	digestHex := hex.EncodeToString(digest)
	pending := []byte("still-pending")

	cal := newUpgradeCalendar(t, "c1", map[string]struct {
		Status int
		Body   []byte
	}{
		digestHex: {Status: http.StatusOK, Body: pending},
	})
	defer cal.Close()

	proof := &OtsAnchorProof{
		SchemaVersion: SchemaOtsAnchorProof,
		TreeSize:      2,
		HashAlg:       "sha256",
		Digest:        digest,
		Calendars: []OtsCalendarTimestamp{
			{URL: cal.URL, Accepted: true, RawTimestamp: pending},
		},
	}
	summary, err := UpgradeOtsProof(context.Background(), proof, OtsUpgradeOptions{HTTPClient: cal.Client()})
	if err != nil {
		t.Fatalf("UpgradeOtsProof: %v", err)
	}
	if summary.Changed {
		t.Fatal("expected no change when bytes match")
	}
	if summary.Calendars[0].Changed {
		t.Fatal("expected per-calendar Changed=false")
	}
}

func TestUpgradeOtsProofRejectsOversizedCalendarResponse(t *testing.T) {
	t.Parallel()

	digest := newTestDigest(t.Name())
	digestHex := hex.EncodeToString(digest)
	pending := []byte("still-pending")
	cal := newUpgradeCalendar(t, "c1", map[string]struct {
		Status int
		Body   []byte
	}{
		digestHex: {Status: http.StatusOK, Body: []byte(strings.Repeat("x", int(maxOtsTimestampBytes)+1))},
	})
	defer cal.Close()

	proof := &OtsAnchorProof{
		SchemaVersion: SchemaOtsAnchorProof,
		TreeSize:      2,
		HashAlg:       "sha256",
		Digest:        digest,
		Calendars: []OtsCalendarTimestamp{
			{URL: cal.URL, Accepted: true, RawTimestamp: pending},
		},
	}
	summary, err := UpgradeOtsProof(context.Background(), proof, OtsUpgradeOptions{HTTPClient: cal.Client()})
	if err != nil {
		t.Fatalf("UpgradeOtsProof: %v", err)
	}
	if summary.Changed {
		t.Fatal("oversized response must not mark proof changed")
	}
	if c := summary.Calendars[0]; !strings.Contains(c.Error, "too large") || c.Changed {
		t.Fatalf("calendar summary = %+v, want too-large error without change", c)
	}
	if got := string(proof.Calendars[0].RawTimestamp); got != string(pending) {
		t.Fatalf("raw timestamp mutated: %q", got)
	}
}

func TestUpgradeOtsProof_Error404IsNeutral(t *testing.T) {
	t.Parallel()

	digest := newTestDigest(t.Name())
	digestHex := hex.EncodeToString(digest)

	cal := newUpgradeCalendar(t, "c1", map[string]struct {
		Status int
		Body   []byte
	}{
		digestHex: {Status: http.StatusNotFound, Body: []byte("not found")},
	})
	defer cal.Close()

	proof := &OtsAnchorProof{
		SchemaVersion: SchemaOtsAnchorProof,
		TreeSize:      3,
		HashAlg:       "sha256",
		Digest:        digest,
		Calendars: []OtsCalendarTimestamp{
			{URL: cal.URL, Accepted: true, RawTimestamp: []byte("pending")},
		},
	}
	summary, err := UpgradeOtsProof(context.Background(), proof, OtsUpgradeOptions{HTTPClient: cal.Client()})
	if err != nil {
		t.Fatalf("UpgradeOtsProof: %v", err)
	}
	if summary.Changed {
		t.Fatal("404 must not count as a change")
	}
	if c := summary.Calendars[0]; c.Changed || c.Error == "" || c.StatusCode != http.StatusNotFound {
		t.Fatalf("unexpected 404 outcome: %+v", c)
	}
	if got := string(proof.Calendars[0].RawTimestamp); got != "pending" {
		t.Fatalf("raw_timestamp should be untouched on 404, got %q", got)
	}
}

func TestUpgradeOtsProof_SkipsRejectedCalendars(t *testing.T) {
	t.Parallel()

	digest := newTestDigest(t.Name())

	proof := &OtsAnchorProof{
		SchemaVersion: SchemaOtsAnchorProof,
		TreeSize:      4,
		HashAlg:       "sha256",
		Digest:        digest,
		Calendars: []OtsCalendarTimestamp{
			{URL: "https://never-accepted.example", Accepted: false, Error: "conn refused"},
		},
	}
	summary, err := UpgradeOtsProof(context.Background(), proof, OtsUpgradeOptions{})
	if err != nil {
		t.Fatalf("UpgradeOtsProof: %v", err)
	}
	if summary.Changed {
		t.Fatal("rejected calendars cannot become upgraded")
	}
	if c := summary.Calendars[0]; !strings.Contains(c.Error, "skipped") {
		t.Fatalf("expected skip marker, got %+v", c)
	}
}

func TestUpgradeOtsProof_RejectsInvalidEnvelope(t *testing.T) {
	t.Parallel()

	if _, err := UpgradeOtsProof(context.Background(), nil, OtsUpgradeOptions{}); err == nil {
		t.Fatal("nil proof should error")
	}
	bad := &OtsAnchorProof{TreeSize: 1} // empty digest
	if _, err := UpgradeOtsProof(context.Background(), bad, OtsUpgradeOptions{}); err == nil {
		t.Fatal("empty digest should error")
	}
	noTree := &OtsAnchorProof{Digest: []byte{1, 2, 3}}
	if _, err := UpgradeOtsProof(context.Background(), noTree, OtsUpgradeOptions{}); err == nil {
		t.Fatal("empty tree_size should error")
	}
}

func TestUpgradeAnchorResult_WrapsProofBytes(t *testing.T) {
	t.Parallel()

	digest := newTestDigest(t.Name())
	digestHex := hex.EncodeToString(digest)

	cal := newUpgradeCalendar(t, "c1", map[string]struct {
		Status int
		Body   []byte
	}{
		digestHex: {Status: http.StatusOK, Body: []byte("upgraded-stream-with-bitcoin-attestation")},
	})
	defer cal.Close()

	proof := OtsAnchorProof{
		SchemaVersion: SchemaOtsAnchorProof,
		TreeSize:      5,
		HashAlg:       "sha256",
		Digest:        digest,
		Calendars: []OtsCalendarTimestamp{
			{URL: cal.URL, Accepted: true, RawTimestamp: []byte("pending")},
		},
	}
	proofBytes, err := json.Marshal(proof)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	sth := newTestSTH(proof.TreeSize, digest)
	ar := model.STHAnchorResult{
		SchemaVersion:    model.SchemaSTHAnchorResult,
		EvidenceStage:    model.AnchorEvidenceStageOfflineVerified,
		TreeSize:         proof.TreeSize,
		SinkName:         OtsSinkName,
		AnchorID:         "ots-test",
		RootHash:         digest,
		STH:              sth,
		Proof:            proofBytes,
		PublishedAtUnixN: time.Now().UnixNano(),
	}

	updated, summary, err := UpgradeAnchorResult(context.Background(), ar, OtsUpgradeOptions{HTTPClient: cal.Client()})
	if err != nil {
		t.Fatalf("UpgradeAnchorResult: %v", err)
	}
	if !summary.Changed {
		t.Fatal("expected Changed=true")
	}
	var roundtrip OtsAnchorProof
	if err := json.Unmarshal(updated.Proof, &roundtrip); err != nil {
		t.Fatalf("decode updated proof: %v", err)
	}
	if got := string(roundtrip.Calendars[0].RawTimestamp); got != "upgraded-stream-with-bitcoin-attestation" {
		t.Fatalf("raw_timestamp not persisted in new bytes, got %q", got)
	}
	// Original input bytes must be untouched so the caller can diff.
	var original OtsAnchorProof
	if err := json.Unmarshal(proofBytes, &original); err != nil {
		t.Fatalf("original still decodable: %v", err)
	}
	if got := string(original.Calendars[0].RawTimestamp); got != "pending" {
		t.Fatalf("original proof was mutated, got %q", got)
	}
}

// TestUpgradeOtsProof_SkipsAlreadyUpgraded guards the worker contract:
// once a calendar is marked Upgraded=true the upgrader must NOT
// re-issue a GET, even if the test server is still up. This is what
// keeps the periodic background upgrader from DDoS-ing public
// calendars after every batch reaches its terminal Bitcoin block.
func TestUpgradeOtsProof_SkipsAlreadyUpgraded(t *testing.T) {
	t.Parallel()

	digest := newTestDigest(t.Name())
	digestHex := hex.EncodeToString(digest)

	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("anything"))
	}))
	defer srv.Close()

	proof := &OtsAnchorProof{
		SchemaVersion: SchemaOtsAnchorProof,
		TreeSize:      6,
		HashAlg:       "sha256",
		Digest:        digest,
		Calendars: []OtsCalendarTimestamp{
			{URL: srv.URL, Accepted: true, Upgraded: true, RawTimestamp: []byte("attested")},
		},
	}
	summary, err := UpgradeOtsProof(context.Background(), proof, OtsUpgradeOptions{HTTPClient: srv.Client()})
	if err != nil {
		t.Fatalf("UpgradeOtsProof: %v", err)
	}
	if summary.Changed {
		t.Fatal("upgraded calendar must not flip Changed")
	}
	if hits != 0 {
		t.Fatalf("server saw %d GETs, want 0 (terminal calendar should be skipped)", hits)
	}
	if got := digestHex; got == "" {
		t.Fatal("digest hex unexpectedly empty")
	}
}

// TestUpgradeOtsProof_MarksUpgradedOnChange pins down the state
// transition: after a successful byte upgrade, the corresponding
// calendar entry must carry Upgraded=true so the next tick skips it.
func TestUpgradeOtsProof_MarksUpgradedOnChange(t *testing.T) {
	t.Parallel()

	digest := newTestDigest(t.Name())
	digestHex := hex.EncodeToString(digest)
	upgraded := []byte("upgraded-with-block-header")

	cal := newUpgradeCalendar(t, "c1", map[string]struct {
		Status int
		Body   []byte
	}{
		digestHex: {Status: http.StatusOK, Body: upgraded},
	})
	defer cal.Close()

	proof := &OtsAnchorProof{
		SchemaVersion: SchemaOtsAnchorProof,
		TreeSize:      7,
		HashAlg:       "sha256",
		Digest:        digest,
		Calendars: []OtsCalendarTimestamp{
			{URL: cal.URL, Accepted: true, RawTimestamp: []byte("pending")},
		},
	}
	if proof.AllUpgraded() {
		t.Fatal("AllUpgraded must be false before upgrade")
	}
	if _, err := UpgradeOtsProof(context.Background(), proof, OtsUpgradeOptions{HTTPClient: cal.Client()}); err != nil {
		t.Fatalf("UpgradeOtsProof: %v", err)
	}
	if !proof.Calendars[0].Upgraded {
		t.Fatal("calendar not marked Upgraded after byte change")
	}
	if !proof.AllUpgraded() {
		t.Fatal("AllUpgraded should now report true")
	}
}

// TestOtsAnchorProof_AllUpgradedIgnoresRejected proves the helper
// short-circuits on rejected calendars (they cannot be upgraded
// without a fresh Publish, so they must not block AllUpgraded).
func TestOtsAnchorProof_AllUpgradedIgnoresRejected(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		p    OtsAnchorProof
		want bool
	}{
		{"empty", OtsAnchorProof{}, true},
		{"only-rejected", OtsAnchorProof{Calendars: []OtsCalendarTimestamp{{Accepted: false}}}, true},
		{"mixed-pending", OtsAnchorProof{Calendars: []OtsCalendarTimestamp{
			{Accepted: false},
			{Accepted: true, Upgraded: false},
		}}, false},
		{"mixed-attested", OtsAnchorProof{Calendars: []OtsCalendarTimestamp{
			{Accepted: false},
			{Accepted: true, Upgraded: true},
		}}, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.p.AllUpgraded(); got != tc.want {
				t.Fatalf("AllUpgraded() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestUpgradeAnchorResult_RejectsNonOtsSink(t *testing.T) {
	t.Parallel()

	ar := model.STHAnchorResult{SinkName: "file", Proof: []byte("{}")}
	_, _, err := UpgradeAnchorResult(context.Background(), ar, OtsUpgradeOptions{})
	if err == nil {
		t.Fatal("expected error for non-ots sink")
	}
	if code := trusterr.CodeOf(err); code != trusterr.CodeFailedPrecondition {
		t.Fatalf("unexpected error code: %v", code)
	}
}
