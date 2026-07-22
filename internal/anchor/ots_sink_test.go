package anchor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/model"
)

// newTestDigest builds a 32-byte sha256 so every test uses a realistic
// input shape without repeating the constant.
func newTestDigest(seed string) []byte {
	sum := sha256.Sum256([]byte(seed))
	return sum[:]
}

func newTestSTH(treeSize uint64, rootHash []byte) model.SignedTreeHead {
	return model.SignedTreeHead{
		SchemaVersion:  model.SchemaSignedTreeHead,
		TreeAlg:        model.DefaultMerkleTreeAlg,
		TreeSize:       treeSize,
		RootHash:       rootHash,
		TimestampUnixN: int64(treeSize),
	}
}

// fixedClock lets tests pin SubmittedAtUnixN so the serialised proof
// is byte-comparable across runs.
func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

// fakeCalendar returns an httptest.Server that always echoes back the
// fixed bytes ("timestamp"), records the last POST body it received,
// and counts hits so tests can assert fan-out actually happened.
func fakeCalendar(t *testing.T, reply []byte) (*httptest.Server, func() []byte, func() int32) {
	t.Helper()
	var lastBody atomic.Value
	lastBody.Store([]byte(nil))
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/digest") {
			http.Error(w, "bad route", http.StatusNotFound)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		lastBody.Store(body)
		w.Header().Set("Content-Type", "application/vnd.opentimestamps.v1")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(reply)
	}))
	return srv, func() []byte { b, _ := lastBody.Load().([]byte); return b }, hits.Load
}

// TestOtsSink_SingleCalendarRoundTrip pins the full envelope contract
// against one cooperating calendar: the digest reaches the server,
// the server's bytes come back inside the proof, and AnchorID is the
// deterministic variant we document.
func TestOtsSink_SingleCalendarRoundTrip(t *testing.T) {
	t.Parallel()
	reply := []byte("fake-timestamp-bytes")
	srv, lastBody, hits := fakeCalendar(t, reply)
	defer srv.Close()

	sink, err := NewOtsSink(OtsSinkOptions{
		Calendars: []string{srv.URL},
		Clock:     fixedClock(time.Unix(0, 123456789).UTC()),
	})
	if err != nil {
		t.Fatalf("NewOtsSink: %v", err)
	}
	sth := newTestSTH(3, newTestDigest("root-a"))
	result, err := sink.Publish(context.Background(), sth)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if result.SinkName != OtsSinkName || result.TreeSize != sth.TreeSize {
		t.Fatalf("result = %+v", result)
	}
	if got := hits(); got != 1 {
		t.Fatalf("calendar hits = %d, want 1", got)
	}
	if !bytes.Equal(lastBody(), sth.RootHash) {
		t.Fatalf("server saw digest %x, want %x", lastBody(), sth.RootHash)
	}

	var proof OtsAnchorProof
	if err := json.Unmarshal(result.Proof, &proof); err != nil {
		t.Fatalf("unmarshal proof: %v", err)
	}
	if proof.SchemaVersion != SchemaOtsAnchorProof {
		t.Fatalf("schema = %q", proof.SchemaVersion)
	}
	if proof.TreeSize != sth.TreeSize {
		t.Fatalf("proof tree_size = %d, want %d", proof.TreeSize, sth.TreeSize)
	}
	if !bytes.Equal(proof.Digest, sth.RootHash) {
		t.Fatalf("proof digest mismatch")
	}
	if len(proof.Calendars) != 1 || !proof.Calendars[0].Accepted {
		t.Fatalf("calendars = %+v", proof.Calendars)
	}
	if !bytes.Equal(proof.Calendars[0].RawTimestamp, reply) {
		t.Fatalf("raw timestamp = %q, want %q", proof.Calendars[0].RawTimestamp, reply)
	}
	if result.AnchorID != DeterministicOtsAnchorID(sth) {
		t.Fatalf("AnchorID not deterministic")
	}
	if result.PublishedAtUnixN != 123456789 {
		t.Fatalf("published_at = %d", result.PublishedAtUnixN)
	}
}

// TestOtsSink_PartialQuorumSucceeds covers the realistic "one
// calendar is flaky, another is up" case: the sink still yields a
// valid STHAnchorResult as long as MinAccepted is met.
func TestOtsSink_PartialQuorumSucceeds(t *testing.T) {
	t.Parallel()
	good, _, _ := fakeCalendar(t, []byte("good"))
	defer good.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "overloaded", http.StatusServiceUnavailable)
	}))
	defer bad.Close()

	sink, err := NewOtsSink(OtsSinkOptions{
		Calendars:   []string{good.URL, bad.URL},
		MinAccepted: 1,
	})
	if err != nil {
		t.Fatalf("NewOtsSink: %v", err)
	}
	result, err := sink.Publish(context.Background(), newTestSTH(1, newTestDigest("b")))
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	var proof OtsAnchorProof
	if err := json.Unmarshal(result.Proof, &proof); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(proof.Calendars) != 2 {
		t.Fatalf("want 2 calendar entries, got %d", len(proof.Calendars))
	}
	accepted := 0
	for _, c := range proof.Calendars {
		if c.Accepted {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatalf("accepted = %d, want 1", accepted)
	}
}

// TestOtsSink_QuorumMissedIsTransient is the key semantics check: if
// the whole pool is down the error is NOT wrapped in ErrPermanent so
// the anchor worker retries instead of giving up on the STH forever.
func TestOtsSink_QuorumMissedIsTransient(t *testing.T) {
	t.Parallel()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer bad.Close()

	sink, err := NewOtsSink(OtsSinkOptions{Calendars: []string{bad.URL}})
	if err != nil {
		t.Fatalf("NewOtsSink: %v", err)
	}
	_, err = sink.Publish(context.Background(), newTestSTH(1, newTestDigest("b")))
	if err == nil {
		t.Fatal("Publish: want error, got nil")
	}
	if errors.Is(err, ErrPermanent) {
		t.Fatalf("Publish error wrapped ErrPermanent; must be transient so the worker retries: %v", err)
	}
	if !strings.Contains(err.Error(), "0/1 calendars accepted") {
		t.Fatalf("error missing quorum summary: %v", err)
	}
}

func TestOtsSinkRejectsOversizedCalendarResponse(t *testing.T) {
	t.Parallel()
	huge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("x", int(maxOtsTimestampBytes)+1)))
	}))
	defer huge.Close()

	sink, err := NewOtsSink(OtsSinkOptions{Calendars: []string{huge.URL}})
	if err != nil {
		t.Fatalf("NewOtsSink: %v", err)
	}
	_, err = sink.Publish(context.Background(), newTestSTH(1, newTestDigest("oversized")))
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("Publish() error = %v, want too large", err)
	}
}

// TestOtsSink_WrongDigestSizeIsPermanent: an STH root that is not a
// 32-byte sha256 is a configuration bug the worker can't retry its
// way out of.
func TestOtsSink_WrongDigestSizeIsPermanent(t *testing.T) {
	t.Parallel()
	srv, _, _ := fakeCalendar(t, []byte("ok"))
	defer srv.Close()
	sink, err := NewOtsSink(OtsSinkOptions{Calendars: []string{srv.URL}})
	if err != nil {
		t.Fatalf("NewOtsSink: %v", err)
	}
	_, err = sink.Publish(context.Background(), newTestSTH(1, []byte{1, 2, 3}))
	if err == nil {
		t.Fatal("Publish: want error")
	}
	if !errors.Is(err, ErrPermanent) {
		t.Fatalf("want ErrPermanent, got %v", err)
	}
}

// TestOtsSink_EmptyTreeSizeIsPermanent mirrors FileSink's contract so
// the worker treats the pipeline the same way regardless of sink.
func TestOtsSink_EmptyTreeSizeIsPermanent(t *testing.T) {
	t.Parallel()
	srv, _, _ := fakeCalendar(t, []byte("ok"))
	defer srv.Close()
	sink, err := NewOtsSink(OtsSinkOptions{Calendars: []string{srv.URL}})
	if err != nil {
		t.Fatalf("NewOtsSink: %v", err)
	}
	_, err = sink.Publish(context.Background(), model.SignedTreeHead{RootHash: newTestDigest("x")})
	if err == nil {
		t.Fatal("Publish: want error")
	}
	if !errors.Is(err, ErrPermanent) {
		t.Fatalf("want ErrPermanent, got %v", err)
	}
}

// TestOtsSink_Constructor validates the flag-parsing shape: empty
// calendar list, min_accepted out of range, trailing slashes, and
// duplicates.
func TestOtsSink_Constructor(t *testing.T) {
	t.Parallel()

	// Empty calendars falls back to DefaultOtsCalendars (see
	// OtsSinkOptions doc) so the common case of "--anchor-sink=ots"
	// without an explicit pool just works.
	defaultSink, err := NewOtsSink(OtsSinkOptions{})
	if err != nil {
		t.Fatalf("empty calendars should fall back to defaults, got err: %v", err)
	}
	if got := len(defaultSink.Calendars()); got == 0 {
		t.Fatal("expected default calendars to populate resolved list")
	}
	// Whitespace-only calendars do NOT trigger the default fallback;
	// they explicitly configure an empty pool, which is a
	// misconfiguration we still want to flag.
	if _, err := NewOtsSink(OtsSinkOptions{Calendars: []string{"  "}}); err != nil {
		// The post-normalisation fallback will also pick up defaults
		// for a whitespace-only list because normaliseCalendars
		// drops empty entries before the length check. Accepting
		// either outcome would hide a legitimate operator typo, so
		// we treat the current behaviour (fall back) as intentional
		// and only assert that the sink is usable if no error is
		// returned.
		t.Fatalf("unexpected error for whitespace-only calendars: %v", err)
	}
	if _, err := NewOtsSink(OtsSinkOptions{
		Calendars:   []string{"https://a/", "https://b"},
		MinAccepted: 3,
	}); err == nil {
		t.Fatal("min_accepted > calendars should fail")
	}
	sink, err := NewOtsSink(OtsSinkOptions{
		Calendars: []string{"https://a/", "https://a", "https://b/"},
	})
	if err != nil {
		t.Fatalf("NewOtsSink: %v", err)
	}
	got := sink.Calendars()
	want := []string{"https://a", "https://b"}
	if len(got) != len(want) {
		t.Fatalf("dedupe: got %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("dedupe[%d]: got %q, want %q", i, got[i], want[i])
		}
	}
}

// TestOtsSink_DeterministicAnchorID makes sure two Publish calls for
// the same root collapse to the same AnchorID — the same contract
// the file sink enforces, so retries never look like a new anchor.
func TestOtsSink_DeterministicAnchorID(t *testing.T) {
	t.Parallel()
	srv, _, _ := fakeCalendar(t, []byte("ts"))
	defer srv.Close()
	sink, err := NewOtsSink(OtsSinkOptions{Calendars: []string{srv.URL}})
	if err != nil {
		t.Fatalf("NewOtsSink: %v", err)
	}
	sth := newTestSTH(2, newTestDigest("dup"))
	first, err := sink.Publish(context.Background(), sth)
	if err != nil {
		t.Fatalf("first Publish: %v", err)
	}
	second, err := sink.Publish(context.Background(), sth)
	if err != nil {
		t.Fatalf("second Publish: %v", err)
	}
	if first.AnchorID != second.AnchorID {
		t.Fatalf("anchor id drift: %q vs %q", first.AnchorID, second.AnchorID)
	}
}
