package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ryan-wong-coder/trustdb/internal/anchor"
	"github.com/ryan-wong-coder/trustdb/internal/proofstore"
	"github.com/ryan-wong-coder/trustdb/internal/wal"
)

// newTestRuntime returns a runtimeConfig minimal enough to drive the
// build helpers without touching the filesystem-rooted PersistentPreRunE
// path. The logger discards everything because none of these tests
// inspect log output.
func newTestRuntime(t *testing.T) *runtimeConfig {
	t.Helper()
	rt := &runtimeConfig{}
	return rt
}

// TestNewOtsSinkFromParams_AcceptsDefaults ensures that an empty
// otsSinkParams yields a usable sink (falls back to the public
// calendar pool and library defaults) — this is the config path
// exercised when the operator simply sets --anchor-sink=ots.
func TestNewOtsSinkFromParams_AcceptsDefaults(t *testing.T) {
	t.Parallel()

	sink, err := newOtsSinkFromParams(otsSinkParams{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sink == nil {
		t.Fatal("expected non-nil sink")
	}
	if got := sink.Name(); got != anchor.OtsSinkName {
		t.Fatalf("unexpected sink name %q, want %q", got, anchor.OtsSinkName)
	}
	if cals := sink.Calendars(); len(cals) == 0 {
		t.Fatalf("expected default calendars to be populated, got 0")
	}
}

// TestNewOtsSinkFromParams_RejectsNegativeMinAccepted guards the
// user-facing flag; accepting a negative value would silently degrade
// the quorum policy to "any single calendar suffices".
func TestNewOtsSinkFromParams_RejectsNegativeMinAccepted(t *testing.T) {
	t.Parallel()

	_, err := newOtsSinkFromParams(otsSinkParams{MinAccepted: -1})
	if err == nil {
		t.Fatal("expected error for negative MinAccepted")
	}
	if !strings.Contains(err.Error(), "anchor-ots-min-accepted") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestNewOtsSinkFromParams_RejectsBadTimeout ensures the shared
// time.ParseDuration error surface propagates through a wrapped
// trusterr so startup fails fast instead of silently using 0s.
func TestNewOtsSinkFromParams_RejectsBadTimeout(t *testing.T) {
	t.Parallel()

	_, err := newOtsSinkFromParams(otsSinkParams{TimeoutText: "not-a-duration"})
	if err == nil {
		t.Fatal("expected error for invalid timeout text")
	}
	if !strings.Contains(err.Error(), "anchor-ots-timeout") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestServeDurationFlagBounds(t *testing.T) {
	t.Parallel()

	if got, err := parseNonNegativeDurationFlag("read-header-timeout", "0s"); err != nil || got != 0 {
		t.Fatalf("parse zero non-negative duration = %v err=%v, want 0 nil", got, err)
	}
	if _, err := parseNonNegativeDurationFlag("idle-timeout", "-1s"); err == nil || !strings.Contains(err.Error(), "--idle-timeout") {
		t.Fatalf("negative idle-timeout error = %v, want flag error", err)
	}
	if got, err := parsePositiveDurationFlag("batch-max-delay", "5ms"); err != nil || got != 5*time.Millisecond {
		t.Fatalf("parse positive duration = %v err=%v, want 5ms nil", got, err)
	}
	if _, err := parsePositiveDurationFlag("batch-max-delay", "0s"); err == nil || !strings.Contains(err.Error(), "--batch-max-delay") {
		t.Fatalf("zero batch-max-delay error = %v, want flag error", err)
	}
	if got, err := parseWALGroupCommitInterval(wal.FsyncGroup, "10ms"); err != nil || got != 10*time.Millisecond {
		t.Fatalf("parse WAL group interval = %v err=%v, want 10ms nil", got, err)
	}
	for _, value := range []string{"0s", "-1ms"} {
		if _, err := parseWALGroupCommitInterval(wal.FsyncGroup, value); err == nil || !strings.Contains(err.Error(), "--wal-group-commit-interval") {
			t.Fatalf("WAL group interval %q error = %v, want flag error", value, err)
		}
	}
	for _, mode := range []string{wal.FsyncStrict, wal.FsyncBatch} {
		if got, err := parseWALGroupCommitInterval(mode, "0s"); err != nil || got != 10*time.Millisecond {
			t.Fatalf("inactive WAL group interval for %s = %v err=%v, want normalized 10ms nil", mode, got, err)
		}
	}
}

// TestNewOtsSinkFromParams_PropagatesOptions verifies non-default
// options flow into the sink, keeping the flag-to-sink plumbing
// honest if OtsSinkOptions is extended later.
func TestNewOtsSinkFromParams_PropagatesOptions(t *testing.T) {
	t.Parallel()

	sink, err := newOtsSinkFromParams(otsSinkParams{
		Calendars:   []string{"https://example.test/"},
		MinAccepted: 1,
		TimeoutText: "5s",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cals := sink.Calendars()
	if len(cals) != 1 || cals[0] != "https://example.test" {
		t.Fatalf("unexpected calendars %v", cals)
	}
	// Timeout / MinAccepted aren't exposed on OtsSink, so we settle
	// for asserting the constructor accepted them without error. A
	// regression in wiring would have to round-trip through the
	// integration tests in internal/anchor.
	_ = time.Second
}

// TestBuildOtsUpgrader_NilForNonOtsSink documents the central
// conditional in the wire-up: the upgrader is only relevant when
// the configured anchor sink is OpenTimestamps. Returning nil keeps
// serve_cmd's start path simple (`if u != nil { u.Start() }`).
func TestBuildOtsUpgrader_NilForNonOtsSink(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	store := &proofstore.LocalStore{Root: filepath.Join(tmp, "ps")}
	defer store.Close()
	rt := newTestRuntime(t)

	for _, kind := range []string{"", "off", "file", "noop", "FILE"} {
		u, err := buildOtsUpgrader(rt, store, nil, kind, otsUpgraderParams{Enabled: true})
		if err != nil {
			t.Fatalf("kind=%q unexpected err: %v", kind, err)
		}
		if u != nil {
			t.Fatalf("kind=%q expected nil upgrader, got %#v", kind, u)
		}
	}
}

// TestBuildOtsUpgrader_DisabledByFlag covers the explicit opt-out
// path: even when the sink is ots, --anchor-ots-upgrade-enabled=false
// must produce a nil upgrader so serve never starts the worker.
func TestBuildOtsUpgrader_DisabledByFlag(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	store := &proofstore.LocalStore{Root: filepath.Join(tmp, "ps")}
	defer store.Close()

	u, err := buildOtsUpgrader(newTestRuntime(t), store, nil, "ots", otsUpgraderParams{Enabled: false})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if u != nil {
		t.Fatal("expected nil upgrader when disabled")
	}
}

// TestBuildOtsUpgrader_BuildsWhenEnabled exercises the success path:
// sink=ots + enabled => non-nil upgrader, defaults applied.
func TestBuildOtsUpgrader_BuildsWhenEnabled(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	store := &proofstore.LocalStore{Root: filepath.Join(tmp, "ps")}
	defer store.Close()

	u, err := buildOtsUpgrader(newTestRuntime(t), store, nil, "OPENTIMESTAMPS", otsUpgraderParams{
		Enabled:      true,
		IntervalText: "30m",
		BatchSize:    32,
		TimeoutText:  "15s",
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if u == nil {
		t.Fatal("expected non-nil upgrader")
	}
	// Lifecycle smoke: Start/Stop must not panic with the resulting
	// configuration even though we never actually fire a tick.
	u.Stop()
}

// TestBuildOtsUpgrader_RejectsBadDuration ensures invalid duration
// strings fail startup fast instead of silently using zero.
func TestBuildOtsUpgrader_RejectsBadDuration(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	store := &proofstore.LocalStore{Root: filepath.Join(tmp, "ps")}
	defer store.Close()

	cases := []struct {
		name   string
		params otsUpgraderParams
		want   string
	}{
		{"interval-bad", otsUpgraderParams{Enabled: true, IntervalText: "weekly"}, "anchor-ots-upgrade-interval"},
		{"interval-zero", otsUpgraderParams{Enabled: true, IntervalText: "0s"}, "anchor-ots-upgrade-interval"},
		{"timeout-bad", otsUpgraderParams{Enabled: true, TimeoutText: "🍩"}, "anchor-ots-upgrade-timeout"},
		{"timeout-zero", otsUpgraderParams{Enabled: true, TimeoutText: "0s"}, "anchor-ots-upgrade-timeout"},
		{"batch-negative", otsUpgraderParams{Enabled: true, BatchSize: -1}, "anchor-ots-upgrade-batch-size"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := buildOtsUpgrader(newTestRuntime(t), store, nil, "ots", tc.params)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q must mention %q", err.Error(), tc.want)
			}
		})
	}
}
