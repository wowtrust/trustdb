package anchorschedule

import (
	"bytes"
	"testing"

	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

func testKey() model.STHAnchorScheduleKey {
	return model.STHAnchorScheduleKey{NodeID: "node-1", LogID: "log-1", SinkName: "file"}
}

func testSTH(treeSize uint64, seed byte) model.SignedTreeHead {
	return model.SignedTreeHead{
		SchemaVersion:  model.SchemaSignedTreeHead,
		TreeAlg:        model.DefaultMerkleTreeAlg,
		TreeSize:       treeSize,
		RootHash:       bytes.Repeat([]byte{seed}, 32),
		TimestampUnixN: int64(treeSize),
		NodeID:         "node-1",
		LogID:          "log-1",
		Signature:      model.Signature{Alg: model.DefaultSignatureAlg, KeyID: "key-1", Signature: []byte{seed}},
	}
}

func candidate(treeSize uint64, seed byte, observed, due int64) model.STHAnchorCandidate {
	return model.STHAnchorCandidate{Key: testKey(), STH: testSTH(treeSize, seed), ObservedAtUnixN: observed, DueAtUnixN: due}
}

func TestMergeCandidatePreservesFirstDeadlineAndBoundsState(t *testing.T) {
	t.Parallel()
	schedule, changed, err := MergeCandidate(model.STHAnchorSchedule{}, false, candidate(1, 1, 100, 200), nil)
	if err != nil || !changed {
		t.Fatalf("first merge changed=%v err=%v", changed, err)
	}
	schedule, changed, err = MergeCandidate(schedule, true, candidate(3, 3, 150, 900), nil)
	if err != nil || !changed {
		t.Fatalf("second merge changed=%v err=%v", changed, err)
	}
	if schedule.Pending == nil || schedule.Pending.Target.TreeSize != 3 || schedule.Pending.OpenedAtUnixN != 100 || schedule.Pending.DueAtUnixN != 200 {
		t.Fatalf("pending=%+v", schedule.Pending)
	}
	if schedule.InFlight != nil {
		t.Fatalf("in_flight=%+v", schedule.InFlight)
	}
}

func TestMergeCandidateKeepsInFlightImmutableWhilePendingAdvances(t *testing.T) {
	t.Parallel()
	schedule, _, err := MergeCandidate(model.STHAnchorSchedule{}, false, candidate(1, 1, 100, 100), nil)
	if err != nil {
		t.Fatal(err)
	}
	schedule, first, claimed, err := Claim(schedule, 100, 200, "worker-1", "lease-1")
	if err != nil || !claimed {
		t.Fatalf("Claim claimed=%v err=%v", claimed, err)
	}
	schedule, changed, err := MergeCandidate(schedule, true, candidate(5, 5, 120, 220), nil)
	if err != nil || !changed {
		t.Fatalf("MergeCandidate changed=%v err=%v", changed, err)
	}
	if schedule.InFlight == nil || !SameTarget(schedule.InFlight.Target, first.Target) {
		t.Fatalf("in_flight changed: %+v", schedule.InFlight)
	}
	if schedule.Pending == nil || schedule.Pending.Target.TreeSize != 5 {
		t.Fatalf("pending=%+v", schedule.Pending)
	}
}

func TestMergeCandidateRejectsSameSizeDifferentRoot(t *testing.T) {
	t.Parallel()
	schedule, _, err := MergeCandidate(model.STHAnchorSchedule{}, false, candidate(2, 1, 100, 200), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = MergeCandidate(schedule, true, candidate(2, 2, 101, 201), nil)
	if trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("error=%v, want data loss", err)
	}
}

func TestMergeCandidateInitializesValidEmptyScheduleWhenAlreadyCovered(t *testing.T) {
	t.Parallel()
	sth := testSTH(3, 3)
	latest := model.STHAnchorResult{
		SchemaVersion:    model.SchemaSTHAnchorResult,
		NodeID:           "node-1",
		LogID:            "log-1",
		TreeSize:         sth.TreeSize,
		SinkName:         "file",
		AnchorID:         "anchor-3",
		RootHash:         sth.RootHash,
		STH:              sth,
		PublishedAtUnixN: 300,
	}
	schedule, changed, err := MergeCandidate(model.STHAnchorSchedule{}, false, candidate(2, 2, 100, 200), &latest)
	if err != nil || !changed {
		t.Fatalf("MergeCandidate changed=%v err=%v", changed, err)
	}
	if schedule.Pending != nil || schedule.InFlight != nil {
		t.Fatalf("covered candidate created work: %+v", schedule)
	}
	if err := ValidateSchedule(schedule); err != nil {
		t.Fatalf("covered candidate returned invalid schedule: %v", err)
	}
}

func TestRetryAndCompleteRequireLeaseAndExactTarget(t *testing.T) {
	t.Parallel()
	schedule, _, err := MergeCandidate(model.STHAnchorSchedule{}, false, candidate(2, 2, 100, 100), nil)
	if err != nil {
		t.Fatal(err)
	}
	schedule, attempt, claimed, err := Claim(schedule, 100, 200, "worker-1", "lease-1")
	if err != nil || !claimed {
		t.Fatalf("Claim claimed=%v err=%v", claimed, err)
	}
	if _, err := Reschedule(schedule, attempt.Generation+1, "lease-1", 1, 300, "retry"); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
		t.Fatalf("Reschedule wrong generation error=%v", err)
	}
	if _, err := Reschedule(schedule, attempt.Generation, "wrong", 1, 300, "retry"); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
		t.Fatalf("Reschedule error=%v", err)
	}
	schedule, err = Reschedule(schedule, attempt.Generation, "lease-1", 1, 300, "retry")
	if err != nil {
		t.Fatal(err)
	}
	schedule, attempt, claimed, err = Claim(schedule, 350, 450, "worker-2", "lease-2")
	if err != nil || !claimed {
		t.Fatalf("retry Claim claimed=%v err=%v", claimed, err)
	}
	if attempt.NextAttemptUnixN != 350 {
		t.Fatalf("retry deadline = %d, want actual late claim time 350", attempt.NextAttemptUnixN)
	}
	badSTH := testSTH(2, 9)
	bad := model.STHAnchorResult{SchemaVersion: model.SchemaSTHAnchorResult, TreeSize: 2, RootHash: badSTH.RootHash, NodeID: "node-1", LogID: "log-1", SinkName: "file", AnchorID: "bad", STH: badSTH, PublishedAtUnixN: 101}
	if _, err := Complete(schedule, attempt.Generation, "lease-2", bad); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
		t.Fatalf("Complete bad result error=%v", err)
	}
	good := model.STHAnchorResult{SchemaVersion: model.SchemaSTHAnchorResult, TreeSize: 2, RootHash: bytes.Repeat([]byte{2}, 32), NodeID: "node-1", LogID: "log-1", SinkName: "file", AnchorID: "good", STH: testSTH(2, 2), PublishedAtUnixN: 102}
	schedule, err = Complete(schedule, attempt.Generation, "lease-2", good)
	if err != nil {
		t.Fatal(err)
	}
	if schedule.InFlight != nil {
		t.Fatalf("in_flight=%+v", schedule.InFlight)
	}
}

func TestRetryAndFailureBoundStoredProviderError(t *testing.T) {
	t.Parallel()
	schedule, _, err := MergeCandidate(model.STHAnchorSchedule{}, false, candidate(2, 2, 100, 100), nil)
	if err != nil {
		t.Fatal(err)
	}
	schedule, attempt, claimed, err := Claim(schedule, 100, 200, "worker-1", "lease-1")
	if err != nil || !claimed {
		t.Fatalf("Claim claimed=%v err=%v", claimed, err)
	}
	tooLong := string(bytes.Repeat([]byte{'x'}, MaxLastErrorBytes+1))
	if _, err := Reschedule(schedule, attempt.Generation, "lease-1", 1, 300, tooLong); trusterr.CodeOf(err) != trusterr.CodeInvalidArgument {
		t.Fatalf("Reschedule oversized error=%v", err)
	}
	if _, err := Fail(schedule, attempt.Generation, "lease-1", 1, tooLong); trusterr.CodeOf(err) != trusterr.CodeInvalidArgument {
		t.Fatalf("Fail oversized error=%v", err)
	}
}

func TestValidateCandidateAgainstExactResultRejectsHistoricalSplitView(t *testing.T) {
	t.Parallel()
	sth := testSTH(13, 0x13)
	result := model.STHAnchorResult{
		SchemaVersion: model.SchemaSTHAnchorResult, NodeID: sth.NodeID, LogID: sth.LogID, TreeSize: sth.TreeSize,
		SinkName: "file", AnchorID: "anchor-13", RootHash: sth.RootHash, STH: sth, PublishedAtUnixN: 130,
	}
	conflict := candidate(13, 0x99, 200, 300)
	if err := ValidateCandidateAgainstExactResult(conflict, result); trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("ValidateCandidateAgainstExactResult error=%v, want data loss", err)
	}
}

func TestCompareResultKeysMatchesEncodedPhysicalOrder(t *testing.T) {
	t.Parallel()
	left := model.STHAnchorResultKey{TreeSize: 7, NodeID: "node-1", LogID: "log-1", SinkName: "C0"}
	right := model.STHAnchorResultKey{TreeSize: 7, NodeID: "node-1", LogID: "log-1", SinkName: "C@"}

	// Raw strings have C0 before C@, while their URL-base64 encodings are QzA
	// and Q0A. Ordered stores therefore place C@ first.
	if got := CompareResultKeys(left, right); got <= 0 {
		t.Fatalf("CompareResultKeys(C0, C@) = %d, want encoded physical order C@ < C0", got)
	}
	if got := CompareResultKeys(right, left); got >= 0 {
		t.Fatalf("CompareResultKeys(C@, C0) = %d, want encoded physical order C@ < C0", got)
	}
}

func TestValidateScheduleRejectsGenerationReuse(t *testing.T) {
	t.Parallel()
	schedule, _, err := MergeCandidate(model.STHAnchorSchedule{}, false, candidate(1, 1, 100, 100), nil)
	if err != nil {
		t.Fatal(err)
	}
	schedule.NextGeneration = schedule.Pending.Generation
	if err := ValidateSchedule(schedule); trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("ValidateSchedule error=%v, want data loss", err)
	}
}

func TestClearLeaseForRestorePreservesRetryState(t *testing.T) {
	t.Parallel()
	schedule, _, err := MergeCandidate(model.STHAnchorSchedule{}, false, candidate(2, 2, 100, 100), nil)
	if err != nil {
		t.Fatal(err)
	}
	schedule, attempt, claimed, err := Claim(schedule, 100, 200, "worker-1", "lease-1")
	if err != nil || !claimed {
		t.Fatalf("Claim claimed=%v err=%v", claimed, err)
	}
	schedule, err = Reschedule(schedule, attempt.Generation, "lease-1", 3, 300, "retry")
	if err != nil {
		t.Fatal(err)
	}
	schedule, _, claimed, err = Claim(schedule, 300, 400, "worker-2", "lease-2")
	if err != nil || !claimed {
		t.Fatalf("retry Claim claimed=%v err=%v", claimed, err)
	}
	restored, err := ClearLeaseForRestore(schedule)
	if err != nil {
		t.Fatal(err)
	}
	if restored.InFlight == nil || restored.InFlight.Attempts != 3 || restored.InFlight.NextAttemptUnixN != 300 || restored.InFlight.LastErrorMessage != "retry" {
		t.Fatalf("retry state changed: %+v", restored.InFlight)
	}
	if restored.InFlight.LeaseOwner != "" || restored.InFlight.LeaseToken != "" || restored.InFlight.LeaseUntilUnixN != 0 {
		t.Fatalf("lease survived restore: %+v", restored.InFlight)
	}
}

func TestTerminalFailureStopsClaimsAndKeepsPendingBounded(t *testing.T) {
	t.Parallel()
	schedule, _, err := MergeCandidate(model.STHAnchorSchedule{}, false, candidate(2, 2, 100, 100), nil)
	if err != nil {
		t.Fatal(err)
	}
	schedule, attempt, claimed, err := Claim(schedule, 100, 200, "worker-1", "lease-1")
	if err != nil || !claimed {
		t.Fatalf("Claim claimed=%v err=%v", claimed, err)
	}
	schedule, err = Fail(schedule, attempt.Generation, "lease-1", 1, "schema rejected")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, claimed, err := Claim(schedule, 300, 400, "worker-2", "lease-2"); err != nil || claimed {
		t.Fatalf("terminal Claim claimed=%v err=%v", claimed, err)
	}
	schedule, changed, err := MergeCandidate(schedule, true, candidate(5, 5, 300, 400), nil)
	if err != nil || !changed {
		t.Fatalf("MergeCandidate changed=%v err=%v", changed, err)
	}
	if schedule.InFlight == nil || !schedule.InFlight.TerminalFailure || schedule.InFlight.Target.TreeSize != 2 || schedule.Pending == nil || schedule.Pending.Target.TreeSize != 5 {
		t.Fatalf("terminal schedule = %+v", schedule)
	}
}

func TestReconcileCompletedClearsOnlyMatchingInFlight(t *testing.T) {
	t.Parallel()
	schedule, _, err := MergeCandidate(model.STHAnchorSchedule{}, false, candidate(2, 2, 100, 100), nil)
	if err != nil {
		t.Fatal(err)
	}
	schedule, attempt, claimed, err := Claim(schedule, 100, 200, "worker-1", "lease-1")
	if err != nil || !claimed {
		t.Fatalf("Claim claimed=%v err=%v", claimed, err)
	}
	result := model.STHAnchorResult{
		SchemaVersion: model.SchemaSTHAnchorResult, NodeID: "node-1", LogID: "log-1", TreeSize: 2,
		SinkName: "file", AnchorID: "anchor-2", RootHash: attempt.Target.RootHash, STH: attempt.Target, PublishedAtUnixN: 150,
	}
	reconciled, changed, err := ReconcileCompleted(schedule, result)
	if err != nil || !changed || reconciled.InFlight != nil {
		t.Fatalf("ReconcileCompleted changed=%v schedule=%+v err=%v", changed, reconciled, err)
	}
	reconciled, _, err = MergeCandidate(reconciled, true, candidate(5, 5, 200, 200), &result)
	if err != nil {
		t.Fatal(err)
	}
	reconciled, _, claimed, err = Claim(reconciled, 200, 300, "worker-2", "lease-2")
	if err != nil || !claimed {
		t.Fatalf("second Claim claimed=%v err=%v", claimed, err)
	}
	unchanged, changed, err := ReconcileCompleted(reconciled, result)
	if err != nil || changed || unchanged.InFlight == nil || unchanged.InFlight.Target.TreeSize != 5 {
		t.Fatalf("old result changed later in-flight changed=%v schedule=%+v err=%v", changed, unchanged, err)
	}
}

func TestSameResultBindingIncludesExternalAnchorIdentity(t *testing.T) {
	t.Parallel()
	sth := testSTH(2, 2)
	left := model.STHAnchorResult{
		SchemaVersion: model.SchemaSTHAnchorResult, NodeID: "node-1", LogID: "log-1", TreeSize: 2,
		SinkName: "file", AnchorID: "anchor-a", RootHash: sth.RootHash, STH: sth, PublishedAtUnixN: 100,
	}
	right := left
	right.AnchorID = "anchor-b"
	if SameResultBinding(left, right) {
		t.Fatal("different external anchor ids share an immutable binding")
	}
	right = left
	right.Proof = []byte("upgraded-proof")
	right.PublishedAtUnixN = 200
	if !SameResultBinding(left, right) {
		t.Fatal("proof enrichment changed immutable result binding")
	}
}

func TestEmptyLatestReferenceIsScopedToOneStream(t *testing.T) {
	t.Parallel()
	key := testKey()
	ref := EmptyLatestReference(&key)
	if !ValidEmptyLatestReference(ref) || !EmptyLatestReferenceMatches(ref, &key) {
		t.Fatalf("empty latest reference does not match its stream: %+v", ref)
	}
	other := key
	other.SinkName = "ots"
	if EmptyLatestReferenceMatches(ref, &other) || EmptyLatestReferenceMatches(ref, nil) {
		t.Fatalf("stream-scoped empty reference matched another scope: %+v", ref)
	}
	aggregate := EmptyLatestReference(nil)
	if !EmptyLatestReferenceMatches(aggregate, nil) || EmptyLatestReferenceMatches(aggregate, &key) {
		t.Fatalf("aggregate empty reference has the wrong scope: %+v", aggregate)
	}
}

func TestSelectPublicationTargetsCanonicalizesNonMonotonicRetries(t *testing.T) {
	t.Parallel()
	one := testSTH(1, 0x11)
	two := testSTH(2, 0x22)
	three := testSTH(3, 0x33)
	windowStart, highest, err := SelectPublicationTargets([]model.SignedTreeHead{three, one, two}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if windowStart.TreeSize != 2 || highest.TreeSize != 3 {
		t.Fatalf("window_start=%d highest=%d, want 2/3", windowStart.TreeSize, highest.TreeSize)
	}
	windowStart, highest, err = SelectPublicationTargets([]model.SignedTreeHead{two, one}, 2)
	if err != nil || windowStart.TreeSize != 2 || highest.TreeSize != 2 {
		t.Fatalf("fully covered selection start=%d highest=%d err=%v", windowStart.TreeSize, highest.TreeSize, err)
	}
	conflict := two
	conflict.RootHash = bytes.Repeat([]byte{0xff}, len(two.RootHash))
	if _, _, err := SelectPublicationTargets([]model.SignedTreeHead{two, conflict}, 0); trusterr.CodeOf(err) != trusterr.CodeDataLoss {
		t.Fatalf("conflicting equal-size STH error=%v, want data loss", err)
	}
}
