package anchorschedule

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"sort"
	"strings"

	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

// MaxLastErrorBytes bounds provider-controlled text retained in the mutable
// scheduler state. Pending/InFlight cardinality is constant, and this keeps
// their encoded size bounded as well.
const MaxLastErrorBytes = 4096

func ValidateKey(key model.STHAnchorScheduleKey) error {
	if key.SinkName == "" {
		return trusterr.New(trusterr.CodeInvalidArgument, "anchor schedule sink_name is required")
	}
	return nil
}

func ValidateResultKey(key model.STHAnchorResultKey) error {
	if err := ValidateKey(ScheduleKey(key)); err != nil {
		return err
	}
	if key.TreeSize == 0 {
		return trusterr.New(trusterr.CodeInvalidArgument, "anchor result tree_size is required")
	}
	return nil
}

func ValidateCandidate(candidate model.STHAnchorCandidate) error {
	if err := ValidateKey(candidate.Key); err != nil {
		return err
	}
	if err := validateTarget(candidate.Key, candidate.STH); err != nil {
		return err
	}
	if candidate.ObservedAtUnixN <= 0 {
		return trusterr.New(trusterr.CodeInvalidArgument, "anchor candidate observed_at is required")
	}
	if candidate.DueAtUnixN < candidate.ObservedAtUnixN {
		return trusterr.New(trusterr.CodeInvalidArgument, "anchor candidate due_at precedes observed_at")
	}
	return nil
}

// BindAttemptResult fills a sink response from the immutable in-flight target
// and then verifies the exact cryptographic binding before it can be stored.
func BindAttemptResult(key model.STHAnchorScheduleKey, attempt model.STHAnchorAttempt, result model.STHAnchorResult, publishedAtUnixN int64) (model.STHAnchorResult, error) {
	if result.SchemaVersion == "" {
		result.SchemaVersion = model.SchemaSTHAnchorResult
	}
	if result.TreeSize == 0 {
		result.TreeSize = attempt.Target.TreeSize
	}
	if result.NodeID == "" {
		result.NodeID = key.NodeID
	}
	if result.LogID == "" {
		result.LogID = key.LogID
	}
	if result.SinkName == "" {
		result.SinkName = key.SinkName
	}
	if len(result.RootHash) == 0 {
		result.RootHash = append([]byte(nil), attempt.Target.RootHash...)
	}
	if result.STH.TreeSize == 0 {
		result.STH = attempt.Target
	}
	if result.PublishedAtUnixN == 0 {
		result.PublishedAtUnixN = publishedAtUnixN
	}
	if err := ValidateResult(key, result); err != nil {
		return model.STHAnchorResult{}, err
	}
	if !ResultMatchesTarget(result, attempt.Target) {
		return model.STHAnchorResult{}, trusterr.New(trusterr.CodeDataLoss, "anchor result does not match immutable in-flight target")
	}
	return result, nil
}

func ValidateSchedule(schedule model.STHAnchorSchedule) error {
	if schedule.SchemaVersion != model.SchemaSTHAnchorSchedule {
		return trusterr.New(trusterr.CodeDataLoss, "unexpected anchor schedule schema")
	}
	if err := ValidateKey(schedule.Key); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "invalid anchor schedule key", err)
	}
	if schedule.NextGeneration == 0 {
		return trusterr.New(trusterr.CodeDataLoss, "anchor schedule next_generation is zero")
	}
	if schedule.Revision == 0 {
		return trusterr.New(trusterr.CodeDataLoss, "anchor schedule revision is zero")
	}
	var highestGeneration uint64
	if schedule.Pending != nil {
		if schedule.Pending.Generation == 0 || schedule.Pending.OpenedAtUnixN <= 0 || schedule.Pending.DueAtUnixN < schedule.Pending.OpenedAtUnixN || schedule.Pending.UpdatedAtUnixN < schedule.Pending.OpenedAtUnixN {
			return trusterr.New(trusterr.CodeDataLoss, "invalid pending anchor window")
		}
		if err := validateTarget(schedule.Key, schedule.Pending.Target); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "invalid pending anchor target", err)
		}
		highestGeneration = schedule.Pending.Generation
	}
	if schedule.InFlight != nil {
		attempt := schedule.InFlight
		if attempt.Generation == 0 || attempt.OpenedAtUnixN <= 0 || attempt.DueAtUnixN < attempt.OpenedAtUnixN || attempt.Attempts < 0 || attempt.NextAttemptUnixN < 0 || attempt.LastAttemptUnixN <= 0 {
			return trusterr.New(trusterr.CodeDataLoss, "invalid in-flight anchor attempt")
		}
		if len(attempt.LastErrorMessage) > MaxLastErrorBytes {
			return trusterr.New(trusterr.CodeDataLoss, "in-flight anchor error exceeds size limit")
		}
		if attempt.NextAttemptUnixN > 0 && attempt.NextAttemptUnixN < attempt.LastAttemptUnixN {
			return trusterr.New(trusterr.CodeDataLoss, "in-flight anchor retry precedes last attempt")
		}
		hasLease := attempt.LeaseOwner != "" || attempt.LeaseToken != "" || attempt.LeaseUntilUnixN != 0
		if hasLease && (attempt.LeaseOwner == "" || attempt.LeaseToken == "" || attempt.LeaseUntilUnixN <= attempt.LastAttemptUnixN) {
			return trusterr.New(trusterr.CodeDataLoss, "in-flight anchor lease is incomplete")
		}
		if attempt.TerminalFailure && (attempt.Attempts == 0 || attempt.LastErrorMessage == "" || attempt.NextAttemptUnixN != 0 || hasLease) {
			return trusterr.New(trusterr.CodeDataLoss, "terminal anchor failure state is invalid")
		}
		if !attempt.TerminalFailure && !hasLease && attempt.Attempts > 0 && attempt.NextAttemptUnixN == 0 {
			return trusterr.New(trusterr.CodeDataLoss, "retryable anchor attempt has no retry deadline")
		}
		if err := validateTarget(schedule.Key, attempt.Target); err != nil {
			return trusterr.Wrap(trusterr.CodeDataLoss, "invalid in-flight anchor target", err)
		}
		if attempt.Generation > highestGeneration {
			highestGeneration = attempt.Generation
		}
	}
	if schedule.Pending != nil && schedule.InFlight != nil {
		if schedule.Pending.Generation <= schedule.InFlight.Generation {
			return trusterr.New(trusterr.CodeDataLoss, "pending anchor generation does not follow in-flight generation")
		}
		if schedule.Pending.Target.TreeSize <= schedule.InFlight.Target.TreeSize {
			return trusterr.New(trusterr.CodeDataLoss, "pending anchor target does not advance in-flight target")
		}
	}
	if schedule.NextGeneration <= highestGeneration {
		return trusterr.New(trusterr.CodeDataLoss, "anchor schedule next_generation does not advance active work")
	}
	return nil
}

// MergeCandidate applies the non-sliding coalescing rule. latest may be nil;
// when present it is the greatest durable successful result and prevents
// re-enqueuing already covered targets.
func MergeCandidate(current model.STHAnchorSchedule, exists bool, candidate model.STHAnchorCandidate, latest *model.STHAnchorResult) (model.STHAnchorSchedule, bool, error) {
	if err := ValidateCandidate(candidate); err != nil {
		return model.STHAnchorSchedule{}, false, err
	}
	created := !exists
	if created {
		current = model.STHAnchorSchedule{
			SchemaVersion:  model.SchemaSTHAnchorSchedule,
			Key:            candidate.Key,
			NextGeneration: 1,
		}
	} else {
		if err := ValidateSchedule(current); err != nil {
			return model.STHAnchorSchedule{}, false, err
		}
		if !SameKey(current.Key, candidate.Key) {
			return model.STHAnchorSchedule{}, false, trusterr.New(trusterr.CodeDataLoss, "anchor schedule key does not match candidate")
		}
	}

	if latest != nil {
		if err := ValidateResult(candidate.Key, *latest); err != nil {
			return model.STHAnchorSchedule{}, false, err
		}
		if candidate.STH.TreeSize == latest.TreeSize && (!bytes.Equal(candidate.STH.RootHash, latest.RootHash) || candidate.Key.NodeID != latest.NodeID || candidate.Key.LogID != latest.LogID) {
			return model.STHAnchorSchedule{}, false, trusterr.New(trusterr.CodeDataLoss, "anchor candidate conflicts with published result")
		}
		if candidate.STH.TreeSize <= latest.TreeSize {
			if created {
				current.Revision = 1
				return current, true, nil
			}
			return current, false, nil
		}
	}

	for _, target := range scheduleTargets(current) {
		if candidate.STH.TreeSize == target.TreeSize && !SameTarget(candidate.STH, target) {
			return model.STHAnchorSchedule{}, false, trusterr.New(trusterr.CodeDataLoss, "anchor candidate conflicts with scheduled target")
		}
		if candidate.STH.TreeSize <= target.TreeSize {
			return current, false, nil
		}
	}

	if current.Pending != nil {
		pending := *current.Pending
		pending.Target = candidate.STH
		if candidate.ObservedAtUnixN > pending.UpdatedAtUnixN {
			pending.UpdatedAtUnixN = candidate.ObservedAtUnixN
		}
		current.Pending = &pending
	} else {
		generation := current.NextGeneration
		if generation == 0 {
			generation = 1
		}
		current.Pending = &model.STHAnchorWindow{
			Generation:     generation,
			Target:         candidate.STH,
			OpenedAtUnixN:  candidate.ObservedAtUnixN,
			DueAtUnixN:     candidate.DueAtUnixN,
			UpdatedAtUnixN: candidate.ObservedAtUnixN,
		}
		current.NextGeneration = generation + 1
	}
	current.Revision++
	return current, true, nil
}

func Claim(current model.STHAnchorSchedule, nowUnixN, leaseUntilUnixN int64, leaseOwner, leaseToken string) (model.STHAnchorSchedule, model.STHAnchorAttempt, bool, error) {
	if err := ValidateSchedule(current); err != nil {
		return model.STHAnchorSchedule{}, model.STHAnchorAttempt{}, false, err
	}
	if nowUnixN <= 0 || leaseUntilUnixN <= nowUnixN || leaseOwner == "" || leaseToken == "" {
		return model.STHAnchorSchedule{}, model.STHAnchorAttempt{}, false, trusterr.New(trusterr.CodeInvalidArgument, "valid anchor lease fields are required")
	}
	if current.InFlight != nil {
		attempt := *current.InFlight
		if attempt.TerminalFailure {
			return current, model.STHAnchorAttempt{}, false, nil
		}
		if attempt.NextAttemptUnixN > nowUnixN || attempt.LeaseUntilUnixN > nowUnixN {
			return current, model.STHAnchorAttempt{}, false, nil
		}
		attempt.LeaseOwner = leaseOwner
		attempt.LeaseToken = leaseToken
		attempt.LeaseUntilUnixN = leaseUntilUnixN
		attempt.LastAttemptUnixN = nowUnixN
		// A retry may be claimed after its persisted deadline. Advance the
		// retry timestamp to the actual claim time so the leased schedule stays
		// valid and a lease-cleared restore remains immediately retryable.
		attempt.NextAttemptUnixN = nowUnixN
		current.InFlight = &attempt
		current.Revision++
		return current, attempt, true, nil
	}
	if current.Pending == nil || current.Pending.DueAtUnixN > nowUnixN {
		return current, model.STHAnchorAttempt{}, false, nil
	}
	pending := *current.Pending
	attempt := model.STHAnchorAttempt{
		Generation:       pending.Generation,
		Target:           pending.Target,
		OpenedAtUnixN:    pending.OpenedAtUnixN,
		DueAtUnixN:       pending.DueAtUnixN,
		LastAttemptUnixN: nowUnixN,
		LeaseOwner:       leaseOwner,
		LeaseToken:       leaseToken,
		LeaseUntilUnixN:  leaseUntilUnixN,
	}
	current.Pending = nil
	current.InFlight = &attempt
	current.Revision++
	return current, attempt, true, nil
}

func Reschedule(current model.STHAnchorSchedule, generation uint64, leaseToken string, attempts int, nextAttemptUnixN int64, lastError string) (model.STHAnchorSchedule, error) {
	if err := ValidateSchedule(current); err != nil {
		return model.STHAnchorSchedule{}, err
	}
	if current.InFlight == nil {
		return model.STHAnchorSchedule{}, trusterr.New(trusterr.CodeNotFound, "in-flight anchor attempt not found")
	}
	if generation == 0 || current.InFlight.Generation != generation || leaseToken == "" || current.InFlight.LeaseToken != leaseToken {
		return model.STHAnchorSchedule{}, trusterr.New(trusterr.CodeFailedPrecondition, "anchor attempt generation or lease token does not match")
	}
	if attempts <= current.InFlight.Attempts || nextAttemptUnixN < current.InFlight.LastAttemptUnixN || lastError == "" || len(lastError) > MaxLastErrorBytes {
		return model.STHAnchorSchedule{}, trusterr.New(trusterr.CodeInvalidArgument, "invalid anchor retry state")
	}
	attempt := *current.InFlight
	attempt.Attempts = attempts
	attempt.NextAttemptUnixN = nextAttemptUnixN
	attempt.LastErrorMessage = lastError
	attempt.TerminalFailure = false
	attempt.LeaseOwner = ""
	attempt.LeaseToken = ""
	attempt.LeaseUntilUnixN = 0
	current.InFlight = &attempt
	current.Revision++
	return current, nil
}

// Fail marks one immutable in-flight target as terminal. It remains durable
// and blocks automatic replacement, while newer STHs may still coalesce into
// the single Pending window for operator inspection and recovery.
func Fail(current model.STHAnchorSchedule, generation uint64, leaseToken string, attempts int, lastError string) (model.STHAnchorSchedule, error) {
	if err := ValidateSchedule(current); err != nil {
		return model.STHAnchorSchedule{}, err
	}
	if current.InFlight == nil {
		return model.STHAnchorSchedule{}, trusterr.New(trusterr.CodeNotFound, "in-flight anchor attempt not found")
	}
	if generation == 0 || current.InFlight.Generation != generation || leaseToken == "" || current.InFlight.LeaseToken != leaseToken {
		return model.STHAnchorSchedule{}, trusterr.New(trusterr.CodeFailedPrecondition, "anchor attempt generation or lease token does not match")
	}
	if attempts <= current.InFlight.Attempts || lastError == "" || len(lastError) > MaxLastErrorBytes {
		return model.STHAnchorSchedule{}, trusterr.New(trusterr.CodeInvalidArgument, "invalid terminal anchor failure state")
	}
	attempt := *current.InFlight
	attempt.Attempts = attempts
	attempt.NextAttemptUnixN = 0
	attempt.LastErrorMessage = lastError
	attempt.TerminalFailure = true
	attempt.LeaseOwner = ""
	attempt.LeaseToken = ""
	attempt.LeaseUntilUnixN = 0
	current.InFlight = &attempt
	current.Revision++
	return current, nil
}

func Complete(current model.STHAnchorSchedule, generation uint64, leaseToken string, result model.STHAnchorResult) (model.STHAnchorSchedule, error) {
	if err := ValidateSchedule(current); err != nil {
		return model.STHAnchorSchedule{}, err
	}
	if current.InFlight == nil {
		return model.STHAnchorSchedule{}, trusterr.New(trusterr.CodeNotFound, "in-flight anchor attempt not found")
	}
	if generation == 0 || current.InFlight.Generation != generation || leaseToken == "" || current.InFlight.LeaseToken != leaseToken {
		return model.STHAnchorSchedule{}, trusterr.New(trusterr.CodeFailedPrecondition, "anchor attempt generation or lease token does not match")
	}
	if err := ValidateResult(current.Key, result); err != nil {
		return model.STHAnchorSchedule{}, err
	}
	if !ResultMatchesTarget(result, current.InFlight.Target) {
		return model.STHAnchorSchedule{}, trusterr.New(trusterr.CodeFailedPrecondition, "anchor result does not match in-flight target")
	}
	return reconcileCompleted(current, result)
}

// ReconcileCompleted repairs the durable scheduler side of a completion after
// the immutable result is already known to be stored. This is the recovery
// path for a crash between result durability and schedule cleanup, so it does
// not require a process-local lease token.
func ReconcileCompleted(current model.STHAnchorSchedule, result model.STHAnchorResult) (model.STHAnchorSchedule, bool, error) {
	if err := ValidateSchedule(current); err != nil {
		return model.STHAnchorSchedule{}, false, err
	}
	if err := ValidateResult(current.Key, result); err != nil {
		return model.STHAnchorSchedule{}, false, err
	}
	next, err := reconcileCompleted(current, result)
	if err != nil {
		return model.STHAnchorSchedule{}, false, err
	}
	return next, next.Revision != current.Revision, nil
}

func reconcileCompleted(current model.STHAnchorSchedule, result model.STHAnchorResult) (model.STHAnchorSchedule, error) {
	changed := false
	if current.InFlight != nil && current.InFlight.Target.TreeSize == result.TreeSize {
		if !ResultMatchesTarget(result, current.InFlight.Target) {
			return model.STHAnchorSchedule{}, trusterr.New(trusterr.CodeDataLoss, "stored anchor result conflicts with in-flight target")
		}
		current.InFlight = nil
		changed = true
	}
	if current.Pending != nil && current.Pending.Target.TreeSize <= result.TreeSize {
		if current.Pending.Target.TreeSize == result.TreeSize && !bytes.Equal(current.Pending.Target.RootHash, result.RootHash) {
			return model.STHAnchorSchedule{}, trusterr.New(trusterr.CodeDataLoss, "pending anchor target conflicts with completed result")
		}
		current.Pending = nil
		changed = true
	}
	if changed {
		current.Revision++
	}
	return current, nil
}

// ClearLeaseForRestore removes ownership from another process while retaining
// the immutable target, retry counter, and retry deadline.
func ClearLeaseForRestore(current model.STHAnchorSchedule) (model.STHAnchorSchedule, error) {
	if err := ValidateSchedule(current); err != nil {
		return model.STHAnchorSchedule{}, err
	}
	if current.InFlight == nil || current.InFlight.LeaseOwner == "" && current.InFlight.LeaseToken == "" && current.InFlight.LeaseUntilUnixN == 0 {
		return current, nil
	}
	attempt := *current.InFlight
	attempt.LeaseOwner = ""
	attempt.LeaseToken = ""
	attempt.LeaseUntilUnixN = 0
	current.InFlight = &attempt
	current.Revision++
	return current, nil
}

func SameKey(left, right model.STHAnchorScheduleKey) bool {
	return left.NodeID == right.NodeID && left.LogID == right.LogID && left.SinkName == right.SinkName
}

func ResultKey(result model.STHAnchorResult) model.STHAnchorResultKey {
	return model.STHAnchorResultKey{
		NodeID: result.NodeID, LogID: result.LogID, SinkName: result.SinkName, TreeSize: result.TreeSize,
	}
}

func ScheduleKey(key model.STHAnchorResultKey) model.STHAnchorScheduleKey {
	return model.STHAnchorScheduleKey{NodeID: key.NodeID, LogID: key.LogID, SinkName: key.SinkName}
}

func SameResultKey(left, right model.STHAnchorResultKey) bool {
	return left.TreeSize == right.TreeSize && SameKey(ScheduleKey(left), ScheduleKey(right))
}

// CompareResultKeys defines backup and physical-key order: TreeSize first so
// aggregate latest remains monotonic, followed by the full stream identity so
// pagination cannot skip two sinks at the same size.
func CompareResultKeys(left, right model.STHAnchorResultKey) int {
	if left.TreeSize < right.TreeSize {
		return -1
	}
	if left.TreeSize > right.TreeSize {
		return 1
	}
	leftIdentity := resultKeyOrderIdentity(left)
	rightIdentity := resultKeyOrderIdentity(right)
	if leftIdentity < rightIdentity {
		return -1
	}
	if leftIdentity > rightIdentity {
		return 1
	}
	return 0
}

// resultKeyOrderIdentity mirrors the exact byte suffix used by the ordered KV
// backends. Comparing the encoded composite (including separators) matters:
// URL-base64 does not preserve the lexical order of the original strings.
func resultKeyOrderIdentity(key model.STHAnchorResultKey) string {
	parts := [...]string{
		base64.RawURLEncoding.EncodeToString([]byte(key.NodeID)),
		base64.RawURLEncoding.EncodeToString([]byte(key.LogID)),
		base64.RawURLEncoding.EncodeToString([]byte(key.SinkName)),
	}
	return strings.Join(parts[:], "/")
}

func SameTarget(left, right model.SignedTreeHead) bool {
	return left.SchemaVersion == right.SchemaVersion &&
		left.TreeAlg == right.TreeAlg &&
		left.TreeSize == right.TreeSize &&
		bytes.Equal(left.RootHash, right.RootHash) &&
		left.TimestampUnixN == right.TimestampUnixN &&
		left.NodeID == right.NodeID &&
		left.LogID == right.LogID &&
		left.Signature.Alg == right.Signature.Alg &&
		left.Signature.KeyID == right.Signature.KeyID &&
		bytes.Equal(left.Signature.Signature, right.Signature.Signature)
}

// SelectPublicationTargets canonicalizes a possibly non-monotonic retry
// batch. The highest STH covers every lower tree size, while the fixed window
// starts at the earliest STH not already covered by the keyed latest result.
// Equal tree sizes must be byte-identical or the store is internally
// inconsistent and anchoring fails closed.
func SelectPublicationTargets(sths []model.SignedTreeHead, coveredTreeSize uint64) (model.SignedTreeHead, model.SignedTreeHead, error) {
	if len(sths) == 0 {
		return model.SignedTreeHead{}, model.SignedTreeHead{}, trusterr.New(trusterr.CodeInvalidArgument, "anchor publication requires at least one STH")
	}
	seen := make(map[uint64]model.SignedTreeHead, len(sths))
	var windowStart model.SignedTreeHead
	var highest model.SignedTreeHead
	for _, sth := range sths {
		if sth.TreeSize == 0 {
			return model.SignedTreeHead{}, model.SignedTreeHead{}, trusterr.New(trusterr.CodeInvalidArgument, "anchor publication STH tree_size is required")
		}
		if existing, found := seen[sth.TreeSize]; found {
			if !SameTarget(existing, sth) {
				return model.SignedTreeHead{}, model.SignedTreeHead{}, trusterr.New(trusterr.CodeDataLoss, "anchor publication contains conflicting STHs at one tree size")
			}
		} else {
			seen[sth.TreeSize] = sth
		}
		if highest.TreeSize == 0 || sth.TreeSize > highest.TreeSize {
			highest = sth
		}
		if sth.TreeSize > coveredTreeSize && (windowStart.TreeSize == 0 || sth.TreeSize < windowStart.TreeSize) {
			windowStart = sth
		}
	}
	if windowStart.TreeSize == 0 {
		windowStart = highest
	}
	return windowStart, highest, nil
}

// ValidateResult verifies the immutable cryptographic binding of a successful
// sink publication. Sink-specific proof bytes may later be enriched (for
// example by an OTS upgrade), but the schedule key and complete Signed STH may
// never change.
func ValidateResult(key model.STHAnchorScheduleKey, result model.STHAnchorResult) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	if result.SchemaVersion != model.SchemaSTHAnchorResult || result.TreeSize == 0 || len(result.RootHash) != sha256.Size || result.AnchorID == "" || result.PublishedAtUnixN <= 0 {
		return trusterr.New(trusterr.CodeInvalidArgument, "valid STH anchor result is required")
	}
	if result.NodeID != key.NodeID || result.LogID != key.LogID || result.SinkName != key.SinkName {
		return trusterr.New(trusterr.CodeInvalidArgument, "anchor result identity does not match schedule key")
	}
	if err := validateTarget(key, result.STH); err != nil {
		return trusterr.Wrap(trusterr.CodeInvalidArgument, "anchor result signed tree head is invalid", err)
	}
	if result.TreeSize != result.STH.TreeSize || !bytes.Equal(result.RootHash, result.STH.RootHash) {
		return trusterr.New(trusterr.CodeInvalidArgument, "anchor result does not bind its signed tree head")
	}
	return nil
}

func ValidateLatestReference(ref model.STHAnchorLatestReference) error {
	if ref.SchemaVersion != model.SchemaSTHAnchorLatest {
		return trusterr.New(trusterr.CodeDataLoss, "unexpected latest anchor reference schema")
	}
	if err := ValidateResultKey(ref.Key); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "invalid latest anchor result key", err)
	}
	if len(ref.RootHash) != sha256.Size || ref.AnchorID == "" {
		return trusterr.New(trusterr.CodeDataLoss, "invalid latest anchor result binding")
	}
	return nil
}

func LatestReference(result model.STHAnchorResult) model.STHAnchorLatestReference {
	return model.STHAnchorLatestReference{
		SchemaVersion: model.SchemaSTHAnchorLatest,
		Key:           ResultKey(result),
		RootHash:      append([]byte(nil), result.RootHash...),
		AnchorID:      result.AnchorID,
	}
}

// EmptyLatestReference is derived negative state for a stream that has been
// scanned and has no successful anchor result. Persisting it prevents every
// candidate merge for a new sink from rescanning unrelated result history.
func EmptyLatestReference(stream *model.STHAnchorScheduleKey) model.STHAnchorLatestReference {
	ref := model.STHAnchorLatestReference{SchemaVersion: model.SchemaSTHAnchorLatestEmpty}
	if stream != nil {
		ref.Key.NodeID = stream.NodeID
		ref.Key.LogID = stream.LogID
		ref.Key.SinkName = stream.SinkName
	}
	return ref
}

func EmptyLatestReferenceMatches(ref model.STHAnchorLatestReference, stream *model.STHAnchorScheduleKey) bool {
	if !ValidEmptyLatestReference(ref) {
		return false
	}
	actual := ScheduleKey(ref.Key)
	if stream == nil {
		return actual == (model.STHAnchorScheduleKey{})
	}
	return SameKey(actual, *stream)
}

func ValidEmptyLatestReference(ref model.STHAnchorLatestReference) bool {
	return ref.SchemaVersion == model.SchemaSTHAnchorLatestEmpty && ref.Key.TreeSize == 0 && len(ref.RootHash) == 0 && ref.AnchorID == ""
}

func ReferenceMatchesResult(ref model.STHAnchorLatestReference, result model.STHAnchorResult) bool {
	return SameResultKey(ref.Key, ResultKey(result)) &&
		bytes.Equal(ref.RootHash, result.RootHash) &&
		ref.AnchorID == result.AnchorID
}

func ResultMatchesTarget(result model.STHAnchorResult, target model.SignedTreeHead) bool {
	return result.TreeSize == target.TreeSize &&
		bytes.Equal(result.RootHash, target.RootHash) &&
		SameTarget(result.STH, target)
}

// ValidateCandidateAgainstExactResult applies the global-log split-view
// check for an immutable result stored at the candidate's exact tree size.
// Sink identity is intentionally not compared: every sink must observe the
// same canonical (NodeID, LogID, TreeSize, RootHash) tuple.
func ValidateCandidateAgainstExactResult(candidate model.STHAnchorCandidate, result model.STHAnchorResult) error {
	resultKey := model.STHAnchorScheduleKey{NodeID: result.NodeID, LogID: result.LogID, SinkName: result.SinkName}
	if err := ValidateResult(resultKey, result); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "stored exact-tree anchor result is invalid", err)
	}
	if result.TreeSize != candidate.STH.TreeSize {
		return trusterr.New(trusterr.CodeDataLoss, "stored anchor result tree size does not match lookup")
	}
	if result.NodeID != candidate.Key.NodeID || result.LogID != candidate.Key.LogID || !bytes.Equal(result.RootHash, candidate.STH.RootHash) {
		return trusterr.New(trusterr.CodeDataLoss, "anchor candidate conflicts with immutable exact-tree result")
	}
	return nil
}

// SameResultBinding compares the immutable portion of two result envelopes.
// It intentionally ignores the external proof bytes and publication metadata
// so an idempotent retry cannot overwrite a later sink-proof upgrade.
func SameResultBinding(left, right model.STHAnchorResult) bool {
	return left.NodeID == right.NodeID &&
		left.LogID == right.LogID &&
		left.TreeSize == right.TreeSize &&
		left.SinkName == right.SinkName &&
		left.AnchorID == right.AnchorID &&
		bytes.Equal(left.RootHash, right.RootHash) &&
		SameTarget(left.STH, right.STH)
}

func Sort(schedules []model.STHAnchorSchedule) {
	sort.Slice(schedules, func(i, j int) bool {
		left, right := schedules[i].Key, schedules[j].Key
		if left.NodeID != right.NodeID {
			return left.NodeID < right.NodeID
		}
		if left.LogID != right.LogID {
			return left.LogID < right.LogID
		}
		return left.SinkName < right.SinkName
	})
}

func validateTarget(key model.STHAnchorScheduleKey, sth model.SignedTreeHead) error {
	if sth.SchemaVersion != model.SchemaSignedTreeHead || sth.TreeAlg != model.DefaultMerkleTreeAlg || sth.TreeSize == 0 || len(sth.RootHash) != sha256.Size || sth.TimestampUnixN <= 0 || sth.Signature.Alg == "" || sth.Signature.KeyID == "" || len(sth.Signature.Signature) == 0 {
		return trusterr.New(trusterr.CodeInvalidArgument, "valid signed tree head is required")
	}
	if sth.NodeID != key.NodeID || sth.LogID != key.LogID {
		return trusterr.New(trusterr.CodeInvalidArgument, "signed tree head identity does not match anchor schedule key")
	}
	return nil
}
func scheduleTargets(schedule model.STHAnchorSchedule) []model.SignedTreeHead {
	targets := make([]model.SignedTreeHead, 0, 2)
	if schedule.InFlight != nil {
		targets = append(targets, schedule.InFlight.Target)
	}
	if schedule.Pending != nil {
		targets = append(targets, schedule.Pending.Target)
	}
	return targets
}
