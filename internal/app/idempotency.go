package app

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	durableidempotency "github.com/ryan-wong-coder/trustdb/internal/idempotency"
	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/trusterr"
)

// DurableIdempotencyReader provides the bounded point lookup used when a
// trusted checkpoint lets startup skip older accepted WAL records.
type DurableIdempotencyReader interface {
	GetIdempotencyDecision(context.Context, model.IdempotencyIdentity) (model.IdempotencyDecision, bool, error)
}

// DurableRecordReader resolves a committed record by its deterministic ID.
// It provides restart idempotency for claims that omit idempotency_key.
type DurableRecordReader interface {
	GetBundle(context.Context, string) (model.ProofBundle, error)
}

// IdempotencyIndex tracks already-accepted claims keyed by either their
// (tenant_id, client_id, idempotency_key) triple or, for unkeyed claims, their
// deterministic record ID. Exact retries must converge to the same accepted
// response before another WAL append.
//
// The index is only a fast lookup layer. Retained WAL replay repopulates recent
// decisions; a durable reader resolves committed decisions below a trusted
// checkpoint without retaining all historical keys in memory.
type IdempotencyIndex struct {
	entriesMu sync.RWMutex
	entries   map[string]idempotencyEntry

	durableSlots     []durableIdempotencySlot
	durableNext      int
	nextDurableEpoch uint64

	locksMu sync.Mutex
	locks   map[string]*keyedLock
}

type idempotencyEntry struct {
	record       model.ServerRecord
	accepted     model.AcceptedReceipt
	claimHash    []byte
	durable      bool
	durableEpoch uint64
}

type durableIdempotencySlot struct {
	key   string
	epoch uint64
}

type keyedLock struct {
	mu   sync.Mutex
	refs int
}

const defaultDurableIdempotencyCapacity = 4096

// NewIdempotencyIndex returns an empty in-memory index ready for use.
func NewIdempotencyIndex() *IdempotencyIndex {
	return &IdempotencyIndex{
		entries:      make(map[string]idempotencyEntry),
		durableSlots: make([]durableIdempotencySlot, defaultDurableIdempotencyCapacity),
		locks:        make(map[string]*keyedLock),
	}
}

// acquire serializes writers for a given idempotency key. Concurrent Submits
// that share the same key will therefore see each other's index writes: the
// first one to reach this point does the WAL append, and any later request
// will observe the first one's entry in Lookup. The returned release function
// must always be called even after Put so the per-key mutex can be garbage
// collected when no writers remain.
func (i *IdempotencyIndex) acquire(key string) func() {
	i.locksMu.Lock()
	lk, ok := i.locks[key]
	if !ok {
		lk = &keyedLock{}
		i.locks[key] = lk
	}
	lk.refs++
	i.locksMu.Unlock()

	lk.mu.Lock()
	return func() {
		lk.mu.Unlock()
		i.locksMu.Lock()
		lk.refs--
		if lk.refs == 0 {
			delete(i.locks, key)
		}
		i.locksMu.Unlock()
	}
}

// Lookup returns the cached entry for the given key, if any.
func (i *IdempotencyIndex) Lookup(key string) (idempotencyEntry, bool) {
	i.entriesMu.RLock()
	defer i.entriesMu.RUnlock()
	entry, ok := i.entries[key]
	return cloneIdempotencyEntry(entry), ok
}

// put stores an entry for the given key, overwriting any previous value. It
// is the caller's responsibility to hold the acquire() lock for the same key
// so that concurrent writers cannot race.
func (i *IdempotencyIndex) put(key string, entry idempotencyEntry) {
	i.entriesMu.Lock()
	defer i.entriesMu.Unlock()
	entry.durable = false
	entry.durableEpoch = 0
	i.entries[key] = cloneIdempotencyEntry(entry)
}

func (i *IdempotencyIndex) putDurable(key string, entry idempotencyEntry) {
	i.entriesMu.Lock()
	defer i.entriesMu.Unlock()
	i.putDurableLocked(key, entry)
}

func (i *IdempotencyIndex) putDurableLocked(key string, entry idempotencyEntry) {
	if len(i.durableSlots) == 0 {
		return
	}
	evicted := i.durableSlots[i.durableNext]
	if evicted.epoch != 0 {
		if existing, ok := i.entries[evicted.key]; ok &&
			existing.durable && existing.durableEpoch == evicted.epoch {
			delete(i.entries, evicted.key)
		}
	}
	i.nextDurableEpoch++
	if i.nextDurableEpoch == 0 {
		i.nextDurableEpoch++
	}
	entry.durable = true
	entry.durableEpoch = i.nextDurableEpoch
	i.entries[key] = cloneIdempotencyEntry(entry)
	i.durableSlots[i.durableNext] = durableIdempotencySlot{key: key, epoch: entry.durableEpoch}
	i.durableNext = (i.durableNext + 1) % len(i.durableSlots)
}

// Remember loads an existing entry for the same claim or installs a new one.
// Callers pass the freshly computed claim hash so the index can detect
// conflicts between different claims that reuse the same key. The build
// function only runs when the key is previously unknown and holds the per-key
// lock so concurrent Submits for the same key are serialized.
//
// Return values:
//   - loaded == true  -> the returned record/accepted are the ones that were
//     stored the first time this key was seen and the caller should return
//     them as-is.
//   - conflict == true -> an entry exists but its claim hash differs from the
//     one supplied here; the caller must surface CodeAlreadyExists.
//   - otherwise       -> build was invoked, its result was stored in the
//     index, and the caller should return it.
func (i *IdempotencyIndex) Remember(
	key string,
	claimHash []byte,
	build func() (model.ServerRecord, model.AcceptedReceipt, error),
) (record model.ServerRecord, accepted model.AcceptedReceipt, loaded bool, conflict bool, err error) {
	return i.RememberDurable(context.Background(), key, model.IdempotencyIdentity{}, claimHash, nil, build)
}

// RememberDurable is Remember with a cold-miss lookup in the committed
// proofstore projection. The read occurs under the per-key lock, so concurrent
// retries cannot both miss storage and append duplicate WAL records. Durable
// hits enter a fixed-size FIFO cache, so hot retries avoid repeated storage IO
// without letting committed history grow this process-local map without bound.
func (i *IdempotencyIndex) RememberDurable(
	ctx context.Context,
	key string,
	identity model.IdempotencyIdentity,
	claimHash []byte,
	durable DurableIdempotencyReader,
	build func() (model.ServerRecord, model.AcceptedReceipt, error),
) (record model.ServerRecord, accepted model.AcceptedReceipt, loaded bool, conflict bool, err error) {
	if key == "" {
		record, accepted, err = build()
		return record, accepted, false, false, err
	}
	release := i.acquire(key)
	defer release()

	if existing, ok := i.Lookup(key); ok {
		if !bytes.Equal(existing.claimHash, claimHash) {
			return model.ServerRecord{}, model.AcceptedReceipt{}, false, true, nil
		}
		return existing.record, existing.accepted, true, false, nil
	}
	if durable != nil {
		decision, found, readErr := durable.GetIdempotencyDecision(ctx, identity)
		if readErr != nil {
			return model.ServerRecord{}, model.AcceptedReceipt{}, false, false, fmt.Errorf("app: read durable idempotency decision: %w", readErr)
		}
		if found {
			if validateErr := durableidempotency.ValidateDecision(identity, decision); validateErr != nil {
				return model.ServerRecord{}, model.AcceptedReceipt{}, false, false, trusterr.Wrap(
					trusterr.CodeDataLoss,
					"validate durable idempotency decision",
					validateErr,
				)
			}
			if !bytes.Equal(decision.ClaimHash, claimHash) {
				i.putDurable(key, idempotencyEntry{record: decision.Record, accepted: decision.Accepted, claimHash: decision.ClaimHash})
				return model.ServerRecord{}, model.AcceptedReceipt{}, false, true, nil
			}
			i.putDurable(key, idempotencyEntry{record: decision.Record, accepted: decision.Accepted, claimHash: decision.ClaimHash})
			return decision.Record, decision.Accepted, true, false, nil
		}
	}
	record, accepted, err = build()
	if err != nil {
		return model.ServerRecord{}, model.AcceptedReceipt{}, false, false, err
	}
	i.put(key, idempotencyEntry{record: record, accepted: accepted, claimHash: claimHash})
	return record, accepted, false, false, nil
}

// RememberDurableRecord serializes an unkeyed exact retry by deterministic
// record ID and resolves committed history with one proof-bundle point read.
func (i *IdempotencyIndex) RememberDurableRecord(
	ctx context.Context,
	key string,
	recordID string,
	claimHash []byte,
	durable DurableRecordReader,
	build func() (model.ServerRecord, model.AcceptedReceipt, error),
) (record model.ServerRecord, accepted model.AcceptedReceipt, loaded bool, conflict bool, err error) {
	if key == "" || recordID == "" {
		record, accepted, err = build()
		return record, accepted, false, false, err
	}
	release := i.acquire(key)
	defer release()

	if existing, ok := i.Lookup(key); ok {
		if !bytes.Equal(existing.claimHash, claimHash) {
			return model.ServerRecord{}, model.AcceptedReceipt{}, false, true, nil
		}
		return existing.record, existing.accepted, true, false, nil
	}
	if durable != nil {
		bundle, readErr := durable.GetBundle(ctx, recordID)
		if readErr == nil {
			if bundle.RecordID != recordID || bundle.ServerRecord.RecordID != recordID || bundle.AcceptedReceipt.RecordID != recordID ||
				!bytes.Equal(bundle.ServerRecord.ClaimHash, claimHash) {
				return model.ServerRecord{}, model.AcceptedReceipt{}, false, false, trusterr.New(
					trusterr.CodeDataLoss,
					"durable record does not match deterministic record id",
				)
			}
			i.putDurable(key, idempotencyEntry{record: bundle.ServerRecord, accepted: bundle.AcceptedReceipt, claimHash: claimHash})
			return bundle.ServerRecord, bundle.AcceptedReceipt, true, false, nil
		}
		if trusterr.CodeOf(readErr) != trusterr.CodeNotFound {
			return model.ServerRecord{}, model.AcceptedReceipt{}, false, false, fmt.Errorf("app: read durable record: %w", readErr)
		}
	}
	record, accepted, err = build()
	if err != nil {
		return model.ServerRecord{}, model.AcceptedReceipt{}, false, false, err
	}
	i.put(key, idempotencyEntry{record: record, accepted: accepted, claimHash: claimHash})
	return record, accepted, false, false, nil
}

// ForgetCommitted converts an accepted entry into the bounded durable cache
// after the same response has been atomically published with its manifest.
func (i *IdempotencyIndex) ForgetCommitted(key, recordID string) {
	if key == "" || recordID == "" {
		return
	}
	release := i.acquire(key)
	defer release()

	i.entriesMu.Lock()
	defer i.entriesMu.Unlock()
	if existing, ok := i.entries[key]; ok && existing.record.RecordID == recordID && !existing.durable {
		i.putDurableLocked(key, existing)
	}
}

// Remembered lets replay paths repopulate the index without going through the
// build callback. Replays are single-threaded so no key lock is required.
func (i *IdempotencyIndex) Remembered(key string, record model.ServerRecord, accepted model.AcceptedReceipt, claimHash []byte) {
	_ = i.Restore(key, record, accepted, claimHash)
}

// Restore repopulates one durable idempotency decision during startup. It
// returns false when the key was already restored with a different claim or
// WAL position, allowing recovery to fail closed instead of silently letting
// scan order choose which duplicate survives. An empty key needs no entry and
// is always consistent.
func (i *IdempotencyIndex) Restore(key string, record model.ServerRecord, accepted model.AcceptedReceipt, claimHash []byte) bool {
	if key == "" {
		return true
	}
	i.entriesMu.Lock()
	defer i.entriesMu.Unlock()
	if existing, ok := i.entries[key]; ok {
		consistent := bytes.Equal(existing.claimHash, claimHash) &&
			existing.record.RecordID == record.RecordID &&
			existing.record.WAL == record.WAL &&
			existing.accepted.RecordID == accepted.RecordID &&
			existing.accepted.WAL == accepted.WAL
		if consistent && existing.durable {
			existing.durable = false
			existing.durableEpoch = 0
			i.entries[key] = existing
		}
		return consistent
	}
	i.entries[key] = cloneIdempotencyEntry(idempotencyEntry{
		record:    record,
		accepted:  accepted,
		claimHash: claimHash,
	})
	return true
}

// Size reports the number of stored entries; exposed for tests and metrics.
func (i *IdempotencyIndex) Size() int {
	i.entriesMu.RLock()
	defer i.entriesMu.RUnlock()
	return len(i.entries)
}

// IdempotencyKey derives the composite key used for explicit client replay
// protection. Empty idempotency_key has no composite key; LocalEngine falls
// back to RecordIDKey for exact-retry protection.
func IdempotencyKey(tenantID, clientID, idempotencyKey string) string {
	if idempotencyKey == "" {
		return ""
	}
	return tenantID + "\x00" + clientID + "\x00" + idempotencyKey
}

// RecordIDKey derives the disjoint process-local key used to deduplicate exact
// retries when a client omits idempotency_key. Retained WAL replay restores
// these entries, so restart does not require a proofstore history scan.
func RecordIDKey(recordID string) string {
	if recordID == "" {
		return ""
	}
	return "\x01" + recordID
}

func cloneIdempotencyEntry(entry idempotencyEntry) idempotencyEntry {
	entry.claimHash = append([]byte(nil), entry.claimHash...)
	entry.record.ClaimHash = append([]byte(nil), entry.record.ClaimHash...)
	entry.record.ClientSignatureHash = append([]byte(nil), entry.record.ClientSignatureHash...)
	entry.accepted.ServerSig.Signature = append([]byte(nil), entry.accepted.ServerSig.Signature...)
	return entry
}
