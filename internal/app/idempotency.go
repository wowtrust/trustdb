package app

import (
	"bytes"
	"sync"

	"github.com/ryan-wong-coder/trustdb/internal/model"
)

// IdempotencyIndex tracks already-accepted claims keyed by their
// (tenant_id, client_id, idempotency_key) triple as required by the design
// document §24.4. Submits that share the same key and produce an identical
// ClientClaim must converge to the exact same ServerRecord/AcceptedReceipt
// pair. Submits that share the same key but carry a different claim must be
// rejected with CodeAlreadyExists so callers cannot silently shadow an
// earlier record by reusing its idempotency_key.
//
// The index is only a fast lookup layer: the WAL is still the durable source
// of truth, so on restart replayWALAccepted will scan the WAL once and repopulate
// the index before the ingest service begins serving traffic.
type IdempotencyIndex struct {
	entriesMu sync.RWMutex
	entries   map[string]idempotencyEntry

	locksMu sync.Mutex
	locks   map[string]*keyedLock
}

type idempotencyEntry struct {
	record    model.ServerRecord
	accepted  model.AcceptedReceipt
	claimHash []byte
}

type keyedLock struct {
	mu   sync.Mutex
	refs int
}

// NewIdempotencyIndex returns an empty in-memory index ready for use.
func NewIdempotencyIndex() *IdempotencyIndex {
	return &IdempotencyIndex{
		entries: make(map[string]idempotencyEntry),
		locks:   make(map[string]*keyedLock),
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
	return entry, ok
}

// put stores an entry for the given key, overwriting any previous value. It
// is the caller's responsibility to hold the acquire() lock for the same key
// so that concurrent writers cannot race.
func (i *IdempotencyIndex) put(key string, entry idempotencyEntry) {
	i.entriesMu.Lock()
	defer i.entriesMu.Unlock()
	i.entries[key] = entry
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
	record, accepted, err = build()
	if err != nil {
		return model.ServerRecord{}, model.AcceptedReceipt{}, false, false, err
	}
	i.put(key, idempotencyEntry{record: record, accepted: accepted, claimHash: claimHash})
	return record, accepted, false, false, nil
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
		return bytes.Equal(existing.claimHash, claimHash) &&
			existing.record.RecordID == record.RecordID &&
			existing.record.WAL == record.WAL &&
			existing.accepted.RecordID == accepted.RecordID &&
			existing.accepted.WAL == accepted.WAL
	}
	i.entries[key] = idempotencyEntry{
		record:    record,
		accepted:  accepted,
		claimHash: append([]byte(nil), claimHash...),
	}
	return true
}

// Size reports the number of stored entries; exposed for tests and metrics.
func (i *IdempotencyIndex) Size() int {
	i.entriesMu.RLock()
	defer i.entriesMu.RUnlock()
	return len(i.entries)
}

// IdempotencyKey derives the composite key used by the index. Empty
// idempotency_key means the client opted out of replay protection, and the
// engine will skip the index entirely.
func IdempotencyKey(tenantID, clientID, idempotencyKey string) string {
	if idempotencyKey == "" {
		return ""
	}
	return tenantID + "\x00" + clientID + "\x00" + idempotencyKey
}
