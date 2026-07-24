package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	pdb "github.com/cockroachdb/pebble"
)

const (
	localRecordPrefixValue  = "rec/"
	localRecordPrefixTime   = "idx/time/"
	localRecordPrefixLevel  = "idx/level/"
	localRecordPrefixBatch  = "idx/batch/"
	localRecordPrefixTenant = "idx/tenant/"
	localRecordPrefixClient = "idx/client/"
	localRecordPrefixHash   = "idx/hash/"
	localRecordPrefixToken  = "idx/token/"
	localRecordPrefixCount  = "cnt/"
	localRecordCountAll     = "cnt/all"
	localRecordMetaMigrated = "meta/migrated-jsonl-v1"
	localRecordMaxSort      = int64(1<<63 - 1)
	maxLocalRecordTokens    = 48
)

type localRecordDB struct {
	db *pdb.DB
}

func openLocalRecordDB(path string) (*localRecordDB, error) {
	db, err := pdb.Open(path, &pdb.Options{})
	if err != nil {
		return nil, err
	}
	return &localRecordDB{db: db}, nil
}

func (d *localRecordDB) close() error {
	if d == nil || d.db == nil {
		return nil
	}
	return d.db.Close()
}

func (d *localRecordDB) migrated() (bool, error) {
	_, closer, err := d.db.Get([]byte(localRecordMetaMigrated))
	if err != nil {
		if errors.Is(err, pdb.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	closer.Close()
	return true, nil
}

func (d *localRecordDB) markMigrated() error {
	return d.db.Set([]byte(localRecordMetaMigrated), []byte("1"), pdb.Sync)
}

func (d *localRecordDB) get(recordID string) (LocalRecord, bool, error) {
	if recordID == "" {
		return LocalRecord{}, false, nil
	}
	value, closer, err := d.db.Get(localRecordKey(recordID))
	if err != nil {
		if errors.Is(err, pdb.ErrNotFound) {
			return LocalRecord{}, false, nil
		}
		return LocalRecord{}, false, err
	}
	defer closer.Close()
	var rec LocalRecord
	if err := json.Unmarshal(value, &rec); err != nil {
		return LocalRecord{}, false, err
	}
	return rec, true, nil
}

func (d *localRecordDB) upsert(rec LocalRecord) error {
	if rec.RecordID == "" {
		return nil
	}
	old, oldOK, err := d.get(rec.RecordID)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	batch := d.db.NewBatch()
	defer batch.Close()
	if oldOK {
		if err := d.stageDeleteIndexes(batch, old); err != nil {
			return err
		}
	} else if err := d.stageCounterDelta(batch, localRecordCountAll, 1); err != nil {
		return err
	}
	if oldOK && old.ProofLevel != rec.ProofLevel {
		if old.ProofLevel != "" {
			if err := d.stageCounterDelta(batch, localRecordLevelCountKey(old.ProofLevel), -1); err != nil {
				return err
			}
		}
		if rec.ProofLevel != "" {
			if err := d.stageCounterDelta(batch, localRecordLevelCountKey(rec.ProofLevel), 1); err != nil {
				return err
			}
		}
	} else if !oldOK && rec.ProofLevel != "" {
		if err := d.stageCounterDelta(batch, localRecordLevelCountKey(rec.ProofLevel), 1); err != nil {
			return err
		}
	}
	if err := batch.Set(localRecordKey(rec.RecordID), raw, nil); err != nil {
		return err
	}
	if err := d.stagePutIndexes(batch, rec); err != nil {
		return err
	}
	return batch.Commit(pdb.Sync)
}

func (d *localRecordDB) upsertMany(records []LocalRecord) error {
	const chunkSize = 500
	for start := 0; start < len(records); start += chunkSize {
		end := start + chunkSize
		if end > len(records) {
			end = len(records)
		}
		batch := d.db.NewBatch()
		for _, rec := range records[start:end] {
			if rec.RecordID == "" {
				continue
			}
			old, oldOK, err := d.get(rec.RecordID)
			if err != nil {
				_ = batch.Close()
				return err
			}
			if oldOK {
				if err := d.stageDeleteIndexes(batch, old); err != nil {
					_ = batch.Close()
					return err
				}
			}
			raw, err := json.Marshal(rec)
			if err != nil {
				_ = batch.Close()
				return err
			}
			if err := batch.Set(localRecordKey(rec.RecordID), raw, nil); err != nil {
				_ = batch.Close()
				return err
			}
			if err := d.stagePutIndexes(batch, rec); err != nil {
				_ = batch.Close()
				return err
			}
		}
		if err := batch.Commit(nil); err != nil {
			_ = batch.Close()
			return err
		}
		if err := batch.Close(); err != nil {
			return err
		}
	}
	return d.rebuildCounters()
}

func (d *localRecordDB) delete(recordID string) error {
	old, ok, err := d.get(recordID)
	if err != nil || !ok {
		return err
	}
	batch := d.db.NewBatch()
	defer batch.Close()
	if err := batch.Delete(localRecordKey(recordID), nil); err != nil {
		return err
	}
	if err := d.stageDeleteIndexes(batch, old); err != nil {
		return err
	}
	if err := d.stageCounterDelta(batch, localRecordCountAll, -1); err != nil {
		return err
	}
	if old.ProofLevel != "" {
		if err := d.stageCounterDelta(batch, localRecordLevelCountKey(old.ProofLevel), -1); err != nil {
			return err
		}
	}
	return batch.Commit(pdb.Sync)
}

func (d *localRecordDB) listAll() ([]LocalRecord, error) {
	records := make([]LocalRecord, 0)
	err := d.scanIndex(localRecordPrefixTime, "", 0, func(rec LocalRecord) (bool, error) {
		records = append(records, rec)
		return true, nil
	})
	return records, err
}

func (d *localRecordDB) listPage(opts RecordPageOptions) (RecordPage, error) {
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	offset := opts.Offset
	if offset < 0 {
		offset = 0
	}
	prefix, counterKey, exactCounter := localRecordListPrefix(opts)
	items := make([]LocalRecord, 0, limit+1)
	var skipped int
	cursorSuffix := decodeLocalRecordCursor(opts.Cursor)
	err := d.scanIndex(prefix, cursorSuffix, offset, func(rec LocalRecord) (bool, error) {
		if !localRecordMatchesOptions(rec, opts) {
			return true, nil
		}
		if opts.Cursor == "" && skipped < offset {
			skipped++
			return true, nil
		}
		items = append(items, rec)
		return len(items) <= limit, nil
	})
	if err != nil {
		return RecordPage{}, err
	}
	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}
	nextCursor := ""
	if hasMore && len(items) > 0 {
		nextCursor = encodeLocalRecordCursor(localRecordIndexSuffix(items[len(items)-1]))
	}
	totalExact := false
	total := offset + len(items)
	if hasMore {
		total++
	}
	if exactCounter {
		if count, err := d.counter(counterKey); err == nil {
			total = count
			totalExact = true
		}
	}
	return RecordPage{
		Items:      items,
		Total:      total,
		Limit:      limit,
		Offset:     offset,
		HasMore:    hasMore,
		NextCursor: nextCursor,
		Source:     "local",
		TotalExact: totalExact,
	}, nil
}

func (d *localRecordDB) scanIndex(prefix, cursorSuffix string, offset int, visit func(LocalRecord) (bool, error)) error {
	lower, upper := localRecordPrefixBounds(prefix)
	iter, err := d.db.NewIter(&pdb.IterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		return err
	}
	defer iter.Close()
	var ok bool
	if cursorSuffix != "" {
		cursorKey := []byte(prefix + cursorSuffix)
		ok = iter.SeekGE(cursorKey)
		if ok && bytes.Equal(iter.Key(), cursorKey) {
			ok = iter.Next()
		}
	} else {
		ok = iter.First()
	}
	for ; ok; ok = iter.Next() {
		recordID := string(iter.Value())
		rec, found, err := d.get(recordID)
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		keepGoing, err := visit(rec)
		if err != nil {
			return err
		}
		if !keepGoing {
			break
		}
	}
	return iter.Error()
}

func (d *localRecordDB) stagePutIndexes(batch *pdb.Batch, rec LocalRecord) error {
	for _, key := range localRecordIndexKeys(rec) {
		if err := batch.Set([]byte(key), []byte(rec.RecordID), nil); err != nil {
			return err
		}
	}
	return nil
}

func (d *localRecordDB) stageDeleteIndexes(batch *pdb.Batch, rec LocalRecord) error {
	for _, key := range localRecordIndexKeys(rec) {
		if err := batch.Delete([]byte(key), nil); err != nil {
			return err
		}
	}
	return nil
}

func (d *localRecordDB) counter(key string) (int, error) {
	value, closer, err := d.db.Get([]byte(key))
	if err != nil {
		if errors.Is(err, pdb.ErrNotFound) {
			return 0, nil
		}
		return 0, err
	}
	defer closer.Close()
	if len(value) != 8 {
		return 0, fmt.Errorf("invalid counter %s", key)
	}
	return int(binary.BigEndian.Uint64(value)), nil
}

func (d *localRecordDB) stageCounterDelta(batch *pdb.Batch, key string, delta int64) error {
	current, err := d.counter(key)
	if err != nil {
		return err
	}
	next := int64(current) + delta
	if next < 0 {
		next = 0
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(next))
	return batch.Set([]byte(key), append([]byte(nil), buf[:]...), nil)
}

func (d *localRecordDB) rebuildCounters() error {
	counts := map[string]int{localRecordCountAll: 0}
	records, err := d.listAll()
	if err != nil {
		return err
	}
	for _, rec := range records {
		counts[localRecordCountAll]++
		if rec.ProofLevel != "" {
			counts[localRecordLevelCountKey(rec.ProofLevel)]++
		}
	}
	batch := d.db.NewBatch()
	defer batch.Close()
	lower, upper := localRecordPrefixBounds(localRecordPrefixCount)
	iter, err := d.db.NewIter(&pdb.IterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		return err
	}
	for ok := iter.First(); ok; ok = iter.Next() {
		key := append([]byte(nil), iter.Key()...)
		if err := batch.Delete(key, nil); err != nil {
			_ = iter.Close()
			return err
		}
	}
	if err := iter.Error(); err != nil {
		_ = iter.Close()
		return err
	}
	if err := iter.Close(); err != nil {
		return err
	}
	for key, count := range counts {
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], uint64(count))
		if err := batch.Set([]byte(key), append([]byte(nil), buf[:]...), nil); err != nil {
			return err
		}
	}
	return batch.Commit(pdb.Sync)
}

func localRecordKey(recordID string) []byte {
	return []byte(localRecordPrefixValue + recordID)
}

func localRecordLevelCountKey(level string) string {
	return localRecordPrefixCount + "level/" + localRecordPart(level)
}

func localRecordListPrefix(opts RecordPageOptions) (prefix, counterKey string, exactCounter bool) {
	q := strings.TrimSpace(opts.Query)
	switch {
	case localRecordLooksLikeContentHash(q):
		return localRecordPrefixHash + trimContentHashPrefix(q) + "/", "", false
	case localRecordQueryToken(q) != "":
		return localRecordPrefixToken + localRecordPart(localRecordQueryToken(q)) + "/", "", false
	case opts.Level != "":
		return localRecordPrefixLevel + localRecordPart(opts.Level) + "/", localRecordLevelCountKey(opts.Level), true
	case opts.BatchID != "":
		return localRecordPrefixBatch + localRecordPart(opts.BatchID) + "/", "", false
	case opts.TenantID != "":
		return localRecordPrefixTenant + localRecordPart(opts.TenantID) + "/", "", false
	case opts.ClientID != "":
		return localRecordPrefixClient + localRecordPart(opts.ClientID) + "/", "", false
	default:
		return localRecordPrefixTime, localRecordCountAll, q == ""
	}
}

func localRecordIndexKeys(rec LocalRecord) []string {
	if rec.RecordID == "" {
		return nil
	}
	suffix := localRecordIndexSuffix(rec)
	keys := []string{localRecordPrefixTime + suffix}
	if rec.ProofLevel != "" {
		keys = append(keys, localRecordPrefixLevel+localRecordPart(rec.ProofLevel)+"/"+suffix)
	}
	if rec.BatchID != "" {
		keys = append(keys, localRecordPrefixBatch+localRecordPart(rec.BatchID)+"/"+suffix)
	}
	if rec.TenantID != "" {
		keys = append(keys, localRecordPrefixTenant+localRecordPart(rec.TenantID)+"/"+suffix)
	}
	if rec.ClientID != "" {
		keys = append(keys, localRecordPrefixClient+localRecordPart(rec.ClientID)+"/"+suffix)
	}
	if localRecordLooksLikeContentHash(rec.ContentHashHex) {
		keys = append(keys, localRecordPrefixHash+trimContentHashPrefix(rec.ContentHashHex)+"/"+suffix)
	}
	for _, token := range localRecordTokens(rec) {
		keys = append(keys, localRecordPrefixToken+localRecordPart(token)+"/"+suffix)
	}
	return keys
}

func localRecordIndexSuffix(rec LocalRecord) string {
	sortKey := localRecordMaxSort - localRecordSortUnixN(rec)
	if sortKey < 0 {
		sortKey = 0
	}
	return fmt.Sprintf("%020d/%s", sortKey, rec.RecordID)
}

func localRecordSortUnixN(rec LocalRecord) int64 {
	if ts := localRecordTimeUnixN(rec.SubmittedAtUnixN, rec.SubmittedAt); ts != 0 {
		return ts
	}
	if ts := localRecordTimeUnixN(rec.LastSyncedAtUnixN, rec.LastSyncedAt); ts != 0 {
		return ts
	}
	return 0
}

func localRecordPrefixBounds(prefix string) (lower, upper []byte) {
	lower = []byte(prefix)
	upper = append([]byte(prefix), 0xff)
	return lower, upper
}

func localRecordPart(value string) string {
	if value == "" {
		return "_"
	}
	return base64.RawURLEncoding.EncodeToString([]byte(value))
}

func encodeLocalRecordCursor(suffix string) string {
	if suffix == "" {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString([]byte(suffix))
}

func decodeLocalRecordCursor(cursor string) string {
	if cursor == "" {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return ""
	}
	return string(raw)
}

func localRecordMatchesOptions(rec LocalRecord, opts RecordPageOptions) bool {
	if opts.Level != "" && rec.ProofLevel != opts.Level {
		return false
	}
	if opts.BatchID != "" && rec.BatchID != opts.BatchID {
		return false
	}
	if opts.TenantID != "" && rec.TenantID != opts.TenantID {
		return false
	}
	if opts.ClientID != "" && rec.ClientID != opts.ClientID {
		return false
	}
	q := strings.ToLower(strings.TrimSpace(opts.Query))
	return q == "" || recordMatchesQuery(rec, q)
}

func localRecordTokens(rec LocalRecord) []string {
	rawTokens := make([]string, 0, 16)
	rawTokens = append(rawTokens, localRecordSearchTokens(rec.FileName)...)
	rawTokens = append(rawTokens, localRecordSearchTokens(rec.FilePath)...)
	rawTokens = append(rawTokens, localRecordSearchTokens(rec.BatchID)...)
	rawTokens = append(rawTokens, localRecordSearchTokens(rec.RecordID)...)
	rawTokens = append(rawTokens, localRecordSearchTokens(rec.EventType)...)
	seen := make(map[string]struct{}, len(rawTokens)*3)
	out := make([]string, 0, len(rawTokens)*3)
	add := func(token string) bool {
		if token == "" {
			return true
		}
		if _, ok := seen[token]; ok {
			return true
		}
		seen[token] = struct{}{}
		out = append(out, token)
		return len(out) < maxLocalRecordTokens
	}
	for _, token := range rawTokens {
		runes := []rune(token)
		if len(runes) < 2 {
			continue
		}
		if len(runes) <= 4 && !add(token) {
			return out
		}
		for width := 2; width <= 3; width++ {
			if len(runes) < width {
				continue
			}
			for i := 0; i+width <= len(runes); i++ {
				if !add(string(runes[i : i+width])) {
					return out
				}
			}
		}
	}
	return out
}

func localRecordQueryToken(query string) string {
	for _, token := range localRecordSearchTokens(query) {
		if utf8.RuneCountInString(token) < 2 {
			continue
		}
		runes := []rune(token)
		if len(runes) <= 3 {
			return token
		}
		return string(runes[:3])
	}
	return ""
}

func localRecordSearchTokens(value string) []string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return nil
	}
	tokens := make([]string, 0, 8)
	var b strings.Builder
	flush := func() {
		if b.Len() == 0 {
			return
		}
		tokens = append(tokens, b.String())
		b.Reset()
	}
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			continue
		}
		flush()
	}
	flush()
	return tokens
}

func localRecordLooksLikeContentHash(value string) bool {
	value = trimContentHashPrefix(value)
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' && r < 'a' || r > 'f' {
			return false
		}
	}
	return true
}

func trimContentHashPrefix(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "sha256:")
	return strings.TrimPrefix(value, "sm3:")
}
