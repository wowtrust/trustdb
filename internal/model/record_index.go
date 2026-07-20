package model

import (
	"bytes"
	"encoding/hex"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxRecordStorageIndexTokens = 64

// RecordIndexMatchesListOptions is the shared post-filter for record list
// queries. Backends may choose a selective secondary index first, but this
// function keeps exact semantics identical across file and Pebble stores.
func RecordIndexMatchesListOptions(idx RecordIndex, opts RecordListOptions) bool {
	if opts.BatchID != "" && idx.BatchID != opts.BatchID {
		return false
	}
	if opts.TenantID != "" && idx.TenantID != opts.TenantID {
		return false
	}
	if opts.ClientID != "" && idx.ClientID != opts.ClientID {
		return false
	}
	if opts.ProofLevel != "" && RecordIndexProofLevel(idx) != opts.ProofLevel {
		return false
	}
	if len(opts.ContentHash) > 0 && !bytes.Equal(idx.ContentHash, opts.ContentHash) {
		return false
	}
	if opts.ReceivedFromUnixN > 0 && idx.ReceivedAtUnixN < opts.ReceivedFromUnixN {
		return false
	}
	if opts.ReceivedToUnixN > 0 && idx.ReceivedAtUnixN > opts.ReceivedToUnixN {
		return false
	}
	if !RecordIndexMatchesQuery(idx, opts.Query) {
		return false
	}
	return true
}

func RecordIndexAfterCursor(idx RecordIndex, opts RecordListOptions) bool {
	if opts.AfterReceivedAtUnixN == 0 && opts.AfterRecordID == "" {
		return true
	}
	cmp := CompareRecordPosition(idx.ReceivedAtUnixN, idx.RecordID, opts.AfterReceivedAtUnixN, opts.AfterRecordID)
	if strings.EqualFold(opts.Direction, RecordListDirectionAsc) {
		return cmp > 0
	}
	return cmp < 0
}

func CompareRecordPosition(leftTime int64, leftID string, rightTime int64, rightID string) int {
	switch {
	case leftTime < rightTime:
		return -1
	case leftTime > rightTime:
		return 1
	case leftID < rightID:
		return -1
	case leftID > rightID:
		return 1
	default:
		return 0
	}
}

func RecordIndexMatchesQuery(idx RecordIndex, query string) bool {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return true
	}
	values := []string{
		idx.RecordID,
		idx.BatchID,
		idx.TenantID,
		idx.ClientID,
		idx.KeyID,
		idx.StorageURI,
		idx.FileName,
		idx.MediaType,
		idx.EventType,
		idx.Source,
		hex.EncodeToString(idx.ContentHash),
	}
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), query) {
			return true
		}
	}
	return false
}

func RecordStorageQueryToken(query string) string {
	for _, token := range recordSearchTokens(query) {
		if utf8.RuneCountInString(token) < 2 {
			continue
		}
		return recordSearchProbe(token)
	}
	return ""
}

func RecordIndexStorageTokens(idx RecordIndex) []string {
	rawTokens := make([]string, 0, 16)
	rawTokens = appendRecordSearchTokens(rawTokens, idx.FileName)
	rawTokens = appendRecordSearchTokens(rawTokens, idx.StorageURI)
	if len(rawTokens) == 0 {
		return nil
	}
	out := make([]string, 0, maxRecordStorageIndexTokens)
	// The token count is tightly bounded, so a small open-addressed table avoids
	// the per-record allocations of a map while retaining exact deduplication.
	var tokenSlots [maxRecordStorageIndexTokens * 2]uint8
	add := func(token string) {
		if token == "" {
			return
		}
		slot := int(recordStorageTokenHash(token) & uint64(len(tokenSlots)-1))
		for {
			entry := tokenSlots[slot]
			if entry == 0 {
				out = append(out, token)
				tokenSlots[slot] = uint8(len(out))
				return
			}
			if out[int(entry)-1] == token {
				return
			}
			slot = (slot + 1) & (len(tokenSlots) - 1)
		}
	}
	for _, token := range rawTokens {
		if isASCII(token) {
			if len(token) < 2 {
				continue
			}
			if len(token) <= 4 {
				add(token)
			}
			for width := 2; width <= 3; width++ {
				if len(token) < width {
					continue
				}
				for i := 0; i+width <= len(token); i++ {
					add(token[i : i+width])
					if len(out) >= maxRecordStorageIndexTokens {
						return out
					}
				}
			}
			continue
		}
		runes := []rune(token)
		if len(runes) < 2 {
			continue
		}
		if len(runes) <= 4 {
			add(token)
		}
		for width := 2; width <= 3; width++ {
			if len(runes) < width {
				continue
			}
			for i := 0; i+width <= len(runes); i++ {
				add(string(runes[i : i+width]))
				if len(out) >= maxRecordStorageIndexTokens {
					return out
				}
			}
		}
	}
	return out
}

func recordSearchProbe(token string) string {
	runes := []rune(token)
	switch {
	case len(runes) <= 3:
		return token
	default:
		return string(runes[:3])
	}
}

func recordSearchTokens(value string) []string {
	return appendRecordSearchTokens(nil, value)
}

func appendRecordSearchTokens(tokens []string, value string) []string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return tokens
	}
	start := -1
	for i, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			tokens = append(tokens, value[start:i])
			start = -1
		}
	}
	if start >= 0 {
		tokens = append(tokens, value[start:])
	}
	return tokens
}

func isASCII(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

func recordStorageTokenHash(value string) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	hash := uint64(offset64)
	for i := 0; i < len(value); i++ {
		hash ^= uint64(value[i])
		hash *= prime64
	}
	return hash
}
