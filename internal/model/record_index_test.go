package model

import (
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"unicode"
)

func TestRecordIndexStorageTokensMatchesReference(t *testing.T) {
	t.Parallel()

	tests := []RecordIndex{
		{},
		{FileName: " evidence-final.PDF ", StorageURI: "s3://tenant/Evidence-Final.PDF"},
		{FileName: "AB-cd", StorageURI: "scheme://AB"},
		{FileName: "你好世界", StorageURI: "证据://你好世界"},
		{FileName: "a-你-1", StorageURI: ""},
		{FileName: "abcdefghijklmnopqrstuvwxyz", StorageURI: "0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ"},
		{FileName: "résumé-Δοκιμή-файл", StorageURI: "file:///tmp/证据.json"},
	}
	for _, idx := range tests {
		idx := idx
		t.Run(idx.FileName+"|"+idx.StorageURI, func(t *testing.T) {
			t.Parallel()
			got := RecordIndexStorageTokens(idx)
			want := referenceRecordIndexStorageTokens(idx)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("RecordIndexStorageTokens() = %#v, want %#v", got, want)
			}
		})
	}
}

func TestRecordIndexStorageTokensMatchesReferenceRandomized(t *testing.T) {
	t.Parallel()

	rng := rand.New(rand.NewSource(1))
	alphabet := []rune("abcXYZ019 -_./:你好世界Δοκιμήrésuméфайл")
	field := func() string {
		runes := make([]rune, rng.Intn(80))
		for i := range runes {
			runes[i] = alphabet[rng.Intn(len(alphabet))]
		}
		return string(runes)
	}
	for i := 0; i < 1_000; i++ {
		idx := RecordIndex{FileName: field(), StorageURI: field()}
		got := RecordIndexStorageTokens(idx)
		want := referenceRecordIndexStorageTokens(idx)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("case %d: RecordIndexStorageTokens(%+v) = %#v, want %#v", i, idx, got, want)
		}
	}
}

func TestRecordIndexStorageTokensLimitAndUniqueness(t *testing.T) {
	t.Parallel()

	tokens := RecordIndexStorageTokens(RecordIndex{
		FileName:   "abcdefghijklmnopqrstuvwxyz",
		StorageURI: "0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	})
	if len(tokens) != maxRecordStorageIndexTokens {
		t.Fatalf("len(tokens) = %d, want %d", len(tokens), maxRecordStorageIndexTokens)
	}
	seen := make(map[string]struct{}, len(tokens))
	for _, token := range tokens {
		if _, ok := seen[token]; ok {
			t.Fatalf("duplicate token %q", token)
		}
		seen[token] = struct{}{}
	}
}

func referenceRecordIndexStorageTokens(idx RecordIndex) []string {
	rawTokens := append(referenceRecordSearchTokens(idx.FileName), referenceRecordSearchTokens(idx.StorageURI)...)
	if len(rawTokens) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(rawTokens)*3)
	out := make([]string, 0, len(rawTokens)*3)
	add := func(token string) {
		if token == "" {
			return
		}
		if _, ok := seen[token]; ok {
			return
		}
		seen[token] = struct{}{}
		out = append(out, token)
	}
	for _, token := range rawTokens {
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

func referenceRecordSearchTokens(value string) []string {
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
