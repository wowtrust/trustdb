package trustcrypto

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/wowtrust/trustdb/internal/model"
)

func TestHashBytesSHA256MatchesStandardAndOwnsResult(t *testing.T) {
	t.Parallel()

	raw := []byte("trustdb hash ownership")
	got, err := HashBytes(model.DefaultHashAlg, raw)
	if err != nil {
		t.Fatalf("HashBytes: %v", err)
	}
	want := sha256.Sum256(raw)
	if !bytes.Equal(got, want[:]) {
		t.Fatalf("HashBytes() = %x, want %x", got, want)
	}
	got[0] ^= 0xff
	again, err := HashBytes(model.DefaultHashAlg, raw)
	if err != nil {
		t.Fatalf("HashBytes again: %v", err)
	}
	if !bytes.Equal(again, want[:]) {
		t.Fatalf("second HashBytes() = %x, want independent %x", again, want)
	}
}

func TestHashBytesRejectsUnsupportedAlgorithm(t *testing.T) {
	t.Parallel()

	if _, err := HashBytes("sha512", []byte("trustdb")); err == nil {
		t.Fatal("HashBytes() error = nil, want unsupported algorithm")
	}
}
