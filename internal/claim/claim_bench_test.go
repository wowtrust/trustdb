package claim

import (
	"bytes"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
)

func BenchmarkSignClaim(b *testing.B) {
	_, priv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		b.Fatal(err)
	}
	c, err := NewFileClaim(
		"tenant-a",
		"client-a",
		"key-a",
		time.Unix(100, 0),
		bytes.Repeat([]byte{1}, 16),
		"idem-a",
		model.Content{HashAlg: model.DefaultHashAlg, ContentHash: bytes.Repeat([]byte{2}, 32), ContentLength: 128},
		model.Metadata{EventType: "file.snapshot"},
	)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Sign(c, priv); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyClaim(b *testing.B) {
	pub, priv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		b.Fatal(err)
	}
	c, err := NewFileClaim(
		"tenant-a",
		"client-a",
		"key-a",
		time.Unix(100, 0),
		bytes.Repeat([]byte{1}, 16),
		"idem-a",
		model.Content{HashAlg: model.DefaultHashAlg, ContentHash: bytes.Repeat([]byte{2}, 32), ContentLength: 128},
		model.Metadata{EventType: "file.snapshot"},
	)
	if err != nil {
		b.Fatal(err)
	}
	signed, err := Sign(c, priv)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Verify(signed, pub); err != nil {
			b.Fatal(err)
		}
	}
}
