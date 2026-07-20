package adminweb

import (
	"strings"
	"testing"
	"time"
)

func TestVerifySessionTokenExpirationBoundary(t *testing.T) {
	t.Parallel()

	secret := []byte(strings.Repeat("s", 32))
	issuedAt := time.Unix(1_700_000_000, 0).UTC()
	ttl := time.Hour
	token, err := issueSessionTokenAt(secret, "admin", ttl, issuedAt)
	if err != nil {
		t.Fatalf("issueSessionTokenAt: %v", err)
	}

	if user, ok := verifySessionTokenAt(secret, token, issuedAt.Add(ttl-time.Second)); !ok || user != "admin" {
		t.Fatalf("token before expiration: user=%q ok=%v", user, ok)
	}
	if user, ok := verifySessionTokenAt(secret, token, issuedAt.Add(ttl)); ok || user != "" {
		t.Fatalf("token at expiration: user=%q ok=%v", user, ok)
	}
	if user, ok := verifySessionTokenAt(secret, token, issuedAt.Add(ttl+time.Second)); ok || user != "" {
		t.Fatalf("token after expiration: user=%q ok=%v", user, ok)
	}
}
