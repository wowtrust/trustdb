package adminweb

import (
	"strings"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/adminauth"
)

func TestVerifySessionTokenExpirationBoundary(t *testing.T) {
	t.Parallel()

	secret := []byte(strings.Repeat("s", 32))
	issuedAt := time.Unix(1_700_000_000, 0).UTC()
	ttl := time.Hour
	principal := adminauth.Principal{
		AccountID: "admin", Username: "admin", Roles: []adminauth.Role{adminauth.RoleSystemAdmin},
		AuthMethod: adminauth.AuthMethodLocal, PolicyVersion: 1, PolicyDigest: strings.Repeat("a", 64), SessionEpoch: 1,
	}
	token, err := issueSessionTokenAt(secret, principal, "", ttl, issuedAt)
	if err != nil {
		t.Fatalf("issueSessionTokenAt: %v", err)
	}

	if got, _, ok := verifySessionTokenAt(secret, token, issuedAt.Add(ttl-time.Second)); !ok || got.Username != "admin" {
		t.Fatalf("token before expiration: principal=%+v ok=%v", got, ok)
	}
	if got, _, ok := verifySessionTokenAt(secret, token, issuedAt.Add(ttl)); ok || got.Username != "" {
		t.Fatalf("token at expiration: principal=%+v ok=%v", got, ok)
	}
	if got, _, ok := verifySessionTokenAt(secret, token, issuedAt.Add(ttl+time.Second)); ok || got.Username != "" {
		t.Fatalf("token after expiration: principal=%+v ok=%v", got, ok)
	}
}
