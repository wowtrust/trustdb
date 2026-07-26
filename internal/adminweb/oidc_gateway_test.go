package adminweb

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/v2/internal/adminauth"
)

func TestMTLSGatewayOIDCVerifierAndMFAAssertion(t *testing.T) {
	t.Parallel()

	spki := []byte("trusted-oidc-gateway-spki")
	digest := sha256.Sum256(spki)
	verifier, err := NewMTLSGatewayOIDCVerifier([]string{hex.EncodeToString(digest[:])})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "/api/config", nil)
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{RawSubjectPublicKeyInfo: spki}}}
	request.Header.Set(oidcIssuerHeader, "https://identity.example")
	request.Header.Set(oidcSubjectHeader, "operator-123")
	request.Header.Set(oidcMFAHeader, "true")
	identity, err := verifier.VerifyOIDC(request)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Issuer != "https://identity.example" || identity.Subject != "operator-123" || !identity.MFA {
		t.Fatalf("identity=%+v", identity)
	}

	dir := t.TempDir()
	auth, store := testAdminAuthorization(t, dir, "system", "secret")
	policy, currentDigest := auth.Snapshot()
	policy.Version++
	policy.Accounts[2].OIDCSubjects = []adminauth.ExternalSubject{{Issuer: identity.Issuer, Subject: identity.Subject}}
	policy.Accounts[2].MFARequired = true
	if _, err := store.ReplaceOffline(currentDigest, policy, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := auth.Replace(policy, time.Now()); err != nil {
		t.Fatal(err)
	}
	handler := &handler{opts: Options{Auth: auth, OIDCVerifier: verifier, Now: time.Now}}
	principal, _, err := handler.authenticatedPrincipal(request)
	if err != nil || principal.AuthMethod != adminauth.AuthMethodOIDC || principal.AccountID != "system" {
		t.Fatalf("authenticatedPrincipal() principal=%+v err=%v", principal, err)
	}

	requestWithoutMFA := request.Clone(request.Context())
	requestWithoutMFA.TLS = request.TLS
	requestWithoutMFA.Header.Set(oidcMFAHeader, "false")
	if _, _, err := handler.authenticatedPrincipal(requestWithoutMFA); err == nil {
		t.Fatal("authenticatedPrincipal() accepted missing MFA assertion")
	}
}
