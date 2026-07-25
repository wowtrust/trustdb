package adminauth

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func testNow() time.Time {
	return time.Date(2026, time.July, 25, 8, 0, 0, 0, time.UTC)
}

func testPolicy(t *testing.T) Policy {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("correct horse battery staple"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return Policy{
		SchemaVersion: PolicySchema,
		Version:       1,
		Accounts: []Account{
			{ID: "audit", Username: "audit", PasswordHash: string(hash), Roles: []Role{RoleAuditAdmin}, SessionEpoch: 1},
			{ID: "security", Username: "security", PasswordHash: string(hash), Roles: []Role{RoleSecurityAdmin}, SessionEpoch: 1},
			{ID: "system", Username: "system", PasswordHash: string(hash), Roles: []Role{RoleSystemAdmin}, SessionEpoch: 1},
		},
	}
}

func TestPolicyValidationRequiresAdministrativeSeparation(t *testing.T) {
	t.Parallel()

	policy := testPolicy(t)
	policy.Accounts[1].Roles = []Role{RoleAuditAdmin, RoleSecurityAdmin}
	if err := policy.Validate(testNow()); err == nil || !strings.Contains(err.Error(), "separate ordinary accounts") {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestPolicyValidationRequiresActiveSeparatedAdministrators(t *testing.T) {
	t.Parallel()

	policy := testPolicy(t)
	policy.Accounts[0].Disabled = true
	if err := policy.Validate(testNow()); err == nil || !strings.Contains(err.Error(), "audit-admin") {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestEmergencyAccountMustBeBounded(t *testing.T) {
	t.Parallel()

	policy := testPolicy(t)
	policy.Accounts = append(policy.Accounts, Account{
		ID: "zz-emergency", Username: "breakglass", PasswordHash: policy.Accounts[0].PasswordHash,
		Roles: []Role{RoleEmergencyAdmin}, Emergency: true, SessionEpoch: 1,
		NotBefore: testNow().Format(time.RFC3339), NotAfter: testNow().Add(25 * time.Hour).Format(time.RFC3339),
	})
	if err := policy.Validate(testNow()); err == nil || !strings.Contains(err.Error(), "at most 24h") {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestParsePolicyRejectsUnknownAndTrailingJSON(t *testing.T) {
	t.Parallel()

	policy := testPolicy(t)
	data, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePolicy(append(data, []byte(` {}`)...), testNow()); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("ParsePolicy(trailing) error = %v", err)
	}
	data = []byte(strings.Replace(string(data), `"version":1`, `"version":1,"unexpected":true`, 1))
	if _, err := ParsePolicy(data, testNow()); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("ParsePolicy(unknown) error = %v", err)
	}
}

func TestCanonicalPolicyDigestIsStable(t *testing.T) {
	t.Parallel()

	policy := testPolicy(t)
	first, err := policy.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePolicy(first, testNow())
	if err != nil {
		t.Fatal(err)
	}
	second, err := parsed.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatalf("canonical encoding changed\nfirst=%s\nsecond=%s", first, second)
	}
	digest1, _ := policy.Digest()
	digest2, _ := parsed.Digest()
	if digest1 != digest2 {
		t.Fatalf("digest changed: %s != %s", digest1, digest2)
	}
}

func TestManagerLocalAuthenticationAndAuthorization(t *testing.T) {
	t.Parallel()

	manager, err := NewManager(testPolicy(t), testNow())
	if err != nil {
		t.Fatal(err)
	}
	principal, err := manager.AuthenticateLocal("SYSTEM", "correct horse battery staple", testNow())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Authorize(principal, PermissionSystemConfigure, testNow()); err != nil {
		t.Fatalf("Authorize(system.configure) = %v", err)
	}
	if _, err := manager.Authorize(principal, PermissionSecurityPolicyWrite, testNow()); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("Authorize(security.policy.write) = %v", err)
	}
	if _, err := manager.AuthenticateLocal("system", "wrong", testNow()); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("AuthenticateLocal(wrong) = %v", err)
	}
}

func TestPolicyReplacementInvalidatesExistingPrincipal(t *testing.T) {
	t.Parallel()

	policy := testPolicy(t)
	manager, err := NewManager(policy, testNow())
	if err != nil {
		t.Fatal(err)
	}
	principal, err := manager.AuthenticateLocal("system", "correct horse battery staple", testNow())
	if err != nil {
		t.Fatal(err)
	}
	policy.Version++
	policy.Accounts[2].SessionEpoch++
	if err := manager.Replace(policy, testNow()); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Authorize(principal, PermissionSystemRead, testNow()); !errors.Is(err, ErrPolicyChanged) {
		t.Fatalf("Authorize(stale) = %v", err)
	}
}

func TestValidateOnlineUpdateProtectsActorAndEmergencyAccounts(t *testing.T) {
	t.Parallel()

	current := testPolicy(t)
	manager, err := NewManager(current, testNow())
	if err != nil {
		t.Fatal(err)
	}
	actor, err := manager.AuthenticateLocal("security", "correct horse battery staple", testNow())
	if err != nil {
		t.Fatal(err)
	}
	next := current.Clone()
	next.Version++
	next.Accounts = append(next.Accounts, Account{})
	copy(next.Accounts[3:], next.Accounts[2:])
	next.Accounts[2] = Account{
		ID: "support", Username: "support", PasswordHash: current.Accounts[0].PasswordHash,
		Roles: []Role{RoleSupportReadOnly}, SessionEpoch: 1,
	}
	if err := ValidateOnlineUpdate(actor, current, next, testNow()); err != nil {
		t.Fatalf("ValidateOnlineUpdate(other account) = %v", err)
	}
	next = current.Clone()
	next.Version++
	next.Accounts[2].Description = "security attempted to seize system custody"
	if err := ValidateOnlineUpdate(actor, current, next, testNow()); err == nil || !strings.Contains(err.Error(), "system and audit") {
		t.Fatalf("ValidateOnlineUpdate(system custody) = %v", err)
	}
	next = current.Clone()
	next.Version++
	next.Accounts[1].Description = "self change"
	if err := ValidateOnlineUpdate(actor, current, next, testNow()); err == nil || !strings.Contains(err.Error(), "own account") {
		t.Fatalf("ValidateOnlineUpdate(self) = %v", err)
	}

	emergency := Account{
		ID: "zz-emergency", Username: "breakglass", PasswordHash: current.Accounts[0].PasswordHash,
		Roles: []Role{RoleEmergencyAdmin}, Emergency: true, SessionEpoch: 1,
		NotBefore: testNow().Format(time.RFC3339), NotAfter: testNow().Add(time.Hour).Format(time.RFC3339),
	}
	current.Accounts = append(current.Accounts, emergency)
	manager, err = NewManager(current, testNow())
	if err != nil {
		t.Fatal(err)
	}
	actor, err = manager.AuthenticateLocal("security", "correct horse battery staple", testNow())
	if err != nil {
		t.Fatal(err)
	}
	next = current.Clone()
	next.Version++
	next.Accounts[3].Description = "changed online"
	if err := ValidateOnlineUpdate(actor, current, next, testNow()); err == nil || !strings.Contains(err.Error(), "offline recovery") {
		t.Fatalf("ValidateOnlineUpdate(emergency) = %v", err)
	}
}

func TestManagerMTLSAndOIDCAuthenticationHooks(t *testing.T) {
	t.Parallel()

	policy := testPolicy(t)
	spki := []byte("test-spki")
	pin := sha256.Sum256(spki)
	policy.Accounts[2].MTLSSPKISHA256 = []string{strings.ToLower(strings.ReplaceAll(strings.TrimSpace(stringHex(pin[:])), " ", ""))}
	policy.Accounts[2].OIDCSubjects = []ExternalSubject{{Issuer: "https://identity.example", Subject: "operator-123"}}
	manager, err := NewManager(policy, testNow())
	if err != nil {
		t.Fatal(err)
	}
	principal, err := manager.AuthenticateMTLS(&x509.Certificate{RawSubjectPublicKeyInfo: spki}, testNow())
	if err != nil || principal.AuthMethod != AuthMethodMTLS {
		t.Fatalf("AuthenticateMTLS() principal=%+v err=%v", principal, err)
	}
	principal, err = manager.AuthenticateOIDC("https://identity.example", "operator-123", testNow())
	if err != nil || principal.AuthMethod != AuthMethodOIDC {
		t.Fatalf("AuthenticateOIDC() principal=%+v err=%v", principal, err)
	}
}

func stringHex(value []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(value)*2)
	for i, b := range value {
		out[i*2] = digits[b>>4]
		out[i*2+1] = digits[b&0xf]
	}
	return string(out)
}
