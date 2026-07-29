package adminweb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/spf13/viper"
	"github.com/wowtrust/trustdb/v2/internal/adminauth"
	trustconfig "github.com/wowtrust/trustdb/v2/internal/config"
	"github.com/wowtrust/trustdb/v2/internal/httpapi"
	"github.com/wowtrust/trustdb/v2/internal/securityaudit"
	"golang.org/x/crypto/bcrypt"
)

func testLogger() zerolog.Logger {
	return zerolog.New(io.Discard).Level(zerolog.Disabled)
}

type recordingAuditor struct {
	mu     sync.Mutex
	drafts []securityaudit.Draft
}

func (r *recordingAuditor) Record(_ context.Context, draft securityaudit.Draft) (securityaudit.SignedEvent, error) {
	r.mu.Lock()
	r.drafts = append(r.drafts, draft)
	r.mu.Unlock()
	return securityaudit.SignedEvent{}, nil
}

func (r *recordingAuditor) snapshot() []securityaudit.Draft {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]securityaudit.Draft(nil), r.drafts...)
}

func (r *recordingAuditor) actions() []string {
	drafts := r.snapshot()
	actions := make([]string, len(drafts))
	for index, draft := range drafts {
		actions[index] = draft.Action + ":" + draft.Result
	}
	return actions
}

type failingAuditor struct{}

func (failingAuditor) Record(context.Context, securityaudit.Draft) (securityaudit.SignedEvent, error) {
	return securityaudit.SignedEvent{}, errors.New("audit unavailable")
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func testAdminAuthorization(t *testing.T, dir, username, password string) (*adminauth.Manager, *adminauth.FileStore) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	policy := adminauth.Policy{
		SchemaVersion: adminauth.PolicySchema, Version: 1,
		Accounts: []adminauth.Account{
			{ID: "audit", Username: "audit", PasswordHash: string(hash), Roles: []adminauth.Role{adminauth.RoleAuditAdmin}, SessionEpoch: 1},
			{ID: "security", Username: "security", PasswordHash: string(hash), Roles: []adminauth.Role{adminauth.RoleSecurityAdmin}, SessionEpoch: 1},
			{ID: "system", Username: username, PasswordHash: string(hash), Roles: []adminauth.Role{adminauth.RoleSystemAdmin}, SessionEpoch: 1},
			{ID: "zy-key", Username: "key", PasswordHash: string(hash), Roles: []adminauth.Role{adminauth.RoleKeyOperator}, SessionEpoch: 1},
		},
	}
	store, err := adminauth.NewFileStore(filepath.Join(dir, "admin-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Bootstrap(policy, time.Now()); err != nil {
		t.Fatal(err)
	}
	manager, err := adminauth.NewManager(policy, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return manager, store
}

func TestWriteConfigAtomicRejectsDirectoryTarget(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("Mkdir(target) error = %v", err)
	}

	if err := writeConfigAtomic(path, []byte("server:\n")); err == nil {
		t.Fatalf("writeConfigAtomic() error = nil, want directory target error")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(target) error = %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("target directory was replaced")
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp"))
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files were not cleaned up: %v", matches)
	}
}

func TestNewRequiresIndexHTML(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	_, err := New(Options{
		Admin: trustconfig.Admin{
			Enabled:       true,
			BasePath:      "/admin",
			PolicyPath:    filepath.Join(tmp, "admin-policy.json"),
			SessionSecret: strings.Repeat("a", 32),
			WebDir:        tmp,
		},
		Viper:        viper.New(),
		EffectiveCfg: trustconfig.Default(),
		Public:       http.NotFoundHandler(),
		Metrics:      http.NotFoundHandler(),
		Logger:       testLogger(),
	})
	if err == nil {
		t.Fatal("expected error without index.html")
	}
}

func TestNewRequiresAuditorWhenPolicyIsRequired(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	auth, store := testAdminAuthorization(t, dir, "system", "secret")
	effective := trustconfig.Default()
	effective.Audit.Required = true
	_, err := New(Options{
		Admin: trustconfig.Admin{Enabled: true, BasePath: "/admin", PolicyPath: store.Path(), SessionSecret: strings.Repeat("x", 32), WebDir: dir, SessionTTL: "1h", LoginMaxFailures: 5, LoginLockout: "15m"},
		Viper: viper.New(), EffectiveCfg: effective, Public: http.NotFoundHandler(), Metrics: http.NotFoundHandler(), Logger: testLogger(), Auth: auth, PolicyStore: store,
	})
	if err == nil || !strings.Contains(err.Error(), "Auditor") {
		t.Fatalf("New error=%v", err)
	}
}

func TestAdminAuthenticationAndAuthorizationAreAudited(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	auth, store := testAdminAuthorization(t, dir, "system", "secret")
	recorder := &recordingAuditor{}
	admin, err := New(Options{
		Admin: trustconfig.Admin{Enabled: true, BasePath: "/admin", PolicyPath: store.Path(), SessionSecret: strings.Repeat("x", 32), WebDir: dir, SessionTTL: "1h", LoginMaxFailures: 5, LoginLockout: "15m"},
		Viper: viper.New(), EffectiveCfg: trustconfig.Default(), Public: http.NotFoundHandler(), Metrics: http.NotFoundHandler(), Logger: testLogger(), Auth: auth, PolicyStore: store, Auditor: recorder,
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := Mount("/admin", http.NotFoundHandler(), admin)
	bad := httptest.NewRequest(http.MethodPost, "/admin/api/session", strings.NewReader(`{"username":"system","password":"wrong"}`))
	bad.RemoteAddr = "192.0.2.1:1234"
	badResult := httptest.NewRecorder()
	handler.ServeHTTP(badResult, bad)
	if badResult.Code != http.StatusUnauthorized {
		t.Fatalf("bad login status=%d", badResult.Code)
	}
	good := httptest.NewRequest(http.MethodPost, "/admin/api/session", strings.NewReader(`{"username":"system","password":"secret"}`))
	good.RemoteAddr = "192.0.2.1:1234"
	goodResult := httptest.NewRecorder()
	handler.ServeHTTP(goodResult, good)
	if goodResult.Code != http.StatusOK {
		t.Fatalf("good login status=%d body=%s", goodResult.Code, goodResult.Body.String())
	}
	request := httptest.NewRequest(http.MethodGet, "/admin/api/config", nil)
	for _, cookie := range goodResult.Result().Cookies() {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("config status=%d body=%s", response.Code, response.Body.String())
	}
	actions := recorder.actions()
	for _, want := range []string{"admin.login:denied", "admin.login:success", "admin.authorization:authorized", "admin.request:success"} {
		if !containsString(actions, want) {
			t.Fatalf("audit actions=%v missing %s", actions, want)
		}
	}
	for _, draft := range recorder.snapshot() {
		if draft.Context["source_hash"] == "192.0.2.1:1234" {
			t.Fatal("raw remote address leaked into audit context")
		}
	}
}

func TestAdminFailsClosedWhenAuditWriteFails(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	auth, store := testAdminAuthorization(t, dir, "system", "secret")
	admin, err := New(Options{
		Admin: trustconfig.Admin{Enabled: true, BasePath: "/admin", PolicyPath: store.Path(), SessionSecret: strings.Repeat("x", 32), WebDir: dir, SessionTTL: "1h", LoginMaxFailures: 5, LoginLockout: "15m"},
		Viper: viper.New(), EffectiveCfg: trustconfig.Default(), Public: http.NotFoundHandler(), Metrics: http.NotFoundHandler(), Logger: testLogger(), Auth: auth, PolicyStore: store,
		Auditor: failingAuditor{},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/session", strings.NewReader(`{"username":"system","password":"secret"}`))
	response := httptest.NewRecorder()
	admin.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestNewRejectsAuthorizationManagerStoreMismatch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	manager, store := testAdminAuthorization(t, dir, "system", "secret")
	policy, _ := manager.Snapshot()
	policy.Version++
	policy.Accounts[2].Description = "runtime-only mutation"
	if err := manager.Replace(policy, time.Now()); err != nil {
		t.Fatal(err)
	}
	_, err := New(Options{
		Admin: trustconfig.Admin{
			Enabled: true, BasePath: "/admin", PolicyPath: store.Path(),
			SessionSecret: strings.Repeat("k", 32), WebDir: dir, SessionTTL: "1h",
			LoginMaxFailures: 5, LoginLockout: "15m",
		},
		Viper: viper.New(), EffectiveCfg: trustconfig.Default(),
		Public: http.NotFoundHandler(), Metrics: http.NotFoundHandler(), Logger: testLogger(),
		Auth: manager, PolicyStore: store,
	})
	if err == nil || !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("New() error = %v, want manager/store mismatch", err)
	}
}

func TestLoginAndMetricsJSON(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "index.html"), []byte("<!doctype html><html></html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	auth, policyStore := testAdminAuthorization(t, tmp, "op", "secret")
	v := viper.New()
	metricsH, _ := httpapi.MetricsHandler()
	ah, err := New(Options{
		Admin: trustconfig.Admin{
			Enabled: true, BasePath: "/admin", PolicyPath: policyStore.Path(),
			SessionSecret: strings.Repeat("k", 32), WebDir: tmp, SessionTTL: "1h",
			LoginMaxFailures: 5, LoginLockout: "15m",
		},
		Viper:        v,
		EffectiveCfg: trustconfig.Default(),
		Public:       http.NotFoundHandler(),
		Metrics:      metricsH,
		Logger:       testLogger(),
		Auth:         auth,
		PolicyStore:  policyStore,
	})
	if err != nil {
		t.Fatal(err)
	}
	h := Mount("/admin", http.NotFoundHandler(), ah)

	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	// login
	body := `{"username":"op","password":"secret"}`
	res, err := http.Post(srv.URL+"/admin/api/session", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d", res.StatusCode)
	}
	if got := res.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("login Cache-Control = %q", got)
	}
	cookie := res.Header.Values("Set-Cookie")
	if len(cookie) == 0 || !strings.Contains(strings.Join(cookie, ";"), sessionCookieName) {
		t.Fatalf("missing session cookie: %v", cookie)
	}

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/admin/api/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range res.Cookies() {
		req.AddCookie(c)
	}
	res2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res2.Body.Close()
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("metrics status = %d", res2.StatusCode)
	}
	if got := res2.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("metrics Cache-Control = %q", got)
	}
}

func TestProxyGETOnly(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "index.html"), []byte("<!doctype html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	auth, policyStore := testAdminAuthorization(t, tmp, "op", "x")
	pub := http.NewServeMux()
	pub.HandleFunc("GET /v2/records", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) })

	metricsH, _ := httpapi.MetricsHandler()
	ah, err := New(Options{
		Admin: trustconfig.Admin{
			Enabled: true, PolicyPath: policyStore.Path(), SessionSecret: strings.Repeat("z", 32), WebDir: tmp,
			SessionTTL: "1h", LoginMaxFailures: 5, LoginLockout: "15m",
		},
		Viper:        viper.New(),
		EffectiveCfg: trustconfig.Default(),
		Public:       pub,
		Metrics:      metricsH,
		Logger:       testLogger(),
		Auth:         auth,
		PolicyStore:  policyStore,
	})
	if err != nil {
		t.Fatal(err)
	}
	h := Mount("/admin", pub, ah)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	// login
	res, err := http.Post(srv.URL+"/admin/api/session", "application/json", strings.NewReader(`{"username":"op","password":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/admin/api/proxy/v2/records", nil)
	for _, c := range res.Cookies() {
		req.AddCookie(c)
	}
	res2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res2.Body.Close()
	if res2.StatusCode != http.StatusTeapot {
		t.Fatalf("proxy status = %d", res2.StatusCode)
	}

	req3, err := http.NewRequest(http.MethodPost, srv.URL+"/admin/api/proxy/v2/claims", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range res.Cookies() {
		req3.AddCookie(c)
	}
	res3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	defer res3.Body.Close()
	if res3.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST proxy status = %d want 405", res3.StatusCode)
	}
}

func TestRolePermissionsAndPolicyChangeInvalidateSessions(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	auth, policyStore := testAdminAuthorization(t, dir, "system", "secret")
	metricsH, _ := httpapi.MetricsHandler()
	admin, err := New(Options{
		Admin: trustconfig.Admin{
			Enabled: true, BasePath: "/admin", PolicyPath: policyStore.Path(),
			SessionSecret: strings.Repeat("p", 32), WebDir: dir, SessionTTL: "1h",
			LoginMaxFailures: 5, LoginLockout: "15m",
		},
		Viper: viper.New(), EffectiveCfg: trustconfig.Default(), Public: http.NotFoundHandler(),
		Metrics: metricsH, Logger: testLogger(), Auth: auth, PolicyStore: policyStore,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(Mount("/admin", http.NotFoundHandler(), admin))
	t.Cleanup(server.Close)

	login := func(username string) []*http.Cookie {
		t.Helper()
		response, err := http.Post(server.URL+"/admin/api/session", "application/json", strings.NewReader(fmt.Sprintf(`{"username":%q,"password":"secret"}`, username)))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("login(%s) status=%d body=%s", username, response.StatusCode, mustRead(t, response.Body))
		}
		return response.Cookies()
	}
	do := func(method, path string, cookies []*http.Cookie, body io.Reader, headers map[string]string) *http.Response {
		t.Helper()
		request, err := http.NewRequest(method, server.URL+path, body)
		if err != nil {
			t.Fatal(err)
		}
		for _, cookie := range cookies {
			request.AddCookie(cookie)
		}
		for key, value := range headers {
			request.Header.Set(key, value)
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}

	systemCookies := login("system")
	response := do(http.MethodGet, "/admin/api/security/policy", systemCookies, nil, nil)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("system admin policy read status=%d body=%s", response.StatusCode, mustRead(t, response.Body))
	}
	response.Body.Close()

	auditCookies := login("audit")
	response = do(http.MethodPut, "/admin/api/config", auditCookies, strings.NewReader("server:\n  listen: 127.0.0.1:8080\n"), nil)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("audit admin config write status=%d body=%s", response.StatusCode, mustRead(t, response.Body))
	}
	response.Body.Close()

	securityCookies := login("security")
	policy, digest := auth.Snapshot()
	policy.Version++
	policy.Accounts = append(policy.Accounts, adminauth.Account{})
	copy(policy.Accounts[3:], policy.Accounts[2:])
	policy.Accounts[2] = adminauth.Account{
		ID: "support", Username: "support", PasswordHash: policy.Accounts[0].PasswordHash,
		Roles: []adminauth.Role{adminauth.RoleSupportReadOnly}, SessionEpoch: 1,
	}
	data, err := policy.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	response = do(http.MethodPut, "/admin/api/security/policy", securityCookies, strings.NewReader(string(data)), map[string]string{"If-Match": `"` + digest + `"`})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("security admin policy write status=%d body=%s", response.StatusCode, mustRead(t, response.Body))
	}
	response.Body.Close()

	response = do(http.MethodGet, "/admin/api/config", securityCookies, nil, nil)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("stale security session status=%d body=%s", response.StatusCode, mustRead(t, response.Body))
	}
	response.Body.Close()
}

func TestLoginLockout(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	auth, policyStore := testAdminAuthorization(t, dir, "system", "secret")
	now := time.Date(2026, time.July, 25, 9, 0, 0, 0, time.UTC)
	metricsH, _ := httpapi.MetricsHandler()
	admin, err := New(Options{
		Admin: trustconfig.Admin{Enabled: true, PolicyPath: policyStore.Path(), SessionSecret: strings.Repeat("l", 32), WebDir: dir, SessionTTL: "1h", LoginMaxFailures: 2, LoginLockout: "10m"},
		Viper: viper.New(), EffectiveCfg: trustconfig.Default(), Public: http.NotFoundHandler(), Metrics: metricsH,
		Logger: testLogger(), Auth: auth, PolicyStore: policyStore, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(admin)
	t.Cleanup(server.Close)
	post := func(password string) int {
		response, err := http.Post(server.URL+"/api/session", "application/json", strings.NewReader(fmt.Sprintf(`{"username":"system","password":%q}`, password)))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		return response.StatusCode
	}
	if got := post("wrong"); got != http.StatusUnauthorized {
		t.Fatalf("first failure status=%d", got)
	}
	if got := post("wrong"); got != http.StatusUnauthorized {
		t.Fatalf("second failure status=%d", got)
	}
	if got := post("secret"); got != http.StatusTooManyRequests {
		t.Fatalf("locked login status=%d", got)
	}
	now = now.Add(10 * time.Minute)
	if got := post("secret"); got != http.StatusOK {
		t.Fatalf("post-lockout login status=%d", got)
	}
}

type testMFAVerifier struct{}

func (testMFAVerifier) VerifyMFA(_ context.Context, _ adminauth.Principal, code string) error {
	if code != "123456" {
		return errors.New("invalid MFA code")
	}
	return nil
}

func TestLocalMFAAndEmergencyReason(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	auth, store := testAdminAuthorization(t, dir, "system", "secret")
	policy, digest := auth.Snapshot()
	policy.Version++
	policy.Accounts[2].MFARequired = true
	policy.Accounts = append(policy.Accounts, adminauth.Account{
		ID: "zz-emergency", Username: "breakglass", PasswordHash: policy.Accounts[2].PasswordHash,
		Roles: []adminauth.Role{adminauth.RoleEmergencyAdmin}, Emergency: true, SessionEpoch: 1,
		NotBefore: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		NotAfter:  time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	})
	if _, err := store.ReplaceOffline(digest, policy, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := auth.Replace(policy, time.Now()); err != nil {
		t.Fatal(err)
	}
	metricsH, _ := httpapi.MetricsHandler()
	auditor := &recordingAuditor{}
	admin, err := New(Options{
		Admin: trustconfig.Admin{Enabled: true, PolicyPath: store.Path(), SessionSecret: strings.Repeat("m", 32), WebDir: dir, SessionTTL: "1h", LoginMaxFailures: 5, LoginLockout: "15m"},
		Viper: viper.New(), EffectiveCfg: trustconfig.Default(), Public: http.NotFoundHandler(), Metrics: metricsH,
		Logger: testLogger(), Auth: auth, PolicyStore: store, MFAVerifier: testMFAVerifier{}, Auditor: auditor,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(admin)
	t.Cleanup(server.Close)
	post := func(body string) int {
		response, err := http.Post(server.URL+"/api/session", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		return response.StatusCode
	}
	if got := post(`{"username":"system","password":"secret"}`); got != http.StatusUnauthorized {
		t.Fatalf("login without MFA status=%d", got)
	}
	if got := post(`{"username":"system","password":"secret","mfa_code":"123456"}`); got != http.StatusOK {
		t.Fatalf("login with MFA status=%d", got)
	}
	if got := post(`{"username":"breakglass","password":"secret"}`); got != http.StatusBadRequest {
		t.Fatalf("emergency login without reason status=%d", got)
	}
	if got := post(`{"username":"breakglass","password":"secret","emergency_reason":"restore access during incident 2026-07-25"}`); got != http.StatusOK {
		t.Fatalf("emergency login with reason status=%d", got)
	}
	for _, draft := range auditor.snapshot() {
		for _, value := range draft.Context {
			if strings.Contains(value, "restore access during incident") {
				t.Fatal("raw emergency reason leaked into audit context")
			}
		}
	}
}

func mustRead(t *testing.T, reader io.Reader) string {
	t.Helper()
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestDecodeJSONBodyLimitRejectsTrailingData(t *testing.T) {
	t.Parallel()
	var body loginBody
	err := decodeJSONBodyLimit(strings.NewReader(`{"username":"op","password":"x"}{}`), &body, maxLoginBodyBytes)
	if err == nil || !strings.Contains(err.Error(), "trailing json data") {
		t.Fatalf("decodeJSONBodyLimit() error = %v, want trailing json data", err)
	}
}

func TestReadBodyLimitRejectsOversizedBody(t *testing.T) {
	t.Parallel()
	_, err := readBodyLimit(strings.NewReader("abcd"), 3)
	if !errors.Is(err, errRequestBodyTooLarge) {
		t.Fatalf("readBodyLimit() error = %v, want errRequestBodyTooLarge", err)
	}
}

func TestGetConfigRawRejectsOversizedFile(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "trustdb.yaml")
	if err := os.WriteFile(configPath, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile(config): %v", err)
	}
	if err := os.Truncate(configPath, maxConfigBodyBytes+1); err != nil {
		t.Fatalf("Truncate(config): %v", err)
	}
	h := &handler{opts: Options{ConfigPath: configPath, Logger: testLogger()}}
	req := httptest.NewRequest(http.MethodGet, "/api/config/raw", nil)
	rec := httptest.NewRecorder()

	h.getConfigRaw(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("getConfigRaw status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPutConfigRejectsOversizedExistingFile(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "trustdb.yaml")
	if err := os.WriteFile(configPath, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile(config): %v", err)
	}
	if err := os.Truncate(configPath, maxConfigBodyBytes+1); err != nil {
		t.Fatalf("Truncate(config): %v", err)
	}
	h := &handler{opts: Options{ConfigPath: configPath, Logger: testLogger()}}
	req := httptest.NewRequest(http.MethodPut, "/api/config", strings.NewReader(trustconfig.DefaultYAML))
	rec := httptest.NewRecorder()

	h.putConfig(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("putConfig status = %d body=%s", rec.Code, rec.Body.String())
	}
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("Stat(config): %v", err)
	}
	if info.Size() != maxConfigBodyBytes+1 {
		t.Fatalf("config size = %d, want %d", info.Size(), maxConfigBodyBytes+1)
	}
}

func TestPutConfigAllowsUnchangedProtectedBlocksAndRejectsMutation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "trustdb.yaml")
	current := trustconfig.DefaultYAML + `
admin:
  enabled: false
  policy_path: "/etc/trustdb/admin-policy.json"
  cli_enforce: false
`
	if err := os.WriteFile(configPath, []byte(current), 0o600); err != nil {
		t.Fatal(err)
	}
	h := &handler{opts: Options{ConfigPath: configPath, Logger: testLogger()}}

	recorder := httptest.NewRecorder()
	h.putConfig(recorder, httptest.NewRequest(http.MethodPut, "/api/config", strings.NewReader(current)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("unchanged admin block status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	changed := strings.Replace(current, "/etc/trustdb/admin-policy.json", "/tmp/attacker-policy.json", 1)
	recorder = httptest.NewRecorder()
	h.putConfig(recorder, httptest.NewRequest(http.MethodPut, "/api/config", strings.NewReader(changed)))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("changed admin block status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	changed = strings.Replace(current, "audit:\n  enabled: false", "audit:\n  enabled: true", 1)
	changed = strings.Replace(changed, `  signing_key: ""`, `  signing_key: "/etc/trustdb/keys/audit.tdkey"`, 1)
	recorder = httptest.NewRecorder()
	h.putConfig(recorder, httptest.NewRequest(http.MethodPut, "/api/config", strings.NewReader(changed)))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("changed audit block status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	changed = strings.Replace(
		current,
		`  egress_mode: "unrestricted"`,
		`  egress_mode: "allowlist"`,
		1,
	)
	recorder = httptest.NewRecorder()
	h.putConfig(recorder, httptest.NewRequest(http.MethodPut, "/api/config", strings.NewReader(changed)))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("changed deployment policy status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	changed = strings.Replace(current, `# run_profile: ""`, `run_profile: development`, 1)
	recorder = httptest.NewRecorder()
	h.putConfig(recorder, httptest.NewRequest(http.MethodPut, "/api/config", strings.NewReader(changed)))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("changed run profile status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestPutConfigIgnoresStaleFixedTempPathAndWritesBackup(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "trustdb.yaml")
	previous := []byte("previous: config\n")
	if err := os.WriteFile(configPath, previous, 0o600); err != nil {
		t.Fatalf("WriteFile(config): %v", err)
	}
	staleFixedTmp := configPath + ".tmp"
	if err := os.Mkdir(staleFixedTmp, 0o755); err != nil {
		t.Fatalf("Mkdir(stale tmp): %v", err)
	}

	h := &handler{opts: Options{
		ConfigPath: configPath,
		Logger:     testLogger(),
	}}
	req := httptest.NewRequest(http.MethodPut, "/api/config", strings.NewReader(trustconfig.DefaultYAML))
	rec := httptest.NewRecorder()
	h.putConfig(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("putConfig status = %d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		OK     bool   `json:"ok"`
		Backup string `json:"backup"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !body.OK {
		t.Fatalf("putConfig ok = false")
	}
	if body.Backup == "" {
		t.Fatalf("putConfig backup path is empty")
	}
	if !strings.HasPrefix(filepath.Base(body.Backup), filepath.Base(configPath)+".bak.") {
		t.Fatalf("backup path = %q, want prefix %q", body.Backup, filepath.Base(configPath)+".bak.")
	}
	backup, err := os.ReadFile(body.Backup)
	if err != nil {
		t.Fatalf("ReadFile(backup): %v", err)
	}
	if string(backup) != string(previous) {
		t.Fatalf("backup = %q, want %q", backup, previous)
	}
	updated, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("ReadFile(config): %v", err)
	}
	if string(updated) != trustconfig.DefaultYAML {
		t.Fatalf("updated config = %q, want default yaml", updated)
	}
	info, err := os.Stat(staleFixedTmp)
	if err != nil {
		t.Fatalf("stale fixed temp path missing: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("stale fixed temp path was modified; isDir=false")
	}
}

func TestAdminMountServesSPAEntrypoints(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "index.html"), []byte("<!doctype html><title>admin</title>"), 0o644); err != nil {
		t.Fatal(err)
	}
	assets := filepath.Join(tmp, "assets")
	if err := os.MkdirAll(assets, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(assets, "app.js"), []byte("console.log('ok')"), 0o644); err != nil {
		t.Fatal(err)
	}

	h := Mount("/admin", http.NotFoundHandler(), spaFileServer(tmp))
	for _, path := range []string{"/admin", "/admin/", "/admin/dashboard"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d body=%s", path, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "<title>admin</title>") {
			t.Fatalf("%s did not serve index.html: %q", path, rec.Body.String())
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/assets/app.js", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("asset status = %d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "console.log('ok')" {
		t.Fatalf("asset body = %q", rec.Body.String())
	}
}

func TestSPAFileServerRejectsSiblingPrefixTraversal(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	root := filepath.Join(parent, "web")
	sibling := filepath.Join(parent, "web_evil")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sibling, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("<!doctype html><title>admin</title>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sibling, "secret.txt"), []byte("outside-secret"), 0o644); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/../web_evil/secret.txt", nil)
	rec := httptest.NewRecorder()
	spaFileServer(root).ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d body=%q, want 404", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "outside-secret") {
		t.Fatalf("served file outside web root: %q", rec.Body.String())
	}
}

func TestSPAFileServerRejectsSymlinkOutsideRoot(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	root := filepath.Join(parent, "web")
	outside := filepath.Join(parent, "outside-secret.txt")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("<!doctype html><title>admin</title>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, []byte("outside-secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "leak.txt")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/leak.txt", nil)
	rec := httptest.NewRecorder()
	spaFileServer(root).ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d body=%q, want 404", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "outside-secret") {
		t.Fatalf("served symlink target outside web root: %q", rec.Body.String())
	}
}
