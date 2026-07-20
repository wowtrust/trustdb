package adminweb

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	trustconfig "github.com/ryan-wong-coder/trustdb/internal/config"
	"github.com/ryan-wong-coder/trustdb/internal/httpapi"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
)

func testLogger() zerolog.Logger {
	return zerolog.New(io.Discard).Level(zerolog.Disabled)
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
			Username:      "u",
			PasswordHash:  "$2a$10$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
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

func TestLoginAndMetricsJSON(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "index.html"), []byte("<!doctype html><html></html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	v := viper.New()
	metricsH, _ := httpapi.MetricsHandler()
	ah, err := New(Options{
		Admin: trustconfig.Admin{
			Enabled:       true,
			BasePath:      "/admin",
			Username:      "op",
			PasswordHash:  string(hash),
			SessionSecret: strings.Repeat("k", 32),
			WebDir:        tmp,
			SessionTTL:    "1h",
		},
		Viper:        v,
		EffectiveCfg: trustconfig.Default(),
		Public:       http.NotFoundHandler(),
		Metrics:      metricsH,
		Logger:       testLogger(),
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
}

func TestProxyGETOnly(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "index.html"), []byte("<!doctype html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("x"), bcrypt.MinCost)
	pub := http.NewServeMux()
	pub.HandleFunc("GET /v1/records", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) })

	metricsH, _ := httpapi.MetricsHandler()
	ah, err := New(Options{
		Admin: trustconfig.Admin{
			Enabled:       true,
			Username:      "op",
			PasswordHash:  string(hash),
			SessionSecret: strings.Repeat("z", 32),
			WebDir:        tmp,
		},
		Viper:        viper.New(),
		EffectiveCfg: trustconfig.Default(),
		Public:       pub,
		Metrics:      metricsH,
		Logger:       testLogger(),
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
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/admin/api/proxy/v1/records", nil)
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

	req3, err := http.NewRequest(http.MethodPost, srv.URL+"/admin/api/proxy/v1/claims", strings.NewReader("x"))
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
