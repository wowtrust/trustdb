package adminweb

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/wowtrust/trustdb/v2/internal/app"
	"github.com/wowtrust/trustdb/v2/internal/claim"
	trustconfig "github.com/wowtrust/trustdb/v2/internal/config"
	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/keydescriptor"
	"github.com/wowtrust/trustdb/v2/internal/keystore"
	"github.com/wowtrust/trustdb/v2/internal/model"
	"github.com/wowtrust/trustdb/v2/internal/trustcrypto"
	"github.com/wowtrust/trustdb/v2/internal/trusterr"
	"github.com/wowtrust/trustdb/v2/internal/wal"
)

func TestAdminKeyLifecycleUsesLiveAppendOnlyRegistry(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	registryPublic, registryPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	registrySigner := trustcrypto.MustNewEd25519Signer("registry-key", registryPrivate)
	registry, err := keystore.Open(
		filepath.Join(dir, "clients.tdkeys"),
		registrySigner,
		trustcrypto.MustNewEd25519PublicKey("registry-key", registryPublic),
	)
	if err != nil {
		t.Fatal(err)
	}
	auth, store := testAdminAuthorization(t, dir, "system", "secret")
	recorder := &recordingAuditor{}
	now := time.Now().UTC().Truncate(time.Second)
	admin, err := New(Options{
		Admin: trustconfig.Admin{
			Enabled: true, BasePath: "/admin", PolicyPath: store.Path(),
			SessionSecret: strings.Repeat("k", 32), WebDir: dir, SessionTTL: "1h",
			LoginMaxFailures: 5, LoginLockout: "15m",
		},
		Viper: viper.New(), EffectiveCfg: trustconfig.Default(),
		Public: http.NotFoundHandler(), Metrics: http.NotFoundHandler(), Logger: testLogger(),
		Auth: auth, PolicyStore: store, Auditor: recorder, KeyRegistry: registry,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := Mount("/admin", http.NotFoundHandler(), admin)

	keyOperatorCookies := loginAdmin(t, handler, "key", "secret")
	clientPublic, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := keydescriptor.Descriptor{
		SchemaVersion: keydescriptor.SchemaV1,
		Kind:          keydescriptor.KindVerifier,
		Provider:      keydescriptor.ProviderPublic,
		CryptoSuite:   cryptosuite.INTLV1,
		KeyID:         "browser-key-1",
		Algorithm:     cryptosuite.SignatureEd25519,
		PublicKey: keydescriptor.PublicKeyMaterial{
			Encoding: cryptosuite.Ed25519PublicKeyEncoding,
			Bytes:    clientPublic,
		},
	}
	registerBody := registerKeyBody{
		TenantID: "tenant-a", ClientID: "chrome-extension:proof-mesh",
		Descriptor: descriptor, ValidFrom: now.Add(-time.Minute),
	}

	first := doAdminJSON(t, handler, http.MethodPost, "/admin/api/keys", keyOperatorCookies, registerBody)
	requireAdminStatus(t, first, http.StatusOK)
	firstResponse := decodeAdminResponse(t, first)
	if sequence := firstResponse["sequence"]; sequence != float64(1) {
		t.Fatalf("first sequence=%v", sequence)
	}
	replay := doAdminJSON(t, handler, http.MethodPost, "/admin/api/keys", keyOperatorCookies, registerBody)
	requireAdminStatus(t, replay, http.StatusOK)
	replayResponse := decodeAdminResponse(t, replay)
	if replayResponse["sequence"] != firstResponse["sequence"] || replayResponse["event_hash"] != firstResponse["event_hash"] {
		t.Fatalf("replay response=%v first=%v", replayResponse, firstResponse)
	}

	conflictBody := registerBody
	conflictBody.Descriptor.PublicKey.Bytes = bytes.Repeat([]byte{1}, ed25519.PublicKeySize)
	conflict := doAdminJSON(t, handler, http.MethodPost, "/admin/api/keys", keyOperatorCookies, conflictBody)
	requireAdminStatus(t, conflict, http.StatusConflict)
	conflict.Body.Close()

	historicalAt := now.Add(-30 * time.Second)
	current := doAdminJSON(
		t,
		handler,
		http.MethodGet,
		"/admin/api/keys/tenant-a/chrome-extension:proof-mesh/browser-key-1?at="+now.Format(time.RFC3339Nano),
		keyOperatorCookies,
		nil,
	)
	requireAdminStatus(t, current, http.StatusOK)
	current.Body.Close()

	writer, err := wal.OpenDirWriter(filepath.Join(dir, "wal"), wal.Options{
		CryptoSuite: cryptosuite.INTLV1,
		NodeID:      "admin-key-e2e",
		LogID:       "admin-key-e2e",
		NamespaceID: "admin-key-e2e",
		FsyncMode:   wal.FsyncStrict,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	_, serverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	engineNow := now
	engine := app.LocalEngine{
		ServerID:     "admin-key-e2e",
		LogID:        "admin-key-e2e",
		ServerKeyID:  "server-key",
		ClientKeys:   registry,
		ServerSigner: trustcrypto.MustNewEd25519Signer("server-key", serverPrivate),
		WAL:          writer,
		Idempotency:  app.NewIdempotencyIndex(),
		Now:          func() time.Time { return engineNow },
	}
	submitClaim := func(idempotencyKey string) error {
		content := []byte("online key lifecycle claim")
		contentHash, err := trustcrypto.HashBytes(model.DefaultHashAlg, content)
		if err != nil {
			return err
		}
		unsigned, err := claim.NewFileClaim(
			"tenant-a",
			"chrome-extension:proof-mesh",
			"browser-key-1",
			now,
			bytes.Repeat([]byte{1}, 16),
			idempotencyKey,
			model.Content{
				HashAlg:       model.DefaultHashAlg,
				ContentHash:   contentHash,
				ContentLength: int64(len(content)),
			},
			model.Metadata{EventType: "file.snapshot"},
		)
		if err != nil {
			return err
		}
		signed, err := claim.Sign(unsigned, clientPrivate)
		if err != nil {
			return err
		}
		_, _, _, err = engine.Submit(context.Background(), signed)
		return err
	}
	if err := submitClaim("before-revocation"); err != nil {
		t.Fatalf("claim immediately after online registration error = %v", err)
	}

	retroactive := doAdminJSON(
		t,
		handler,
		http.MethodPost,
		"/admin/api/keys/tenant-a/chrome-extension:proof-mesh/browser-key-1/revoke",
		keyOperatorCookies,
		revokeKeyBody{RevokedAt: now.Add(-time.Minute), Reason: "retroactive change"},
	)
	requireAdminStatus(t, retroactive, http.StatusBadRequest)
	retroactive.Body.Close()
	if events := registry.Events(); len(events) != 1 {
		t.Fatalf("retroactive revocation appended events=%+v", events)
	}

	revokeAt := now.Add(time.Second)
	revokeBody := revokeKeyBody{RevokedAt: revokeAt, Reason: "user requested revocation"}
	revoked := doAdminJSON(
		t,
		handler,
		http.MethodPost,
		"/admin/api/keys/tenant-a/chrome-extension:proof-mesh/browser-key-1/revoke",
		keyOperatorCookies,
		revokeBody,
	)
	requireAdminStatus(t, revoked, http.StatusOK)
	revokedResponse := decodeAdminResponse(t, revoked)
	if sequence := revokedResponse["sequence"]; sequence != float64(2) {
		t.Fatalf("revoke sequence=%v", sequence)
	}
	revokeReplay := doAdminJSON(
		t,
		handler,
		http.MethodPost,
		"/admin/api/keys/tenant-a/chrome-extension:proof-mesh/browser-key-1/revoke",
		keyOperatorCookies,
		revokeBody,
	)
	requireAdminStatus(t, revokeReplay, http.StatusOK)
	revokeReplayResponse := decodeAdminResponse(t, revokeReplay)
	if revokeReplayResponse["event_hash"] != revokedResponse["event_hash"] {
		t.Fatalf("revoke replay=%v first=%v", revokeReplayResponse, revokedResponse)
	}

	historical := doAdminJSON(
		t,
		handler,
		http.MethodGet,
		"/admin/api/keys/tenant-a/chrome-extension:proof-mesh/browser-key-1?at="+historicalAt.Format(time.RFC3339Nano),
		keyOperatorCookies,
		nil,
	)
	requireAdminStatus(t, historical, http.StatusOK)
	historical.Body.Close()
	afterRevocation := doAdminJSON(
		t,
		handler,
		http.MethodGet,
		"/admin/api/keys/tenant-a/chrome-extension:proof-mesh/browser-key-1?at="+revokeAt.Add(time.Second).Format(time.RFC3339Nano),
		keyOperatorCookies,
		nil,
	)
	requireAdminStatus(t, afterRevocation, http.StatusConflict)
	afterRevocation.Body.Close()
	engineNow = revokeAt.Add(time.Second)
	if err := submitClaim("after-revocation"); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition || !strings.Contains(err.Error(), "key status is revoked") {
		t.Fatalf("claim after online revocation error = %v", err)
	}

	if events := registry.Events(); len(events) != 2 || events[0].Type != model.KeyEventRegister || events[1].Type != model.KeyEventRevoke {
		t.Fatalf("registry events=%+v", events)
	}
	for _, want := range []string{"admin.authorization:authorized", "admin.request:success", "admin.request:failure"} {
		if !containsString(recorder.actions(), want) {
			t.Fatalf("audit actions=%v missing %s", recorder.actions(), want)
		}
	}
}

func loginAdmin(t *testing.T, handler http.Handler, username, password string) []*http.Cookie {
	t.Helper()
	response := doAdminJSON(
		t,
		handler,
		http.MethodPost,
		"/admin/api/session",
		nil,
		map[string]string{"username": username, "password": password},
	)
	requireAdminStatus(t, response, http.StatusOK)
	response.Body.Close()
	return response.Cookies()
}

func doAdminJSON(t *testing.T, handler http.Handler, method, path string, cookies []*http.Cookie, body any) *http.Response {
	t.Helper()
	var payload *bytes.Reader
	if body == nil {
		payload = bytes.NewReader(nil)
	} else {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		payload = bytes.NewReader(raw)
	}
	request := httptest.NewRequest(method, path, payload)
	request.Header.Set("Content-Type", "application/json")
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response.Result()
}

func requireAdminStatus(t *testing.T, response *http.Response, want int) {
	t.Helper()
	if response.StatusCode != want {
		defer response.Body.Close()
		t.Fatalf("status=%d want=%d body=%s", response.StatusCode, want, mustRead(t, response.Body))
	}
}

func decodeAdminResponse(t *testing.T, response *http.Response) map[string]any {
	t.Helper()
	defer response.Body.Close()
	var value map[string]any
	if err := json.NewDecoder(response.Body).Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}
