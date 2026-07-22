package keystore

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
)

func TestRegistryRegisterLookupAndReload(t *testing.T) {
	t.Parallel()

	regPub, regPriv := mustKey(t)
	clientPub, _ := mustKey(t)
	path := filepath.Join(t.TempDir(), "keys.tdkeys")
	reg, err := Open(path, "registry-key", regPriv, regPub)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	validFrom := time.Unix(100, 0)
	ev, err := reg.RegisterClientKey("tenant", "client", "key", clientPub, validFrom, time.Time{})
	if err != nil {
		t.Fatalf("RegisterClientKey() error = %v", err)
	}
	if ev.Sequence != 1 || len(ev.EventHash) == 0 || len(ev.RegistrySignature.Signature) == 0 {
		t.Fatalf("registered event incomplete: %+v", ev)
	}
	got, err := reg.LookupClientKeyAt("tenant", "client", "key", time.Unix(101, 0))
	if err != nil {
		t.Fatalf("LookupClientKeyAt() error = %v", err)
	}
	if got.Status != model.KeyStatusValid || string(got.PublicKey) != string(clientPub) {
		t.Fatalf("LookupClientKeyAt() = %+v", got)
	}

	reloaded, err := Open(path, "registry-key", nil, regPub)
	if err != nil {
		t.Fatalf("Open(reload) error = %v", err)
	}
	got, err = reloaded.LookupClientKeyAt("tenant", "client", "key", time.Unix(101, 0))
	if err != nil {
		t.Fatalf("LookupClientKeyAt(reload) error = %v", err)
	}
	if got.Status != model.KeyStatusValid {
		t.Fatalf("reloaded status = %s", got.Status)
	}
}

func TestRegistryRejectsRevokedKeyAtLookupTime(t *testing.T) {
	t.Parallel()

	regPub, regPriv := mustKey(t)
	clientPub, _ := mustKey(t)
	reg, err := Open(filepath.Join(t.TempDir(), "keys.tdkeys"), "registry-key", regPriv, regPub)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if _, err := reg.RegisterClientKey("tenant", "client", "key", clientPub, time.Unix(100, 0), time.Time{}); err != nil {
		t.Fatalf("RegisterClientKey() error = %v", err)
	}
	if _, err := reg.RevokeClientKey("tenant", "client", "key", time.Unix(200, 0), "rotation"); err != nil {
		t.Fatalf("RevokeClientKey() error = %v", err)
	}
	if _, err := reg.LookupClientKeyAt("tenant", "client", "key", time.Unix(199, 0)); err != nil {
		t.Fatalf("Lookup before revoke error = %v", err)
	}
	if got, err := reg.LookupClientKeyAt("tenant", "client", "key", time.Unix(200, 0)); err == nil || got.Status != model.KeyStatusRevoked {
		t.Fatalf("Lookup after revoke got = %+v err = %v, want revoked error", got, err)
	}
}

func TestRegistryRejectsDuplicateRegister(t *testing.T) {
	t.Parallel()

	regPub, regPriv := mustKey(t)
	clientPub, _ := mustKey(t)
	reg, err := Open(filepath.Join(t.TempDir(), "keys.tdkeys"), "registry-key", regPriv, regPub)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if _, err := reg.RegisterClientKey("tenant", "client", "key", clientPub, time.Unix(100, 0), time.Time{}); err != nil {
		t.Fatalf("RegisterClientKey() error = %v", err)
	}
	if _, err := reg.RegisterClientKey("tenant", "client", "key", clientPub, time.Unix(101, 0), time.Time{}); err == nil {
		t.Fatal("RegisterClientKey duplicate error = nil, want error")
	}
}

func mustKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key() error = %v", err)
	}
	return pub, priv
}
