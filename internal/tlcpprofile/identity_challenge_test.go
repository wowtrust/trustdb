package tlcpprofile

import (
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

	"github.com/wowtrust/trustdb/v2/internal/keydescriptor"
	"github.com/wowtrust/trustdb/v2/internal/trustcrypto"
)

func TestActiveIdentityChallengeBindsRunningSignerAndRegistry(t *testing.T) {
	dir := t.TempDir()
	proofSigner, proofData := challengeSigner(t, "active-proof")
	_, registryData := challengeSigner(t, "active-registry")
	manifestPath := filepath.Join(dir, "identities.json")
	manifest, err := WriteTrustDBIdentityManifest(
		manifestPath,
		proofData,
		registryData,
	)
	if err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(dir, "profile.json")
	profile := Profile{TrustDBIdentityManifestFile: manifestPath}
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	profile.Network.TrustDBHTTPUpstream = strings.TrimPrefix(
		server.URL,
		"http://",
	)
	writeChallengeProfile(t, profilePath, profile)
	service, err := NewActiveIdentityChallengeService(
		manifest,
		proofSigner,
	)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = service.Mount(http.NotFoundHandler())

	if err := VerifyActiveIdentityChallenge(
		context.Background(),
		profilePath,
		profile,
	); err != nil {
		t.Fatalf("VerifyActiveIdentityChallenge() error = %v", err)
	}
	rotatedProfile := profile
	rotatedProfile.ProfileID = "rotated-certificate-profile"
	writeChallengeProfile(t, profilePath, rotatedProfile)
	if err := VerifyActiveIdentityChallenge(
		context.Background(),
		profilePath,
		rotatedProfile,
	); err != nil {
		t.Fatalf("certificate-only profile rotation challenge error = %v", err)
	}

	_, staleProofData := challengeSigner(t, "stale-proof")
	if _, err := WriteTrustDBIdentityManifest(
		manifestPath,
		staleProofData,
		registryData,
	); err != nil {
		t.Fatal(err)
	}
	if err := VerifyActiveIdentityChallenge(
		context.Background(),
		profilePath,
		rotatedProfile,
	); err == nil || !strings.Contains(err.Error(), "do not exactly match") {
		t.Fatalf("stale manifest error = %v", err)
	}
}

func TestActiveIdentityChallengeServiceRejectsAnotherSigner(t *testing.T) {
	signer, proofData := challengeSigner(t, "expected-proof")
	manifestPath := filepath.Join(t.TempDir(), "identities.json")
	manifest, err := WriteTrustDBIdentityManifest(
		manifestPath,
		proofData,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := challengeSigner(t, "other-proof")
	if _, err := NewActiveIdentityChallengeService(
		manifest,
		other,
	); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched signer error = %v", err)
	}
	if _, err := NewActiveIdentityChallengeService(
		manifest,
		signer,
	); err != nil {
		t.Fatalf("matching signer error = %v", err)
	}
}

func TestActiveIdentityChallengeEndpointIsLoopbackOnly(t *testing.T) {
	signer, proofData := challengeSigner(t, "active-proof")
	manifestPath := filepath.Join(t.TempDir(), "identities.json")
	manifest, err := WriteTrustDBIdentityManifest(
		manifestPath,
		proofData,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewActiveIdentityChallengeService(
		manifest,
		signer,
	)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodGet,
		ActiveIdentityChallengePath+"?nonce="+
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		nil,
	)
	request.RemoteAddr = "192.0.2.1:1234"
	response := httptest.NewRecorder()
	service.Mount(http.NotFoundHandler()).ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("non-loopback response status = %d", response.Code)
	}
}

func challengeSigner(
	t *testing.T,
	keyID string,
) (trustcrypto.Signer, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := trustcrypto.MustNewEd25519Signer(keyID, privateKey)
	descriptor := proofVerifierDescriptor(t, publicKey)
	descriptor.KeyID = keyID
	if err := descriptor.Validate(); err != nil {
		t.Fatal(err)
	}
	data, err := keydescriptor.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	return signer, data
}

func writeChallengeProfile(t *testing.T, path string, profile Profile) {
	t.Helper()
	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}
