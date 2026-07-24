package tlcpprofile

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cryptox509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

var fixtureNow = time.Date(2026, 7, 24, 8, 0, 0, 0, time.UTC)

type trustFixture struct {
	dir                   string
	profile               Profile
	serverCA              *smx509.Certificate
	serverCAKey           *sm2.PrivateKey
	clientCA              *smx509.Certificate
	clientCAKey           *sm2.PrivateKey
	signingCertificate    *smx509.Certificate
	encryptionCertificate *smx509.Certificate
}

func TestGoldenProfileValidatesStrictSM2DualCertificatesAndCRLs(t *testing.T) {
	fixture := newTrustFixture(t)
	report, err := Validate(fixture.profile, Options{Now: fixtureNow})
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if report.SchemaVersion != SchemaVersion ||
		report.ProfileID != fixture.profile.ProfileID ||
		report.ServerName != fixture.profile.ServerName ||
		len(report.SigningCertificateSHA256) != 64 ||
		len(report.EncryptionCertificateSHA256) != 64 ||
		report.SigningCertificateSHA256 == report.EncryptionCertificateSHA256 ||
		len(report.ServerCASHA256) != 1 ||
		len(report.ClientCASHA256) != 1 ||
		len(report.CRLIssuers) != 2 {
		t.Fatalf("unexpected validation report: %+v", report)
	}
}

func TestDecodeRejectsUnknownDuplicateTrailingAndOversizedJSON(t *testing.T) {
	fixture := newTrustFixture(t)
	data := marshalProfile(t, fixture.profile)
	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatal(err)
	}
	object["unknown"] = true
	unknown, _ := json.Marshal(object)
	if _, err := Decode(unknown); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field error = %v", err)
	}
	duplicate := bytes.Replace(data, []byte(`"profile_id":`), []byte(`"profile_id":"duplicate","profile_id":`), 1)
	if _, err := Decode(duplicate); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate key error = %v", err)
	}
	if _, err := Decode(append(data, []byte(` {}`)...)); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("trailing value error = %v", err)
	}
	if _, err := Decode(bytes.Repeat([]byte{' '}, MaxProfileBytes+1)); err == nil {
		t.Fatal("oversized profile was accepted")
	}
	if _, err := Decode([]byte{'{', '"', 0xff, '"', ':', '1', '}'}); err == nil ||
		!strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("invalid UTF-8 error = %v", err)
	}
}

func TestProfileFailsClosedOnDeploymentAndTrustBoundaryDrift(t *testing.T) {
	fixture := newTrustFixture(t)
	tests := []struct {
		name   string
		mutate func(*Profile)
		match  string
	}{
		{
			name:   "wrong crypto mode",
			mutate: func(profile *Profile) { profile.CryptoMode = "standard" },
			match:  "crypto_mode",
		},
		{
			name:   "host network",
			mutate: func(profile *Profile) { profile.Network.HostNetwork = true },
			match:  "hostNetwork",
		},
		{
			name:   "unshared namespace",
			mutate: func(profile *Profile) { profile.Network.SharedNetworkNamespace = false },
			match:  "share a restricted network namespace",
		},
		{
			name: "extra container",
			mutate: func(profile *Profile) {
				profile.Network.AllowedContainers = append(profile.Network.AllowedContainers, "debug")
			},
			match: "exactly",
		},
		{
			name:   "external loopback bind",
			mutate: func(profile *Profile) { profile.Network.GatewayHTTPBind = "127.0.0.1:8443" },
			match:  "external binds",
		},
		{
			name:   "non-loopback app upstream",
			mutate: func(profile *Profile) { profile.Network.TrustDBGRPCUpstream = "10.0.0.2:9090" },
			match:  "loopback-only",
		},
		{
			name:   "production file key",
			mutate: func(profile *Profile) { profile.Environment = EnvironmentProduction },
			match:  "test profiles",
		},
		{
			name: "same key reference under another provider label",
			mutate: func(profile *Profile) {
				profile.Certificates.EncryptionKey.Provider = KeyProviderEngine
				profile.Certificates.EncryptionKey.Reference = profile.Certificates.SigningKey.Reference
			},
			match: "distinct references",
		},
		{
			name:   "ocsp not silently accepted",
			mutate: func(profile *Profile) { profile.Revocation.Mode = "ocsp" },
			match:  "only fail-closed CRL",
		},
		{
			name:   "unpinned tengine",
			mutate: func(profile *Profile) { profile.Implementation.TengineCommit = strings.Repeat("0", 40) },
			match:  "pinned",
		},
		{
			name: "gateway image digest without algorithm",
			mutate: func(profile *Profile) {
				profile.Implementation.GatewayImageDigest = strings.TrimPrefix(
					profile.Implementation.GatewayImageDigest, "sha256:",
				)
			},
			match: "algorithm prefix",
		},
		{
			name:   "build parameter drift",
			mutate: func(profile *Profile) { profile.Implementation.BuildParameters[0] = "--unsafe" },
			match:  "build_parameters",
		},
		{
			name:   "unbounded timeout",
			mutate: func(profile *Profile) { profile.Timeouts.Canary = "0s" },
			match:  "timeout",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profile := cloneProfile(t, fixture.profile)
			test.mutate(&profile)
			if _, err := Validate(profile, Options{Now: fixtureNow}); err == nil ||
				!strings.Contains(err.Error(), test.match) {
				t.Fatalf("Validate() error = %v, want %q", err, test.match)
			}
		})
	}
}

func TestProfileRejectsProofKeyReferenceOverlapWithoutReadingKeys(t *testing.T) {
	fixture := newTrustFixture(t)
	reference := fixture.profile.Certificates.SigningKey.Reference
	if _, err := Validate(fixture.profile, Options{
		Now: fixtureNow, ForbiddenKeyReferences: []string{reference},
	}); err == nil || !strings.Contains(err.Error(), "proof-signing") {
		t.Fatalf("Validate() error = %v", err)
	}
	if _, err := os.Stat(reference); !os.IsNotExist(err) {
		t.Fatalf("test key unexpectedly exists: %v", err)
	}
}

func TestProfileRejectsMissingOrUnsafePublicMaterial(t *testing.T) {
	fixture := newTrustFixture(t)
	missing := cloneProfile(t, fixture.profile)
	missing.Certificates.ServerEncryptionChainFile = filepath.Join(fixture.dir, "missing.pem")
	if _, err := Validate(missing, Options{Now: fixtureNow}); err == nil {
		t.Fatal("missing encryption certificate was accepted")
	}
	if runtime.GOOS != "windows" {
		link := filepath.Join(fixture.dir, "signing-link.pem")
		if err := os.Symlink(fixture.profile.Certificates.ServerSigningChainFile, link); err != nil {
			t.Fatal(err)
		}
		symlinked := cloneProfile(t, fixture.profile)
		symlinked.Certificates.ServerSigningChainFile = link
		if _, err := Validate(symlinked, Options{Now: fixtureNow}); err == nil ||
			!strings.Contains(err.Error(), "non-symlink") {
			t.Fatalf("symlink error = %v", err)
		}
	}
}

func TestProfileRejectsWrongCertificateModeRoleIdentityAndValidity(t *testing.T) {
	t.Run("standard CA", func(t *testing.T) {
		fixture := newTrustFixture(t)
		fixture.profile.Certificates.ServerCAFile = writeStandardCA(t, fixture.dir)
		if _, err := Validate(fixture.profile, Options{Now: fixtureNow}); err == nil ||
			!strings.Contains(err.Error(), "SM2-with-SM3") {
			t.Fatalf("standard CA error = %v", err)
		}
	})
	t.Run("expired chain", func(t *testing.T) {
		fixture := newTrustFixture(t)
		if _, err := Validate(fixture.profile, Options{Now: fixtureNow.Add(48 * time.Hour)}); err == nil ||
			!strings.Contains(err.Error(), "expired") {
			t.Fatalf("expired chain error = %v", err)
		}
	})
	t.Run("wrong role", func(t *testing.T) {
		fixture := newTrustFixture(t)
		writeEndpoint(t, fixture.profile.Certificates.ServerEncryptionChainFile,
			fixture.serverCA, fixture.serverCAKey, 12, "trustdb.example",
			smx509.KeyUsageDigitalSignature, fixtureNow.Add(-time.Hour), fixtureNow.Add(24*time.Hour), nil)
		if _, err := Validate(fixture.profile, Options{Now: fixtureNow}); err == nil ||
			!strings.Contains(err.Error(), "encryption") {
			t.Fatalf("wrong role error = %v", err)
		}
	})
	t.Run("identity mismatch", func(t *testing.T) {
		fixture := newTrustFixture(t)
		writeEndpoint(t, fixture.profile.Certificates.ServerEncryptionChainFile,
			fixture.serverCA, fixture.serverCAKey, 13, "other.example",
			smx509.KeyUsageKeyEncipherment, fixtureNow.Add(-time.Hour), fixtureNow.Add(24*time.Hour), nil)
		if _, err := Validate(fixture.profile, Options{Now: fixtureNow}); err == nil {
			t.Fatal("mismatched dual-certificate identity was accepted")
		}
	})
	t.Run("same public key", func(t *testing.T) {
		fixture := newTrustFixture(t)
		signingKey := certificatePrivateKey(t, fixture.dir, "shared")
		writeEndpoint(t, fixture.profile.Certificates.ServerSigningChainFile,
			fixture.serverCA, fixture.serverCAKey, 14, "trustdb.example",
			smx509.KeyUsageDigitalSignature, fixtureNow.Add(-time.Hour), fixtureNow.Add(24*time.Hour), signingKey)
		writeEndpoint(t, fixture.profile.Certificates.ServerEncryptionChainFile,
			fixture.serverCA, fixture.serverCAKey, 15, "trustdb.example",
			smx509.KeyUsageKeyEncipherment, fixtureNow.Add(-time.Hour), fixtureNow.Add(24*time.Hour), signingKey)
		if _, err := Validate(fixture.profile, Options{Now: fixtureNow}); err == nil ||
			!strings.Contains(err.Error(), "distinct SM2 public keys") {
			t.Fatalf("same key error = %v", err)
		}
	})
}

func TestProfileRejectsStaleMissingAndRevokingCRLs(t *testing.T) {
	t.Run("stale", func(t *testing.T) {
		fixture := newTrustFixture(t)
		writeCRL(t, fixture.profile.Revocation.CRLFiles[0], fixture.serverCA, fixture.serverCAKey,
			fixtureNow.Add(-48*time.Hour), fixtureNow.Add(time.Hour), nil)
		if _, err := Validate(fixture.profile, Options{Now: fixtureNow}); err == nil ||
			!strings.Contains(err.Error(), "max_staleness") {
			t.Fatalf("stale CRL error = %v", err)
		}
	})
	t.Run("missing issuer", func(t *testing.T) {
		fixture := newTrustFixture(t)
		fixture.profile.Revocation.CRLFiles = fixture.profile.Revocation.CRLFiles[:1]
		if _, err := Validate(fixture.profile, Options{Now: fixtureNow}); err == nil ||
			!strings.Contains(err.Error(), "every TLCP server issuer and client trust anchor") {
			t.Fatalf("missing CRL error = %v", err)
		}
	})
	t.Run("missing authority key identifier", func(t *testing.T) {
		fixture := newTrustFixture(t)
		crl, err := loadCRL(fixture.profile.Revocation.CRLFiles[0])
		if err != nil {
			t.Fatal(err)
		}
		crl.AuthorityKeyId = nil
		if _, err := findCRLIssuer(crl, []*smx509.Certificate{fixture.serverCA}); err == nil ||
			!strings.Contains(err.Error(), "authority key identifier is required") {
			t.Fatalf("missing CRL authority key identifier error = %v", err)
		}
	})
	t.Run("revoked server certificate", func(t *testing.T) {
		fixture := newTrustFixture(t)
		writeCRL(t, fixture.profile.Revocation.CRLFiles[0], fixture.serverCA, fixture.serverCAKey,
			fixtureNow.Add(-time.Hour), fixtureNow.Add(time.Hour), []*big.Int{fixture.signingCertificate.SerialNumber})
		if _, err := Validate(fixture.profile, Options{Now: fixtureNow}); err == nil ||
			!strings.Contains(err.Error(), "revokes") {
			t.Fatalf("revoked certificate error = %v", err)
		}
	})
}

func TestProfileRequiresCRLForEveryServerIntermediate(t *testing.T) {
	fixture := newTrustFixture(t)
	intermediate, intermediateKey := writeIntermediateCA(
		t,
		filepath.Join(fixture.dir, "server-intermediate.pem"),
		fixture.serverCA,
		fixture.serverCAKey,
		20,
		"TLCP Server Intermediate",
	)
	fixture.signingCertificate = writeEndpoint(
		t,
		fixture.profile.Certificates.ServerSigningChainFile,
		intermediate,
		intermediateKey,
		21,
		"trustdb.example",
		smx509.KeyUsageDigitalSignature,
		fixtureNow.Add(-time.Hour),
		fixtureNow.Add(24*time.Hour),
		nil,
	)
	appendCertificatePEM(t, fixture.profile.Certificates.ServerSigningChainFile, intermediate)
	fixture.encryptionCertificate = writeEndpoint(
		t,
		fixture.profile.Certificates.ServerEncryptionChainFile,
		intermediate,
		intermediateKey,
		22,
		"trustdb.example",
		smx509.KeyUsageKeyEncipherment,
		fixtureNow.Add(-time.Hour),
		fixtureNow.Add(24*time.Hour),
		nil,
	)
	appendCertificatePEM(t, fixture.profile.Certificates.ServerEncryptionChainFile, intermediate)
	intermediateCRL := filepath.Join(fixture.dir, "server-intermediate.crl")
	writeCRL(
		t,
		intermediateCRL,
		intermediate,
		intermediateKey,
		fixtureNow.Add(-time.Hour),
		fixtureNow.Add(12*time.Hour),
		nil,
	)
	fixture.profile.Revocation.CRLFiles = append(fixture.profile.Revocation.CRLFiles, intermediateCRL)
	if _, err := Validate(fixture.profile, Options{Now: fixtureNow}); err != nil {
		t.Fatalf("Validate() with intermediate error = %v", err)
	}

	fixture.profile.Revocation.CRLFiles = fixture.profile.Revocation.CRLFiles[:2]
	if _, err := Validate(fixture.profile, Options{Now: fixtureNow}); err == nil ||
		!strings.Contains(err.Error(), "every TLCP server issuer") {
		t.Fatalf("missing intermediate CRL error = %v", err)
	}
}

func TestLoadAndValidateRejectsDirtyAndSymlinkProfilePaths(t *testing.T) {
	fixture := newTrustFixture(t)
	data := marshalProfile(t, fixture.profile)
	path := filepath.Join(fixture.dir, "profile.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadAndValidate(path, Options{Now: fixtureNow}); err != nil {
		t.Fatalf("LoadAndValidate() error = %v", err)
	}
	dirty := filepath.Dir(path) + string(filepath.Separator) + "." + string(filepath.Separator) + filepath.Base(path)
	if _, _, err := LoadAndValidate(dirty, Options{Now: fixtureNow}); err == nil ||
		!strings.Contains(err.Error(), "absolute clean path") {
		t.Fatalf("dirty path error = %v", err)
	}
	if runtime.GOOS != "windows" {
		link := filepath.Join(fixture.dir, "profile-link.json")
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		if _, _, err := LoadAndValidate(link, Options{Now: fixtureNow}); err == nil ||
			!strings.Contains(err.Error(), "non-symlink") {
			t.Fatalf("profile symlink error = %v", err)
		}
	}
}

func newTrustFixture(t *testing.T) trustFixture {
	t.Helper()
	dir := t.TempDir()
	serverCA, serverCAKey := writeCA(t, filepath.Join(dir, "server-ca.pem"), 1, "TLCP Server CA")
	clientCA, clientCAKey := writeCA(t, filepath.Join(dir, "client-ca.pem"), 2, "TLCP Client CA")
	signing := writeEndpoint(t, filepath.Join(dir, "server-signing.pem"), serverCA, serverCAKey,
		10, "trustdb.example", smx509.KeyUsageDigitalSignature,
		fixtureNow.Add(-time.Hour), fixtureNow.Add(24*time.Hour), nil)
	encryption := writeEndpoint(t, filepath.Join(dir, "server-encryption.pem"), serverCA, serverCAKey,
		11, "trustdb.example", smx509.KeyUsageKeyEncipherment,
		fixtureNow.Add(-time.Hour), fixtureNow.Add(24*time.Hour), nil)
	writeCRL(t, filepath.Join(dir, "server-ca.crl"), serverCA, serverCAKey,
		fixtureNow.Add(-time.Hour), fixtureNow.Add(12*time.Hour), nil)
	writeCRL(t, filepath.Join(dir, "client-ca.crl"), clientCA, clientCAKey,
		fixtureNow.Add(-time.Hour), fixtureNow.Add(12*time.Hour), nil)
	goldenPath := filepath.Join("..", "..", "test", "vectors", "tlcp-gateway-profile-v1.json")
	golden, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	golden = bytes.ReplaceAll(golden, []byte("${FIXTURE_DIR}"), []byte(filepath.ToSlash(dir)))
	profile, err := Decode(golden)
	if err != nil {
		t.Fatal(err)
	}
	return trustFixture{
		dir: dir, profile: profile,
		serverCA: serverCA, serverCAKey: serverCAKey,
		clientCA: clientCA, clientCAKey: clientCAKey,
		signingCertificate: signing, encryptionCertificate: encryption,
	}
}

func writeCA(t *testing.T, path string, serial int64, commonName string) (*smx509.Certificate, *sm2.PrivateKey) {
	t.Helper()
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &smx509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             fixtureNow.Add(-24 * time.Hour),
		NotAfter:              fixtureNow.Add(24 * time.Hour),
		SignatureAlgorithm:    smx509.SM2WithSM3,
		KeyUsage:              smx509.KeyUsageDigitalSignature | smx509.KeyUsageCertSign | smx509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{byte(serial), 1, 2, 3},
	}
	der, err := smx509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, path, "CERTIFICATE", der)
	certificate, err := smx509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key
}

func writeIntermediateCA(
	t *testing.T,
	path string,
	parent *smx509.Certificate,
	parentKey *sm2.PrivateKey,
	serial int64,
	commonName string,
) (*smx509.Certificate, *sm2.PrivateKey) {
	t.Helper()
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &smx509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             fixtureNow.Add(-24 * time.Hour),
		NotAfter:              fixtureNow.Add(24 * time.Hour),
		SignatureAlgorithm:    smx509.SM2WithSM3,
		KeyUsage:              smx509.KeyUsageDigitalSignature | smx509.KeyUsageCertSign | smx509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{byte(serial), 1, 2, 3},
		AuthorityKeyId:        parent.SubjectKeyId,
	}
	der, err := smx509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, path, "CERTIFICATE", der)
	certificate, err := smx509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key
}

func writeEndpoint(t *testing.T, path string, ca *smx509.Certificate, caKey *sm2.PrivateKey,
	serial int64, commonName string, usage smx509.KeyUsage, notBefore, notAfter time.Time, key *sm2.PrivateKey,
) *smx509.Certificate {
	t.Helper()
	if key == nil {
		key = certificatePrivateKey(t, filepath.Dir(path), filepath.Base(path))
	}
	template := &smx509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: commonName},
		DNSNames:              []string{commonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		SignatureAlgorithm:    smx509.SM2WithSM3,
		KeyUsage:              usage,
		ExtKeyUsage:           []smx509.ExtKeyUsage{smx509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		AuthorityKeyId:        ca.SubjectKeyId,
	}
	der, err := smx509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, path, "CERTIFICATE", der)
	certificate, err := smx509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func certificatePrivateKey(t *testing.T, _ string, _ string) *sm2.PrivateKey {
	t.Helper()
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func writeCRL(t *testing.T, path string, ca *smx509.Certificate, caKey *sm2.PrivateKey,
	thisUpdate, nextUpdate time.Time, revoked []*big.Int,
) {
	t.Helper()
	entries := make([]smx509.RevocationListEntry, 0, len(revoked))
	for _, serial := range revoked {
		entries = append(entries, smx509.RevocationListEntry{
			SerialNumber:   new(big.Int).Set(serial),
			RevocationTime: thisUpdate,
		})
	}
	der, err := smx509.CreateRevocationList(rand.Reader, &smx509.RevocationList{
		SignatureAlgorithm:        smx509.SM2WithSM3,
		RevokedCertificateEntries: entries,
		Number:                    big.NewInt(1),
		ThisUpdate:                thisUpdate,
		NextUpdate:                nextUpdate,
	}, ca, caKey)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, path, "X509 CRL", der)
}

func writeStandardCA(t *testing.T, dir string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &cryptox509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "Standard CA"},
		NotBefore:             fixtureNow.Add(-time.Hour),
		NotAfter:              fixtureNow.Add(time.Hour),
		KeyUsage:              cryptox509.KeyUsageCertSign | cryptox509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := cryptox509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "standard-ca.pem")
	writePEM(t, path, "CERTIFICATE", der)
	return path
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func appendCertificatePEM(t *testing.T, path string, certificate *smx509.Certificate) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate.Raw,
	})); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func marshalProfile(t *testing.T, profile Profile) []byte {
	t.Helper()
	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func cloneProfile(t *testing.T, profile Profile) Profile {
	t.Helper()
	clone, err := Decode(marshalProfile(t, profile))
	if err != nil {
		t.Fatal(err)
	}
	return clone
}
