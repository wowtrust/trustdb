package tlcpprofile

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
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
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/keydescriptor"
)

var fixtureNow = time.Date(2026, 7, 24, 8, 0, 0, 0, time.UTC)

type trustFixture struct {
	dir                            string
	profile                        Profile
	serverCA                       *smx509.Certificate
	serverCAKey                    *sm2.PrivateKey
	clientCA                       *smx509.Certificate
	clientCAKey                    *sm2.PrivateKey
	signingCertificate             *smx509.Certificate
	encryptionCertificate          *smx509.Certificate
	readinessSigningCertificate    *smx509.Certificate
	readinessEncryptionCertificate *smx509.Certificate
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
		len(report.SigningPublicKeySHA256) != 64 ||
		len(report.EncryptionPublicKeySHA256) != 64 ||
		len(report.ReadinessSigningPublicKeySHA256) != 64 ||
		len(report.ReadinessEncryptionPublicKeySHA256) != 64 ||
		report.SigningCertificateSHA256 == report.EncryptionCertificateSHA256 ||
		report.SigningPublicKeySHA256 == report.EncryptionPublicKeySHA256 ||
		len(report.ServerCASHA256) != 1 ||
		len(report.ClientCASHA256) != 1 ||
		len(report.CRLIssuers) != 2 {
		t.Fatalf("unexpected validation report: %+v", report)
	}
}

func TestTrustDBIdentityManifestContainsOnlyAuthenticatedPublicMaterial(t *testing.T) {
	fixture := newTrustFixture(t)
	data, err := os.ReadFile(fixture.profile.TrustDBIdentityManifestFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"material_path",
		"credential",
		"private",
		"pkcs11",
		"sdf",
		"remote",
	} {
		if bytes.Contains(bytes.ToLower(data), []byte(forbidden)) {
			t.Fatalf("public identity manifest leaked %q: %s", forbidden, data)
		}
	}
	var manifest TrustDBIdentityManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.ProofSigner.PublicKeySHA256 = strings.Repeat("0", 64)
	tampered, err := encodeTrustDBIdentityManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		fixture.profile.TrustDBIdentityManifestFile,
		tampered,
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := Validate(fixture.profile, Options{Now: fixtureNow}); err == nil ||
		!strings.Contains(err.Error(), "metadata does not match") {
		t.Fatalf("tampered identity metadata error = %v", err)
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
			match:  "exactly 127.0.0.1",
		},
		{
			name:   "production file key",
			mutate: func(profile *Profile) { profile.Environment = EnvironmentProduction },
			match:  "test profiles",
		},
		{
			name: "production raw key path",
			mutate: func(profile *Profile) {
				profile.Environment = EnvironmentProduction
				profile.Certificates.SigningKey.Provider = KeyProviderSDF
				profile.Certificates.SigningKey.Reference = "/private/signing.key"
				profile.Certificates.EncryptionKey.Provider = KeyProviderSDF
				profile.Certificates.EncryptionKey.Reference = "engine:sdf:encryption-key"
			},
			match: "engine:<id>:<key-id>",
		},
		{
			name: "production provider and engine mismatch",
			mutate: func(profile *Profile) {
				profile.Environment = EnvironmentProduction
				profile.Certificates.SigningKey.Provider = KeyProviderSDF
				profile.Certificates.SigningKey.Reference = "engine:pkcs11:signing-key"
				profile.Certificates.EncryptionKey.Provider = KeyProviderSDF
				profile.Certificates.EncryptionKey.Reference = "engine:sdf:encryption-key"
			},
			match: "must match provider sdf",
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
			name: "unpinned tengine source",
			mutate: func(profile *Profile) {
				profile.Implementation.TengineSourceSHA256 = strings.Repeat("0", 64)
			},
			match: "pinned",
		},
		{
			name: "unpinned builder image",
			mutate: func(profile *Profile) {
				profile.Implementation.BuilderImage = "docker.io/library/debian:bookworm-slim@sha256:" +
					strings.Repeat("0", 64)
			},
			match: "pinned",
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

func TestLifecycleTimeoutSelectsEveryBoundedContract(t *testing.T) {
	profile := Profile{Timeouts: Timeouts{
		Startup: "11s",
		Reload:  "12s",
		Canary:  "13s",
	}}
	for _, test := range []struct {
		lifecycle string
		want      time.Duration
	}{
		{LifecycleStartup, 11 * time.Second},
		{LifecycleReload, 12 * time.Second},
		{LifecycleCanary, 13 * time.Second},
	} {
		got, err := LifecycleTimeout(profile, test.lifecycle)
		if err != nil {
			t.Fatal(err)
		}
		if got != test.want {
			t.Fatalf("LifecycleTimeout(%q) = %s, want %s", test.lifecycle, got, test.want)
		}
	}
	if _, err := LifecycleTimeout(profile, "shutdown"); err == nil {
		t.Fatal("unsupported lifecycle was accepted")
	}
}

func TestLifecycleTimeoutSecondsUsesIntegerCeiling(t *testing.T) {
	profile := Profile{Timeouts: Timeouts{
		Startup: "1m30s",
		Reload:  "90.001s",
		Canary:  "90s",
	}}
	for _, test := range []struct {
		lifecycle string
		want      uint64
	}{
		{LifecycleStartup, 90},
		{LifecycleReload, 91},
		{LifecycleCanary, 90},
	} {
		got, err := LifecycleTimeoutSeconds(profile, test.lifecycle)
		if err != nil {
			t.Fatal(err)
		}
		if got != test.want {
			t.Fatalf(
				"LifecycleTimeoutSeconds(%q) = %d, want %d",
				test.lifecycle,
				got,
				test.want,
			)
		}
	}
}

func TestProductionOpaqueEngineReferencesValidateWithoutReadingPrivateKeys(t *testing.T) {
	fixture := newTrustFixture(t)
	profile := fixture.profile
	profile.Environment = EnvironmentProduction
	profile.Certificates.SigningKey.Provider = KeyProviderSDF
	profile.Certificates.SigningKey.Reference = "engine:sdf:gateway-signing"
	profile.Certificates.EncryptionKey.Provider = KeyProviderSDF
	profile.Certificates.EncryptionKey.Reference = "engine:sdf:gateway-encryption"
	if _, err := Validate(profile, Options{Now: fixtureNow}); err != nil {
		t.Fatalf("Validate() production opaque keys error = %v", err)
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
	if _, err := Validate(fixture.profile, Options{
		Now: fixtureNow,
		ForbiddenPublicKeySHA256s: []string{
			fixture.profile.Certificates.SigningKey.PublicKeySHA256,
		},
	}); err == nil || !strings.Contains(err.Error(), "public key overlaps") {
		t.Fatalf("Validate() public-key alias error = %v", err)
	}
}

func TestProfileRejectsDeclaredPublicKeyFingerprintDrift(t *testing.T) {
	fixture := newTrustFixture(t)
	fixture.profile.Certificates.SigningKey.PublicKeySHA256 = strings.Repeat("a", 64)
	if _, err := Validate(fixture.profile, Options{Now: fixtureNow}); err == nil ||
		!strings.Contains(err.Error(), "fingerprint does not match") {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestProfileReadsTrustDBAuthenticatedProofIdentity(t *testing.T) {
	fixture := newTrustFixture(t)
	report, err := Validate(fixture.profile, Options{Now: fixtureNow})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.ProofKeyDescriptorSHA256) != 1 ||
		len(report.ProofSigningPublicKeySHA256) != 1 {
		t.Fatalf("unexpected proof-key inventory: %+v", report)
	}

	signer := proofVerifierDescriptor(t, reportPublicKey(t))
	signer.Kind = keydescriptor.KindSigner
	signer.Provider = keydescriptor.ProviderSoftware
	signer.Software = &keydescriptor.SoftwareKeyReference{
		MaterialPath: "proof.key",
		Encoding:     cryptosuite.Ed25519PrivateKeyEncoding,
		Protection:   keydescriptor.SoftwareProtectionPlaintextDev,
	}
	data, err := keydescriptor.Marshal(signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := WriteTrustDBIdentityManifest(
		fixture.profile.TrustDBIdentityManifestFile,
		data,
		nil,
	); err == nil ||
		!strings.Contains(err.Error(), "public verifier") {
		t.Fatalf("private signer identity error = %v", err)
	}
}

func TestProfileRejectsTransportKeyMatchingAuthoritativeProofDescriptor(t *testing.T) {
	fixture := newTrustFixture(t)
	publicKey, ok := fixture.signingCertificate.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("signing public key type = %T", fixture.signingCertificate.PublicKey)
	}
	writeProofIdentityManifest(t, fixture.profile.TrustDBIdentityManifestFile, keydescriptor.Descriptor{
		SchemaVersion: keydescriptor.SchemaV1,
		Kind:          keydescriptor.KindVerifier,
		Provider:      keydescriptor.ProviderPublic,
		CryptoSuite:   cryptosuite.CNSMV1,
		KeyID:         "active-proof-signer",
		Algorithm:     cryptosuite.SignatureSM2SM3,
		SM2UserID:     cryptosuite.SM2DefaultUserID,
		PublicKey: keydescriptor.PublicKeyMaterial{
			Encoding: cryptosuite.SM2PublicKeyEncoding,
			Bytes:    elliptic.Marshal(sm2.P256(), publicKey.X, publicKey.Y),
		},
	})
	if _, err := Validate(fixture.profile, Options{Now: fixtureNow}); err == nil ||
		!strings.Contains(err.Error(), "overlaps the active") {
		t.Fatalf("transport/proof overlap error = %v", err)
	}
}

func TestProfileRejectsReadinessKeyMatchingActiveProofSigner(t *testing.T) {
	fixture := newTrustFixture(t)
	publicKey, ok := fixture.readinessSigningCertificate.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf(
			"readiness signing public key type = %T",
			fixture.readinessSigningCertificate.PublicKey,
		)
	}
	writeProofIdentityManifest(
		t,
		fixture.profile.TrustDBIdentityManifestFile,
		keydescriptor.Descriptor{
			SchemaVersion: keydescriptor.SchemaV1,
			Kind:          keydescriptor.KindVerifier,
			Provider:      keydescriptor.ProviderPublic,
			CryptoSuite:   cryptosuite.CNSMV1,
			KeyID:         "active-proof-signer",
			Algorithm:     cryptosuite.SignatureSM2SM3,
			SM2UserID:     cryptosuite.SM2DefaultUserID,
			PublicKey: keydescriptor.PublicKeyMaterial{
				Encoding: cryptosuite.SM2PublicKeyEncoding,
				Bytes:    elliptic.Marshal(sm2.P256(), publicKey.X, publicKey.Y),
			},
		},
	)
	if _, err := Validate(fixture.profile, Options{Now: fixtureNow}); err == nil ||
		!strings.Contains(err.Error(), "readiness key overlaps") {
		t.Fatalf("readiness/proof overlap error = %v", err)
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
	t.Run("revoked readiness certificate", func(t *testing.T) {
		fixture := newTrustFixture(t)
		writeCRL(
			t,
			fixture.profile.Revocation.CRLFiles[1],
			fixture.clientCA,
			fixture.clientCAKey,
			fixtureNow.Add(-time.Hour),
			fixtureNow.Add(time.Hour),
			[]*big.Int{fixture.readinessSigningCertificate.SerialNumber},
		)
		if _, err := Validate(fixture.profile, Options{Now: fixtureNow}); err == nil ||
			!strings.Contains(err.Error(), "revokes") {
			t.Fatalf("revoked readiness certificate error = %v", err)
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
	fixture.profile.Certificates.SigningKey.PublicKeySHA256 =
		publicKeyFingerprint(fixture.signingCertificate)
	fixture.profile.Certificates.EncryptionKey.PublicKeySHA256 =
		publicKeyFingerprint(fixture.encryptionCertificate)
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
	readinessSigning := writeEndpointWithUsage(
		t,
		filepath.Join(dir, "client-signing.pem"),
		clientCA,
		clientCAKey,
		12,
		"TrustDB Readiness",
		smx509.KeyUsageDigitalSignature,
		smx509.ExtKeyUsageClientAuth,
		fixtureNow.Add(-time.Hour),
		fixtureNow.Add(24*time.Hour),
		nil,
	)
	readinessEncryption := writeEndpointWithUsage(
		t,
		filepath.Join(dir, "client-encryption.pem"),
		clientCA,
		clientCAKey,
		13,
		"TrustDB Readiness",
		smx509.KeyUsageKeyEncipherment,
		smx509.ExtKeyUsageClientAuth,
		fixtureNow.Add(-time.Hour),
		fixtureNow.Add(24*time.Hour),
		nil,
	)
	writeCRL(t, filepath.Join(dir, "server-ca.crl"), serverCA, serverCAKey,
		fixtureNow.Add(-time.Hour), fixtureNow.Add(12*time.Hour), nil)
	writeCRL(t, filepath.Join(dir, "client-ca.crl"), clientCA, clientCAKey,
		fixtureNow.Add(-time.Hour), fixtureNow.Add(12*time.Hour), nil)
	proofPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proofDescriptor := proofVerifierDescriptor(t, proofPublic)
	proofDescriptorData, err := keydescriptor.Marshal(proofDescriptor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := WriteTrustDBIdentityManifest(
		filepath.Join(dir, "trustdb-active-identities.json"),
		proofDescriptorData,
		nil,
	); err != nil {
		t.Fatal(err)
	}
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
	profile.Certificates.SigningKey.PublicKeySHA256 = publicKeyFingerprint(signing)
	profile.Certificates.EncryptionKey.PublicKeySHA256 = publicKeyFingerprint(encryption)
	return trustFixture{
		dir: dir, profile: profile,
		serverCA: serverCA, serverCAKey: serverCAKey,
		clientCA: clientCA, clientCAKey: clientCAKey,
		signingCertificate: signing, encryptionCertificate: encryption,
		readinessSigningCertificate:    readinessSigning,
		readinessEncryptionCertificate: readinessEncryption,
	}
}

func proofVerifierDescriptor(t *testing.T, publicKey []byte) keydescriptor.Descriptor {
	t.Helper()
	descriptor := keydescriptor.Descriptor{
		SchemaVersion: keydescriptor.SchemaV1,
		Kind:          keydescriptor.KindVerifier,
		Provider:      keydescriptor.ProviderPublic,
		CryptoSuite:   cryptosuite.INTLV1,
		KeyID:         "active-proof-signer",
		Algorithm:     cryptosuite.SignatureEd25519,
		PublicKey: keydescriptor.PublicKeyMaterial{
			Encoding: cryptosuite.Ed25519PublicKeyEncoding,
			Bytes:    append([]byte(nil), publicKey...),
		},
	}
	if err := descriptor.Validate(); err != nil {
		t.Fatal(err)
	}
	return descriptor
}

func reportPublicKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return publicKey
}

func writeProofIdentityManifest(
	t *testing.T,
	path string,
	descriptor keydescriptor.Descriptor,
) {
	t.Helper()
	data, err := keydescriptor.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := WriteTrustDBIdentityManifest(path, data, nil); err != nil {
		t.Fatal(err)
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
	return writeEndpointWithUsage(
		t,
		path,
		ca,
		caKey,
		serial,
		commonName,
		usage,
		smx509.ExtKeyUsageServerAuth,
		notBefore,
		notAfter,
		key,
	)
}

func writeEndpointWithUsage(
	t *testing.T,
	path string,
	ca *smx509.Certificate,
	caKey *sm2.PrivateKey,
	serial int64,
	commonName string,
	usage smx509.KeyUsage,
	extendedUsage smx509.ExtKeyUsage,
	notBefore, notAfter time.Time,
	key *sm2.PrivateKey,
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
		ExtKeyUsage:           []smx509.ExtKeyUsage{extendedUsage},
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
	refreshCRLBundle(t, filepath.Dir(path))
}

func refreshCRLBundle(t *testing.T, dir string) {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "*.crl"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(paths)
	var bundle []byte
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		bundle = append(bundle, data...)
	}
	if err := os.WriteFile(filepath.Join(dir, "crl-bundle.pem"), bundle, 0o600); err != nil {
		t.Fatal(err)
	}
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
