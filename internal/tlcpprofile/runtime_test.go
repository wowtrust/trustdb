package tlcpprofile

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareAndVerifyRuntimeBindsProfileTrustAndConfiguration(t *testing.T) {
	fixture := newTrustFixture(t)
	profilePath := filepath.Join(fixture.dir, "profile.json")
	if err := os.WriteFile(profilePath, marshalProfile(t, fixture.profile), 0o600); err != nil {
		t.Fatal(err)
	}
	options := RuntimeOptions{
		ExpectedGatewayImageDigest: fixture.profile.Implementation.GatewayImageDigest,
		ConfigurationPath:          filepath.Join(fixture.dir, "nginx.conf"),
		ManifestPath:               filepath.Join(fixture.dir, "runtime-manifest.json"),
		Now:                        fixtureNow,
	}
	prepared, err := PrepareRuntime(profilePath, options)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyRuntime(profilePath, options)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.ProfileSHA256 != verified.ProfileSHA256 ||
		prepared.ConfigurationSHA256 != verified.ConfigurationSHA256 ||
		len(verified.Validation.ProofSigningPublicKeySHA256) != 1 {
		t.Fatalf("runtime binding drifted: prepared=%+v verified=%+v", prepared, verified)
	}
	configuration, err := os.ReadFile(options.ConfigurationPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"client_header_timeout 10s;",
		"client_max_body_size 16m;",
		"client_body_temp_path /var/cache/tlcp-gateway/client-body;",
		"http2_max_concurrent_streams 64;",
		"limit_conn tlcp_clients 32;",
		"proxy_connect_timeout 5s;",
		"grpc_connect_timeout 5s;",
	} {
		if !bytes.Contains(configuration, []byte(required)) {
			t.Fatalf("runtime configuration does not contain %q", required)
		}
	}
}

func TestVerifyRuntimeRejectsEveryBoundInputDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, profilePath string, options RuntimeOptions, fixture trustFixture)
	}{
		{
			name: "configuration",
			mutate: func(t *testing.T, _ string, options RuntimeOptions, _ trustFixture) {
				t.Helper()
				if err := os.WriteFile(options.ConfigurationPath, []byte("events {}\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "profile",
			mutate: func(t *testing.T, profilePath string, _ RuntimeOptions, fixture trustFixture) {
				t.Helper()
				profile := fixture.profile
				profile.ProfileID = "drifted"
				if err := os.WriteFile(profilePath, marshalProfile(t, profile), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "CRL bundle",
			mutate: func(t *testing.T, _ string, _ RuntimeOptions, fixture trustFixture) {
				t.Helper()
				if err := os.WriteFile(
					fixture.profile.Revocation.GatewayCRLBundleFile,
					[]byte("not a CRL"),
					0o600,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "TrustDB active identity manifest",
			mutate: func(t *testing.T, _ string, _ RuntimeOptions, fixture trustFixture) {
				t.Helper()
				writeProofIdentityManifest(
					t,
					fixture.profile.TrustDBIdentityManifestFile,
					proofVerifierDescriptor(t, reportPublicKey(t)),
				)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTrustFixture(t)
			profilePath := filepath.Join(fixture.dir, "profile.json")
			if err := os.WriteFile(profilePath, marshalProfile(t, fixture.profile), 0o600); err != nil {
				t.Fatal(err)
			}
			options := RuntimeOptions{
				ExpectedGatewayImageDigest: fixture.profile.Implementation.GatewayImageDigest,
				ConfigurationPath:          filepath.Join(fixture.dir, "nginx.conf"),
				ManifestPath:               filepath.Join(fixture.dir, "runtime-manifest.json"),
				Now:                        fixtureNow,
			}
			if _, err := PrepareRuntime(profilePath, options); err != nil {
				t.Fatal(err)
			}
			test.mutate(t, profilePath, options, fixture)
			if _, err := VerifyRuntime(profilePath, options); err == nil {
				t.Fatalf("%s drift was accepted", test.name)
			}
		})
	}
}

func TestProductionRequiresTrustDBIdentityManifest(t *testing.T) {
	fixture := newTrustFixture(t)
	fixture.profile.Environment = EnvironmentProduction
	fixture.profile.Certificates.SigningKey.Provider = KeyProviderSDF
	fixture.profile.Certificates.SigningKey.Reference = "engine:sdf:gateway-signing"
	fixture.profile.Certificates.EncryptionKey.Provider = KeyProviderSDF
	fixture.profile.Certificates.EncryptionKey.Reference = "engine:sdf:gateway-encryption"
	fixture.profile.TrustDBIdentityManifestFile = ""
	if _, err := Validate(fixture.profile, Options{Now: fixtureNow}); err == nil ||
		!strings.Contains(err.Error(), "trustdb_identity_manifest_file") {
		t.Fatalf("production profile without proof identities error = %v", err)
	}
}
