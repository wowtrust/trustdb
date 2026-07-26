package main

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/rand"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/wowtrust/trustdb/v2/internal/anchor/fiscobcos"
	trustconfig "github.com/wowtrust/trustdb/v2/internal/config"
	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/keydescriptor"
	"github.com/wowtrust/trustdb/v2/internal/securityaudit"
	"github.com/wowtrust/trustdb/v2/internal/trustcrypto"
)

func TestResolvePolicyCheckedSignerRejectsEgressBeforeStartingProvider(t *testing.T) {
	t.Parallel()
	privateKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := keydescriptor.Descriptor{
		SchemaVersion: keydescriptor.SchemaV1,
		Kind:          keydescriptor.KindSigner,
		Provider:      keydescriptor.ProviderRemote,
		CryptoSuite:   cryptosuite.CNSMV1,
		KeyID:         "remote-sm2",
		Algorithm:     cryptosuite.SignatureSM2SM3,
		SM2UserID:     cryptosuite.SM2DefaultUserID,
		PublicKey: keydescriptor.PublicKeyMaterial{
			Encoding: cryptosuite.SM2PublicKeyEncoding,
			Bytes:    elliptic.Marshal(sm2.P256(), privateKey.X, privateKey.Y),
		},
		Remote: &keydescriptor.RemoteKeyReference{
			Endpoint:      "https://unapproved-kms.example.cn:443",
			Handle:        "remote-sm2",
			CredentialRef: "env:KMS_TOKEN",
		},
	}
	path := filepath.Join(t.TempDir(), "remote-sm2.tdkey")
	if err := keydescriptor.WriteFile(path, descriptor); err != nil {
		t.Fatal(err)
	}
	rt := &runtimeConfig{cfg: trustconfig.Default()}
	rt.cfg.RunProfile = trustconfig.RunProfileChinaProduction
	rt.cfg.DeploymentPolicy = trustconfig.DeploymentPolicy{
		EgressMode:       trustconfig.EgressAllowlist,
		AllowedEndpoints: []string{"https://approved-kms.example.cn:443"},
		DNSAllowlist:     []string{"approved-kms.example.cn"},
	}
	_, _, err = rt.resolvePolicyCheckedSigner(context.Background(), path, "server")
	if err == nil || !strings.Contains(err.Error(), "not in deployment_policy.allowed_endpoints") {
		t.Fatalf("policy preflight error = %v", err)
	}
	if rt.signerResolver != nil {
		t.Fatal("policy rejection started or retained a signer provider")
	}
}

func TestValidateServeDeploymentPolicyCollectsLoadedRuntimeEndpoints(t *testing.T) {
	t.Parallel()
	rt := &runtimeConfig{cfg: trustconfig.Default()}
	rt.cfg.RunProfile = trustconfig.RunProfileChinaProduction
	rt.cfg.DeploymentPolicy = trustconfig.DeploymentPolicy{
		EgressMode: trustconfig.EgressAllowlist,
		AllowedEndpoints: []string{
			"https://kms.internal:443",
			"gm-tls://10.0.0.20:20200",
			"tikv://10.0.0.30:2379",
		},
		DNSAllowlist: []string{"kms.internal"},
	}
	rt.auditKey = keydescriptor.Descriptor{
		CryptoSuite: cryptosuite.CNSMV1,
		Provider:    keydescriptor.ProviderSDF,
	}
	server := keydescriptor.Descriptor{
		CryptoSuite: cryptosuite.CNSMV1,
		Provider:    keydescriptor.ProviderRemote,
		Remote: &keydescriptor.RemoteKeyReference{
			Endpoint: "https://kms.internal:443",
		},
	}
	trust := &fiscobcos.TrustConfig{
		CryptoMode:      fiscobcos.CryptoModeGuomi,
		Endpoints:       []string{"gm-tls://10.0.0.20:20200"},
		AccountProvider: fiscobcos.AccountProviderConfig{Provider: "sdf"},
		Certificates: fiscobcos.CertificateConfig{
			PinnedPeerCertificateHashes: [][]byte{make([]byte, 32)},
		},
	}
	if err := validateServeDeploymentPolicy(
		context.Background(),
		rt,
		server,
		"tikv",
		[]string{"10.0.0.30:2379"},
		"fisco-bcos",
		trust,
	); err != nil {
		t.Fatalf("strict runtime rejected: %v", err)
	}
	rt.cfg.DeploymentPolicy.AllowedEndpoints =
		rt.cfg.DeploymentPolicy.AllowedEndpoints[1:]
	err := validateServeDeploymentPolicy(
		context.Background(),
		rt,
		server,
		"tikv",
		[]string{"10.0.0.30:2379"},
		"fisco-bcos",
		trust,
	)
	if err == nil || !strings.Contains(err.Error(), "server signer endpoint") {
		t.Fatalf("unlisted signer endpoint error = %v", err)
	}
}

func TestValidateServeDeploymentPolicyRequiresAuditorForException(t *testing.T) {
	t.Parallel()
	rt := &runtimeConfig{cfg: trustconfig.Default()}
	rt.cfg.RunProfile = trustconfig.RunProfileOfflineIsolated
	rt.cfg.DeploymentPolicy = trustconfig.DeploymentPolicy{
		EgressMode: trustconfig.EgressDenyAll,
		Exceptions: []trustconfig.PolicyException{{
			ID: "CAB-1", Control: trustconfig.PolicyControlServerKeyCustody,
			Reason: "assessment fixture", ApprovedBy: "security", Ticket: "SEC-1",
			ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		}},
	}
	rt.auditKey = keydescriptor.Descriptor{
		CryptoSuite: cryptosuite.CNSMV1,
		Provider:    keydescriptor.ProviderSDF,
	}
	server := keydescriptor.Descriptor{
		CryptoSuite: cryptosuite.CNSMV1,
		Provider:    keydescriptor.ProviderSoftware,
	}
	err := validateServeDeploymentPolicy(
		context.Background(),
		rt,
		server,
		"pebble",
		nil,
		"off",
		nil,
	)
	if err == nil || !strings.Contains(err.Error(), "active security audit writer") {
		t.Fatalf("missing audit writer error = %v", err)
	}
	_, privateKey, err := trustcrypto.GenerateSM2Key()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := trustcrypto.NewSM2Signer("audit-sm2", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	rt.auditor, err = securityaudit.OpenWriter(context.Background(), securityaudit.Options{
		Path:           filepath.Join(directory, "security.audit"),
		CheckpointPath: filepath.Join(directory, "security.checkpoint"),
		MaxBytes:       1 << 20,
		Retention:      180 * 24 * time.Hour,
		Signer:         signer,
	})
	if err != nil {
		t.Fatal(err)
	}
	rt.auditActor = "test-operator"
	rt.auditRequestID = "test-request"
	t.Cleanup(func() { _ = rt.auditor.Close() })
	if err := validateServeDeploymentPolicy(
		context.Background(),
		rt,
		server,
		"pebble",
		nil,
		"off",
		nil,
	); err != nil {
		t.Fatalf("audited exception rejected: %v", err)
	}
	var exported bytes.Buffer
	if _, err := rt.auditor.ExportJSONL(context.Background(), &exported); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(exported.String(), `"action":"deployment.policy.exception"`) ||
		!strings.Contains(exported.String(), `"object":"CAB-1"`) {
		t.Fatalf("exception audit event missing: %s", exported.String())
	}
}
