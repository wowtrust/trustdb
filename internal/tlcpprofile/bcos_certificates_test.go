package tlcpprofile

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

func TestValidateSM2ClientDualCertificateFiles(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	caPath := filepath.Join(root, "sm-ca.crt")
	ca, caKey := writeCA(t, caPath, 100, "BCOS Guomi CA")
	signingKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encryptionKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingCertPath := filepath.Join(root, "sm-sdk.crt")
	encryptionCertPath := filepath.Join(root, "sm-ensdk.crt")
	writeBCOSClientCertificate(
		t, signingCertPath, ca, caKey, signingKey, 101, "sdk",
		smx509.KeyUsageDigitalSignature|smx509.KeyUsageContentCommitment,
	)
	writeBCOSClientCertificate(
		t, encryptionCertPath, ca, caKey, encryptionKey, 102, "ensdk",
		smx509.KeyUsageKeyEncipherment|smx509.KeyUsageDataEncipherment|smx509.KeyUsageKeyAgreement,
	)
	signingKeyPath := writeSM2PrivateKey(t, root, "sm-sdk.key", signingKey)
	encryptionKeyPath := writeSM2PrivateKey(t, root, "sm-ensdk.key", encryptionKey)

	if err := ValidateSM2ClientDualCertificateFiles(
		caPath,
		signingCertPath,
		signingKeyPath,
		encryptionCertPath,
		encryptionKeyPath,
		fixtureNow,
	); err != nil {
		t.Fatalf("valid BCOS Guomi dual certificate identity rejected: %v", err)
	}
	if err := ValidateSM2ClientDualCertificateFiles(
		caPath,
		encryptionCertPath,
		encryptionKeyPath,
		signingCertPath,
		signingKeyPath,
		fixtureNow,
	); err == nil || !strings.Contains(err.Error(), "signing") {
		t.Fatalf("swapped certificate roles error = %v", err)
	}
	if err := ValidateSM2ClientDualCertificateFiles(
		caPath,
		signingCertPath,
		encryptionKeyPath,
		encryptionCertPath,
		encryptionKeyPath,
		fixtureNow,
	); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched certificate key error = %v", err)
	}
}

func writeBCOSClientCertificate(
	t *testing.T,
	path string,
	ca *smx509.Certificate,
	caKey, key *sm2.PrivateKey,
	serial int64,
	organizationalUnit string,
	usage smx509.KeyUsage,
) {
	t.Helper()
	template := &smx509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName:         "FISCO-BCOS",
			Organization:       []string{"fisco-bcos"},
			OrganizationalUnit: []string{organizationalUnit},
		},
		NotBefore:             fixtureNow.Add(-time.Hour),
		NotAfter:              fixtureNow.Add(time.Hour),
		SignatureAlgorithm:    smx509.SM2WithSM3,
		KeyUsage:              usage,
		BasicConstraintsValid: true,
		AuthorityKeyId:        ca.SubjectKeyId,
	}
	der, err := smx509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeSM2PrivateKey(t *testing.T, root, name string, key *sm2.PrivateKey) string {
	t.Helper()
	der, err := smx509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, name)
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
