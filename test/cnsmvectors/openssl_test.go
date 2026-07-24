package cnsmvectors

import (
	"bytes"
	"encoding/hex"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

func TestIndependentOpenSSLConfirmsCriticalCorpusVectors(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("OpenSSL 3 is required by the CN_SM_V1 interoperability gate: %v", err)
		}
		t.Skip("OpenSSL executable is unavailable")
	}
	corpus, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	publicPaths := map[string]string{}
	for name, identity := range map[string]Identity{
		"client": corpus.Identities.Client, "server": corpus.Identities.Server, "registry": corpus.Identities.Registry,
	} {
		publicBytes, err := hex.DecodeString(identity.PublicKeyHex)
		if err != nil {
			t.Fatal(err)
		}
		publicKey, err := sm2.NewPublicKey(publicBytes)
		if err != nil {
			t.Fatal(err)
		}
		der, err := smx509.MarshalPKIXPublicKey(publicKey)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, name+".pem")
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		publicPaths[name] = path
	}
	for _, item := range []struct {
		name     string
		identity string
		artifact Artifact
	}{
		{"client-claim", "client", corpus.Artifacts.ClientClaim},
		{"accepted-receipt", "server", corpus.Artifacts.AcceptedReceipt},
		{"committed-receipt", "server", corpus.Artifacts.CommittedReceipt},
		{"signed-tree-head", "server", corpus.Artifacts.SignedTreeHead},
		{"key-event", "registry", corpus.Artifacts.KeyEvent},
	} {
		t.Run(item.name, func(t *testing.T) {
			input, err := item.artifact.SignatureInput()
			if err != nil {
				t.Fatal(err)
			}
			signature, err := item.artifact.SignatureDER()
			if err != nil {
				t.Fatal(err)
			}
			signaturePath := filepath.Join(dir, item.name+".der")
			if err := os.WriteFile(signaturePath, signature, 0o600); err != nil {
				t.Fatal(err)
			}
			output, err := opensslCommand(
				openssl,
				input,
				"dgst", "-sm3",
				"-verify", publicPaths[item.identity],
				"-signature", signaturePath,
				"-sigopt", "distid:"+corpus.Provenance.SM2UserIDASCII,
			)
			if err != nil {
				if os.Getenv("CI") != "" {
					t.Fatalf("OpenSSL 3 SM2 verification is required: %v output=%q", err, output)
				}
				t.Skipf("local OpenSSL/LibreSSL lacks compatible SM2 support: %v output=%q", err, output)
			}
			if !strings.Contains(string(output), "Verified OK") {
				t.Fatalf("OpenSSL output = %q", output)
			}
			if _, err := opensslCommand(
				openssl,
				input,
				"dgst", "-sm3",
				"-verify", publicPaths[item.identity],
				"-signature", signaturePath,
				"-sigopt", "distid:wrong-user-id",
			); err == nil {
				t.Fatal("OpenSSL accepted the corpus signature with the wrong SM2 user ID")
			}
		})
	}
	for _, content := range corpus.Contents {
		t.Run("sm3-"+content.ID, func(t *testing.T) {
			raw, err := content.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			got, err := opensslCommand(openssl, raw, "dgst", "-sm3", "-binary")
			if err != nil {
				if os.Getenv("CI") != "" {
					t.Fatalf("OpenSSL 3 SM3 is required: %v", err)
				}
				t.Skipf("local OpenSSL/LibreSSL lacks SM3: %v", err)
			}
			want, err := hex.DecodeString(content.DigestHex)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("OpenSSL SM3 = %x, want %x", got, want)
			}
		})
	}
}

func opensslCommand(path string, stdin []byte, args ...string) ([]byte, error) {
	command := exec.Command(path, args...)
	command.Stdin = bytes.NewReader(stdin)
	return command.CombinedOutput()
}
