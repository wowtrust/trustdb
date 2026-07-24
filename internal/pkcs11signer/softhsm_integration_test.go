//go:build pkcs11 && cgo && pkcs11_integration

package pkcs11signer_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/keydescriptor"
	"github.com/wowtrust/trustdb/internal/pkcs11signer"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"github.com/wowtrust/trustdb/sdk/signerplugin"
)

func TestSoftHSMEd25519ProviderEndToEnd(t *testing.T) {
	modulePath := requiredEnvironment(t, "TRUSTDB_PKCS11_INTEGRATION_MODULE")
	binaryPath := requiredEnvironment(t, "TRUSTDB_PKCS11_INTEGRATION_BINARY")
	tokenURI := requiredEnvironment(t, pkcs11signer.EnvTokenURI)
	keyURI := requiredEnvironment(t, "TRUSTDB_PKCS11_INTEGRATION_KEY_URI")
	pinPath := requiredEnvironment(t, pkcs11signer.EnvPINFile)

	pin, err := pkcs11signer.NewFilePINSource(pinPath)
	if err != nil {
		t.Fatal(err)
	}
	config := pkcs11signer.Config{
		PluginID:           pkcs11signer.DefaultPluginID,
		TokenURI:           tokenURI,
		MaxConcurrentSigns: 8,
		PIN:                pin,
		Profiles: []pkcs11signer.Profile{{
			CryptoSuite:     signerplugin.SuiteINTLV1,
			Mechanism:       0x1057,
			SignatureFormat: pkcs11signer.SignatureFormatRaw,
		}},
	}
	backend, err := pkcs11signer.OpenNativeBackend(modulePath)
	if err != nil {
		t.Fatalf("OpenNativeBackend() error = %v", err)
	}
	direct, err := pkcs11signer.New(context.Background(), config, backend)
	if err != nil {
		_ = backend.Close()
		t.Fatalf("New() error = %v", err)
	}
	key := pluginKey(keyURI)
	publicKey, err := direct.PublicKey(context.Background(), key)
	if err != nil {
		_ = direct.Close()
		t.Fatalf("direct PublicKey() error = %v", err)
	}
	if err := direct.Close(); err != nil {
		t.Fatalf("direct Close() error = %v", err)
	}

	provider, err := keydescriptor.NewPluginSignerProvider(keydescriptor.SignerPluginOptions{
		Provider: keydescriptor.ProviderPKCS11,
		Command:  binaryPath,
		InheritEnv: []string{
			pkcs11signer.EnvModulePath,
			pkcs11signer.EnvTokenURI,
			pkcs11signer.EnvPINFile,
			pkcs11signer.EnvAlgorithms,
			pkcs11signer.EnvMaxConcurrency,
			"SOFTHSM2_CONF",
		},
		StartTimeout:   10 * time.Second,
		RPCTimeout:     10 * time.Second,
		MaxConcurrency: 8,
		Stderr:         os.Stderr,
	})
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := keydescriptor.NewResolver(provider)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resolver.Close() })
	descriptor := keydescriptor.Descriptor{
		SchemaVersion: keydescriptor.SchemaV1,
		Kind:          keydescriptor.KindSigner,
		Provider:      keydescriptor.ProviderPKCS11,
		CryptoSuite:   cryptosuite.INTLV1,
		KeyID:         "softhsm-ed25519",
		Algorithm:     signerplugin.AlgorithmEd25519,
		PublicKey: keydescriptor.PublicKeyMaterial{
			Encoding: signerplugin.Ed25519PublicKeyEncoding,
			Bytes:    publicKey,
		},
		PKCS11: &keydescriptor.PKCS11KeyReference{URI: keyURI},
	}
	signer, err := resolver.ResolveSigner(context.Background(), descriptor, t.TempDir())
	if err != nil {
		t.Fatalf("ResolveSigner() error = %v", err)
	}

	const operations = 16
	var wait sync.WaitGroup
	errorsCh := make(chan error, operations)
	wait.Add(operations)
	for i := 0; i < operations; i++ {
		go func(index int) {
			defer wait.Done()
			message := []byte{byte(index), 0x54, 0x44, 0x42}
			signature, signErr := trustcrypto.Sign(context.Background(), cryptosuite.INTLV1, signer, message)
			if signErr != nil {
				errorsCh <- signErr
				return
			}
			if !ed25519.Verify(publicKey, message, signature.Signature) {
				errorsCh <- errors.New("host accepted a signature that failed local Ed25519 verification")
			}
		}(i)
	}
	wait.Wait()
	close(errorsCh)
	for err := range errorsCh {
		t.Error(err)
	}
}

func pluginKey(uri string) signerplugin.Key {
	return signerplugin.Key{
		Binding: signerplugin.Binding{
			ProtocolVersion:   signerplugin.ProtocolVersion,
			PluginID:          pkcs11signer.DefaultPluginID,
			ProviderKind:      signerplugin.ProviderPKCS11,
			CryptoSuite:       signerplugin.SuiteINTLV1,
			Algorithm:         signerplugin.AlgorithmEd25519,
			PublicKeyEncoding: signerplugin.Ed25519PublicKeyEncoding,
			SignatureEncoding: signerplugin.Ed25519SignatureEncoding,
			KeyID:             "softhsm-ed25519",
		},
		Reference: signerplugin.KeyReference{
			PKCS11: &signerplugin.PKCS11KeyReference{URI: uri},
		},
	}
}

func requiredEnvironment(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required", name)
	}
	return value
}
