//go:build sdf && cgo && sdf_vendor_integration && (linux || darwin)

package sdfsigner_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"

	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/keydescriptor"
	"github.com/wowtrust/trustdb/v2/internal/sdfsigner"
	"github.com/wowtrust/trustdb/v2/sdk/signerplugin"
)

func TestQualifiedSDFProviderEndToEnd(t *testing.T) {
	binaryPath := requiredEnvironment(t, "TRUSTDB_SDF_INTEGRATION_BINARY")
	keyIndexRaw := requiredEnvironment(t, "TRUSTDB_SDF_INTEGRATION_KEY_INDEX")
	keyIndexValue, err := strconv.ParseUint(keyIndexRaw, 10, 32)
	if err != nil || keyIndexValue == 0 {
		t.Fatal("TRUSTDB_SDF_INTEGRATION_KEY_INDEX must be a non-zero decimal integer")
	}
	expectedPublic, err := hex.DecodeString(requiredEnvironment(t, "TRUSTDB_SDF_INTEGRATION_PUBLIC_KEY_HEX"))
	if err != nil || len(expectedPublic) != 65 {
		t.Fatal("TRUSTDB_SDF_INTEGRATION_PUBLIC_KEY_HEX must encode one 65-byte SM2 public key")
	}
	if _, err := sm2.NewPublicKey(expectedPublic); err != nil {
		t.Fatal("TRUSTDB_SDF_INTEGRATION_PUBLIC_KEY_HEX is not a canonical SM2 public key")
	}

	environment, err := sdfsigner.LoadEnvironment()
	if err != nil {
		t.Fatalf("LoadEnvironment() error = %v", err)
	}
	adapterConfig := append([]byte(nil), environment.AdapterConfig...)
	clear(environment.AdapterConfig)
	environment.AdapterConfig = nil

	backend, err := sdfsigner.OpenNativeBackend(environment.AdapterPath, adapterConfig)
	if err != nil {
		clear(adapterConfig)
		t.Fatalf("OpenNativeBackend() error = %v", err)
	}
	direct, err := sdfsigner.New(context.Background(), environment.Config, backend)
	if err != nil {
		clear(adapterConfig)
		_ = backend.Close()
		t.Fatalf("New() error = %v", err)
	}
	key := pluginKey(environment.Config, uint32(keyIndexValue))
	publicKey, err := direct.PublicKey(context.Background(), key)
	if err != nil {
		clear(adapterConfig)
		_ = direct.Close()
		t.Fatalf("direct PublicKey() error = %v", err)
	}
	if !bytes.Equal(publicKey, expectedPublic) {
		clear(adapterConfig)
		_ = direct.Close()
		t.Fatal("device public key does not match the qualification trust material")
	}

	if environment.Config.RequiredCapabilities&sdfsigner.CapabilityRandom != 0 {
		random, err := direct.Random(context.Background(), 64)
		if err != nil || len(random) != 64 {
			clear(adapterConfig)
			_ = direct.Close()
			t.Fatalf("device Random() failed: %v", err)
		}
		clear(random)
	}
	descriptor := qualificationDescriptor(environment.Config, uint32(keyIndexValue), expectedPublic)
	var wrappedKeys []sdfsigner.WrappedSM4Key
	var iv, plaintext, ciphertext []byte
	if environment.Config.RequiredCapabilities&sdfsigner.SM4Capabilities == sdfsigner.SM4Capabilities {
		wrapped, generated, err := direct.GenerateSM4Session(context.Background())
		if err != nil {
			clear(adapterConfig)
			_ = direct.Close()
			t.Fatalf("GenerateSM4Session() error = %v", err)
		}
		wrappedKeys = append(wrappedKeys, wrapped)
		iv = make([]byte, sdfsigner.SM4BlockBytes)
		if _, err := rand.Read(iv); err != nil {
			clear(adapterConfig)
			_ = generated.Close()
			_ = direct.Close()
			t.Fatalf("generate IV error = %v", err)
		}
		plaintext = []byte("trustdb-sdf-sm4!")
		ciphertext, err = generated.EncryptCBC(context.Background(), iv, plaintext)
		if err != nil {
			clear(adapterConfig)
			_ = generated.Close()
			_ = direct.Close()
			t.Fatalf("EncryptCBC() error = %v", err)
		}
		if _, err := generated.MAC(context.Background(), iv, ciphertext); err != nil {
			clear(adapterConfig)
			clear(ciphertext)
			_ = generated.Close()
			_ = direct.Close()
			t.Fatalf("MAC() error = %v", err)
		}
		if err := generated.Close(); err != nil {
			clear(adapterConfig)
			clear(ciphertext)
			_ = direct.Close()
			t.Fatalf("generated session Close() error = %v", err)
		}
	}
	recoveryArtifact, err := direct.ExportRecoveryBundle(
		context.Background(),
		[]keydescriptor.Descriptor{descriptor},
		wrappedKeys,
	)
	if err != nil {
		clear(adapterConfig)
		clear(ciphertext)
		_ = direct.Close()
		t.Fatalf("ExportRecoveryBundle() error = %v", err)
	}
	if err := direct.Close(); err != nil {
		clear(adapterConfig)
		clear(recoveryArtifact)
		clear(ciphertext)
		t.Fatalf("first provider Close() error = %v", err)
	}

	restoredBackend, err := sdfsigner.OpenNativeBackend(environment.AdapterPath, adapterConfig)
	clear(adapterConfig)
	if err != nil {
		clear(recoveryArtifact)
		clear(ciphertext)
		t.Fatalf("reopen native backend error = %v", err)
	}
	restoredProvider, err := sdfsigner.New(context.Background(), environment.Config, restoredBackend)
	if err != nil {
		clear(recoveryArtifact)
		clear(ciphertext)
		_ = restoredBackend.Close()
		t.Fatalf("restart provider error = %v", err)
	}
	restoredRecovery, err := restoredProvider.RestoreRecoveryBundle(context.Background(), recoveryArtifact)
	clear(recoveryArtifact)
	if err != nil {
		clear(ciphertext)
		_ = restoredProvider.Close()
		t.Fatalf("RestoreRecoveryBundle() error = %v", err)
	}
	if len(restoredRecovery.SignerDescriptors) != 1 ||
		!bytes.Equal(restoredRecovery.SignerDescriptors[0].PublicKey.Bytes, expectedPublic) ||
		len(restoredRecovery.WrappedSM4Keys) != len(wrappedKeys) {
		clear(ciphertext)
		_ = restoredProvider.Close()
		t.Fatal("restored recovery inventory does not match qualification inputs")
	}
	if len(wrappedKeys) != 0 {
		restored, err := restoredProvider.ImportSM4Session(
			context.Background(),
			restoredRecovery.WrappedSM4Keys[0],
		)
		if err != nil {
			clear(ciphertext)
			_ = restoredProvider.Close()
			t.Fatalf("restore wrapped SM4 key error = %v", err)
		}
		roundTrip, err := restored.DecryptCBC(context.Background(), iv, ciphertext)
		clear(ciphertext)
		if err != nil || !bytes.Equal(roundTrip, plaintext) {
			clear(roundTrip)
			_ = restored.Close()
			_ = restoredProvider.Close()
			t.Fatalf("restored SM4 round trip failed: %v", err)
		}
		clear(roundTrip)
		if err := restored.Close(); err != nil {
			_ = restoredProvider.Close()
			t.Fatalf("restored session Close() error = %v", err)
		}
	}
	if err := restoredProvider.Close(); err != nil {
		t.Fatalf("restored provider Close() error = %v", err)
	}

	process, err := signerplugin.StartProcess(context.Background(), signerplugin.ProcessConfig{
		Command:                binaryPath,
		InheritEnv:             configuredSidecarEnvironment(),
		StartTimeout:           10 * time.Second,
		HealthTimeout:          10 * time.Second,
		PublicKeyTimeout:       20 * time.Second,
		SignTimeout:            30 * time.Second,
		ShutdownTimeout:        2 * time.Second,
		HostMaxConcurrentSigns: 8,
		Stderr:                 os.Stderr,
	})
	if err != nil {
		t.Fatalf("StartProcess() error = %v", err)
	}
	defer process.Close()
	processPublicKey, err := process.GetPublicKey(context.Background(), key)
	if err != nil || !bytes.Equal(processPublicKey, expectedPublic) {
		t.Fatalf("supervised GetPublicKey() failed: %v", err)
	}
	public, err := sm2.NewPublicKey(expectedPublic)
	if err != nil {
		t.Fatal(err)
	}
	const operations = 16
	var wait sync.WaitGroup
	failures := make(chan error, operations)
	wait.Add(operations)
	for index := 0; index < operations; index++ {
		go func(index int) {
			defer wait.Done()
			message := []byte(fmt.Sprintf("trustdb-sdf-qualified-%02d", index))
			signature, signErr := process.Sign(context.Background(), key, message)
			if signErr != nil {
				failures <- signErr
				return
			}
			if !sm2.VerifyASN1WithSM2(public, []byte(signerplugin.SM2DefaultUserID), message, signature) {
				failures <- errors.New("supervised SDF signature failed local SM2 verification")
			}
		}(index)
	}
	wait.Wait()
	close(failures)
	for failure := range failures {
		t.Error(failure)
	}
}

func qualificationDescriptor(config sdfsigner.Config, keyIndex uint32, publicKey []byte) keydescriptor.Descriptor {
	return keydescriptor.Descriptor{
		SchemaVersion: keydescriptor.SchemaV1,
		Kind:          keydescriptor.KindSigner,
		Provider:      keydescriptor.ProviderSDF,
		CryptoSuite:   cryptosuite.CNSMV1,
		KeyID:         "qualified-sdf-sm2",
		Algorithm:     cryptosuite.SignatureSM2SM3,
		SM2UserID:     cryptosuite.SM2DefaultUserID,
		PublicKey: keydescriptor.PublicKeyMaterial{
			Encoding: cryptosuite.SM2PublicKeyEncoding,
			Bytes:    append([]byte(nil), publicKey...),
		},
		SDF: &keydescriptor.SDFKeyReference{
			DeviceRef:     config.DeviceRef,
			KeyIndex:      keyIndex,
			CredentialRef: config.CredentialRef,
		},
	}
}

func pluginKey(config sdfsigner.Config, keyIndex uint32) signerplugin.Key {
	return signerplugin.Key{
		Binding: signerplugin.Binding{
			ProtocolVersion:   signerplugin.ProtocolVersion,
			PluginID:          config.PluginID,
			ProviderKind:      signerplugin.ProviderSDF,
			CryptoSuite:       signerplugin.SuiteCNSMV1,
			Algorithm:         signerplugin.AlgorithmSM2SM3,
			PublicKeyEncoding: signerplugin.SM2PublicKeyEncoding,
			SignatureEncoding: signerplugin.SM2SignatureEncoding,
			KeyID:             "qualified-sdf-sm2",
			SM2UserID:         signerplugin.SM2DefaultUserID,
		},
		Reference: signerplugin.KeyReference{
			SDF: &signerplugin.SDFKeyReference{
				DeviceRef: config.DeviceRef, KeyIndex: keyIndex,
				CredentialRef: config.CredentialRef,
			},
		},
	}
}

func configuredSidecarEnvironment() []string {
	names := []string{
		sdfsigner.EnvAdapterPath,
		sdfsigner.EnvAdapterConfigFile,
		sdfsigner.EnvDeviceRef,
		sdfsigner.EnvCredentialRef,
		sdfsigner.EnvCredentialFile,
	}
	for _, optional := range []string{
		sdfsigner.EnvCapabilities,
		sdfsigner.EnvKEKID,
		sdfsigner.EnvKEKIndex,
		sdfsigner.EnvPluginID,
		sdfsigner.EnvMaxConcurrency,
	} {
		if _, exists := os.LookupEnv(optional); exists {
			names = append(names, optional)
		}
	}
	return names
}

func requiredEnvironment(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required", name)
	}
	return value
}
