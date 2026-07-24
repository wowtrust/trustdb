package pkcs11signer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/wowtrust/trustdb/sdk/signerplugin"
)

func TestLoadEnvironmentRequiresExplicitSM2Profile(t *testing.T) {
	clearPKCS11Environment(t)
	pinPath := filepath.Join(t.TempDir(), "pin")
	if err := os.WriteFile(pinPath, []byte("123456"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvModulePath, "/opt/vendor/libpkcs11.so")
	t.Setenv(EnvTokenURI, "pkcs11:serial=serial-1;token=trustdb")
	t.Setenv(EnvPINFile, pinPath)
	t.Setenv(EnvAlgorithms, signerplugin.SuiteCNSMV1)
	if _, err := LoadEnvironment(); err == nil {
		t.Fatal("LoadEnvironment() accepted CN_SM_V1 without an explicit mechanism")
	}

	t.Setenv(EnvSM2Mechanism, "0x80001001")
	t.Setenv(EnvSM2SignatureFormat, SignatureFormatRaw)
	t.Setenv(EnvSM2MechanismParam, "010203")
	environment, err := LoadEnvironment()
	if err != nil {
		t.Fatalf("LoadEnvironment() error = %v", err)
	}
	if environment.ModulePath != "/opt/vendor/libpkcs11.so" ||
		len(environment.Config.Profiles) != 1 ||
		environment.Config.Profiles[0].Mechanism != 0x80001001 ||
		string(environment.Config.Profiles[0].Parameter) != "\x01\x02\x03" {
		t.Fatalf("environment = %+v", environment.Config)
	}
}

func TestLoadEnvironmentNeverReadsAnInlinePIN(t *testing.T) {
	clearPKCS11Environment(t)
	t.Setenv(EnvModulePath, "/opt/vendor/libpkcs11.so")
	t.Setenv(EnvTokenURI, "pkcs11:token=trustdb")
	t.Setenv(EnvAlgorithms, signerplugin.SuiteINTLV1)
	t.Setenv("TRUSTDB_PKCS11_PIN", "must-not-be-supported")
	if _, err := LoadEnvironment(); err == nil {
		t.Fatal("LoadEnvironment() accepted an inline environment PIN")
	}
}

func clearPKCS11Environment(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		EnvModulePath,
		EnvTokenURI,
		EnvPINFile,
		EnvPluginID,
		EnvAlgorithms,
		EnvMaxConcurrency,
		EnvEdDSAMechanism,
		EnvSM2Mechanism,
		EnvSM2MechanismParam,
		EnvSM2SignatureFormat,
		"TRUSTDB_PKCS11_PIN",
	} {
		t.Setenv(name, "")
	}
}
