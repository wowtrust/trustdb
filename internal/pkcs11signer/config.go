package pkcs11signer

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/wowtrust/trustdb/sdk/signerplugin"
)

const (
	EnvModulePath         = "TRUSTDB_PKCS11_MODULE"
	EnvTokenURI           = "TRUSTDB_PKCS11_TOKEN_URI"
	EnvPINFile            = "TRUSTDB_PKCS11_PIN_FILE"
	EnvPluginID           = "TRUSTDB_PKCS11_PLUGIN_ID"
	EnvAlgorithms         = "TRUSTDB_PKCS11_ALGORITHMS"
	EnvMaxConcurrency     = "TRUSTDB_PKCS11_MAX_CONCURRENCY"
	EnvEdDSAMechanism     = "TRUSTDB_PKCS11_EDDSA_MECHANISM"
	EnvSM2Mechanism       = "TRUSTDB_PKCS11_SM2_MECHANISM"
	EnvSM2MechanismParam  = "TRUSTDB_PKCS11_SM2_PARAMETER_HEX"
	EnvSM2SignatureFormat = "TRUSTDB_PKCS11_SM2_SIGNATURE_FORMAT"

	defaultEdDSAMechanism uint = 0x00001057 // CKM_EDDSA in PKCS#11 v3.x.
)

type Environment struct {
	ModulePath string
	Config     Config
}

// LoadEnvironment reads only named PKCS#11 plugin variables. The PIN itself
// is never accepted from an environment value or command argument.
func LoadEnvironment() (Environment, error) {
	module := strings.TrimSpace(os.Getenv(EnvModulePath))
	if !validEnvironmentPath(module) {
		return Environment{}, envError(EnvModulePath, "is required and must be a bounded path without control characters")
	}
	tokenURI := strings.TrimSpace(os.Getenv(EnvTokenURI))
	if tokenURI == "" {
		return Environment{}, envError(EnvTokenURI, "is required")
	}
	pinSource, err := NewFilePINSource(strings.TrimSpace(os.Getenv(EnvPINFile)))
	if err != nil {
		return Environment{}, err
	}
	pluginID := strings.TrimSpace(os.Getenv(EnvPluginID))
	if pluginID == "" {
		pluginID = DefaultPluginID
	}
	maxConcurrency := uint64(DefaultMaxConcurrentSigns)
	if raw := strings.TrimSpace(os.Getenv(EnvMaxConcurrency)); raw != "" {
		maxConcurrency, err = strconv.ParseUint(raw, 10, 32)
		if err != nil || maxConcurrency == 0 || maxConcurrency > 1024 {
			return Environment{}, envError(EnvMaxConcurrency, "must be an integer between 1 and 1024")
		}
	}
	algorithms := strings.TrimSpace(os.Getenv(EnvAlgorithms))
	if algorithms == "" {
		return Environment{}, envError(EnvAlgorithms, "must explicitly list INTL_V1 and/or CN_SM_V1")
	}
	profiles := make([]Profile, 0, 2)
	seen := make(map[string]struct{}, 2)
	for _, algorithm := range strings.Split(algorithms, ",") {
		algorithm = strings.TrimSpace(algorithm)
		if _, exists := seen[algorithm]; exists {
			return Environment{}, envError(EnvAlgorithms, "contains a duplicate suite")
		}
		seen[algorithm] = struct{}{}
		switch algorithm {
		case signerplugin.SuiteINTLV1:
			mechanism := uint64(defaultEdDSAMechanism)
			if raw := strings.TrimSpace(os.Getenv(EnvEdDSAMechanism)); raw != "" {
				mechanism, err = strconv.ParseUint(raw, 0, strconv.IntSize)
				if err != nil || mechanism == 0 {
					return Environment{}, envError(EnvEdDSAMechanism, "must be a non-zero integer")
				}
			}
			profiles = append(profiles, Profile{
				CryptoSuite:     signerplugin.SuiteINTLV1,
				Mechanism:       uint(mechanism),
				SignatureFormat: SignatureFormatRaw,
			})
		case signerplugin.SuiteCNSMV1:
			mechanism, parseErr := strconv.ParseUint(strings.TrimSpace(os.Getenv(EnvSM2Mechanism)), 0, strconv.IntSize)
			if parseErr != nil || mechanism == 0 {
				return Environment{}, envError(EnvSM2Mechanism, "must explicitly name a non-zero vendor mechanism")
			}
			format := strings.TrimSpace(os.Getenv(EnvSM2SignatureFormat))
			if format != SignatureFormatRaw && format != SignatureFormatDER {
				return Environment{}, envError(EnvSM2SignatureFormat, "must be raw or der")
			}
			var parameter []byte
			if encoded := strings.TrimSpace(os.Getenv(EnvSM2MechanismParam)); encoded != "" {
				parameter, err = hex.DecodeString(encoded)
				if err != nil || len(parameter) > 4096 {
					clear(parameter)
					return Environment{}, envError(EnvSM2MechanismParam, "must be at most 4096 bytes of hexadecimal")
				}
			}
			profiles = append(profiles, Profile{
				CryptoSuite:     signerplugin.SuiteCNSMV1,
				Mechanism:       uint(mechanism),
				Parameter:       parameter,
				SignatureFormat: format,
			})
		default:
			return Environment{}, envError(EnvAlgorithms, "contains an unsupported suite")
		}
	}
	return Environment{
		ModulePath: module,
		Config: Config{
			PluginID:           pluginID,
			TokenURI:           tokenURI,
			Profiles:           profiles,
			MaxConcurrentSigns: uint32(maxConcurrency),
			PIN:                pinSource,
		},
	}, nil
}

func envError(name, message string) error {
	return fmt.Errorf("%w: %s %s", ErrInvalidConfiguration, name, message)
}

func validEnvironmentPath(value string) bool {
	if value == "" || len(value) > maxURIBytes || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
