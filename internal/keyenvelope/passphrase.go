package keyenvelope

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/emmansun/gmsm/sm3"
	"golang.org/x/crypto/pbkdf2"

	"github.com/wowtrust/trustdb/internal/cborx"
)

const (
	PassphraseProvider       = "passphrase-dev-v1"
	PassphraseKDF            = "PBKDF2-HMAC-SM3"
	DefaultPassphraseEnv     = "TRUSTDB_DEV_KEY_PASSPHRASE"
	DefaultPassphraseFileEnv = "TRUSTDB_DEV_KEY_PASSPHRASE_FILE"
	NewPassphraseEnv         = "TRUSTDB_DEV_KEY_PASSPHRASE_NEW"
	NewPassphraseFileEnv     = "TRUSTDB_DEV_KEY_PASSPHRASE_FILE_NEW"

	DefaultPBKDF2Iterations = 200_000
	MinPBKDF2Iterations     = 100_000
	MaxPBKDF2Iterations     = 2_000_000
	passphraseSaltBytes     = 16
	minPassphraseBytes      = 12
	maxPassphraseBytes      = 1024
)

var ErrPassphraseUnavailable = errors.New("development key passphrase is unavailable")

// PassphraseSource returns a fresh caller-owned byte slice. Implementations
// must not log the passphrase or include it in returned errors.
type PassphraseSource func(context.Context) ([]byte, error)

type PassphraseKEKProvider struct {
	source     PassphraseSource
	random     io.Reader
	iterations uint32
}

type passphraseParameters struct {
	KDF        string `cbor:"kdf"`
	Salt       []byte `cbor:"salt"`
	Iterations uint32 `cbor:"iterations"`
	KEKBytes   uint8  `cbor:"kek_bytes"`
	Nonce      []byte `cbor:"nonce"`
	TagBytes   uint8  `cbor:"tag_bytes"`
}

func NewPassphraseKEKProvider(source PassphraseSource) *PassphraseKEKProvider {
	return &PassphraseKEKProvider{
		source:     source,
		random:     rand.Reader,
		iterations: DefaultPBKDF2Iterations,
	}
}

func EnvPassphraseSource(name string) PassphraseSource {
	return func(ctx context.Context) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		value, ok := os.LookupEnv(name)
		if !ok || value == "" {
			return nil, ErrPassphraseUnavailable
		}
		return []byte(value), nil
	}
}

// DefaultPassphraseSource supports exactly one secret source: the standard
// development environment variable or an owner-only secret file named by the
// standard file environment variable. The file path itself is never persisted
// in an envelope or diagnostic.
func DefaultPassphraseSource() PassphraseSource {
	return EnvironmentOrFilePassphraseSource(DefaultPassphraseEnv, DefaultPassphraseFileEnv)
}

func NewPassphraseSource() PassphraseSource {
	return EnvironmentOrFilePassphraseSource(NewPassphraseEnv, NewPassphraseFileEnv)
}

func EnvironmentOrFilePassphraseSource(valueEnv, fileEnv string) PassphraseSource {
	return func(ctx context.Context) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		value, hasValue := os.LookupEnv(valueEnv)
		path, hasFile := os.LookupEnv(fileEnv)
		if hasValue == hasFile {
			return nil, fmt.Errorf("%w: configure exactly one development passphrase source", ErrPassphraseUnavailable)
		}
		if hasValue {
			return []byte(value), nil
		}
		return readPassphraseFile(path)
	}
}

func readPassphraseFile(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, secretSafePathError("inspect development passphrase file", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: passphrase source is not a regular file", ErrPassphraseUnavailable)
	}
	if runtime.GOOS != "windows" && before.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: passphrase file permissions grant group or other access", ErrPassphraseUnavailable)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, secretSafePathError("open development passphrase file", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, secretSafePathError("stat development passphrase file", err)
	}
	if !info.Mode().IsRegular() || !os.SameFile(before, info) {
		return nil, fmt.Errorf("%w: passphrase source changed while opening", ErrPassphraseUnavailable)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxPassphraseBytes+3))
	if err != nil {
		return nil, secretSafePathError("read development passphrase file", err)
	}
	if len(data) > maxPassphraseBytes+2 {
		clearBytes(data)
		return nil, fmt.Errorf("%w: passphrase file is too large", ErrPassphraseUnavailable)
	}
	if bytes.HasSuffix(data, []byte("\r\n")) {
		data = data[:len(data)-2]
	} else if bytes.HasSuffix(data, []byte("\n")) {
		data = data[:len(data)-1]
	}
	return data, nil
}

func (*PassphraseKEKProvider) Name() string { return PassphraseProvider }

func (p *PassphraseKEKProvider) WrapDEK(ctx context.Context, dek, aad []byte) (WrappedDEK, error) {
	if err := p.validate(); err != nil {
		return WrappedDEK{}, err
	}
	if len(dek) != dekBytes {
		return WrappedDEK{}, ErrAuthenticationFailed
	}
	passphrase, err := p.source(ctx)
	if err != nil {
		return WrappedDEK{}, ErrPassphraseUnavailable
	}
	defer clearBytes(passphrase)
	if err := validatePassphrase(passphrase); err != nil {
		return WrappedDEK{}, err
	}
	parameters := passphraseParameters{
		KDF:        PassphraseKDF,
		Salt:       make([]byte, passphraseSaltBytes),
		Iterations: p.iterations,
		KEKBytes:   dekBytes,
		Nonce:      make([]byte, nonceBytes),
		TagBytes:   tagBytes,
	}
	if _, err := io.ReadFull(p.random, parameters.Salt); err != nil {
		return WrappedDEK{}, fmt.Errorf("generate passphrase salt: %w", err)
	}
	if _, err := io.ReadFull(p.random, parameters.Nonce); err != nil {
		return WrappedDEK{}, fmt.Errorf("generate KEK nonce: %w", err)
	}
	parameterBytes, err := cborx.Marshal(parameters)
	if err != nil {
		return WrappedDEK{}, fmt.Errorf("marshal KEK parameters: %w", err)
	}
	kek := pbkdf2.Key(passphrase, parameters.Salt, int(parameters.Iterations), int(parameters.KEKBytes), sm3.New)
	defer clearBytes(kek)
	ciphertext, err := sm4Seal(kek, parameters.Nonce, dek, providerAAD(aad, PassphraseProvider, WrapAlgorithm, parameterBytes))
	if err != nil {
		clearBytes(parameterBytes)
		return WrappedDEK{}, err
	}
	return WrappedDEK{
		Provider:   PassphraseProvider,
		Algorithm:  WrapAlgorithm,
		Parameters: parameterBytes,
		Ciphertext: ciphertext,
	}, nil
}

func (p *PassphraseKEKProvider) UnwrapDEK(ctx context.Context, wrapped WrappedDEK, aad []byte) ([]byte, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	if wrapped.Provider != PassphraseProvider || wrapped.Algorithm != WrapAlgorithm || len(wrapped.Ciphertext) != maxWrappedDEKBytes {
		return nil, ErrAuthenticationFailed
	}
	parameters, err := parsePassphraseParameters(wrapped.Parameters)
	if err != nil {
		return nil, ErrAuthenticationFailed
	}
	defer clearBytes(parameters.Salt)
	defer clearBytes(parameters.Nonce)
	passphrase, err := p.source(ctx)
	if err != nil {
		return nil, ErrPassphraseUnavailable
	}
	defer clearBytes(passphrase)
	if err := validatePassphrase(passphrase); err != nil {
		return nil, err
	}
	kek := pbkdf2.Key(passphrase, parameters.Salt, int(parameters.Iterations), int(parameters.KEKBytes), sm3.New)
	defer clearBytes(kek)
	dek, err := sm4Open(kek, parameters.Nonce, wrapped.Ciphertext, providerAAD(aad, wrapped.Provider, wrapped.Algorithm, wrapped.Parameters))
	if err != nil || len(dek) != dekBytes {
		clearBytes(dek)
		return nil, ErrAuthenticationFailed
	}
	return dek, nil
}

func (p *PassphraseKEKProvider) validate() error {
	if p == nil || p.source == nil || p.random == nil {
		return fmt.Errorf("%w: passphrase provider is incomplete", ErrUnsupportedKEK)
	}
	if p.iterations < MinPBKDF2Iterations || p.iterations > MaxPBKDF2Iterations {
		return fmt.Errorf("%w: passphrase KDF work factor is outside policy", ErrUnsupportedKEK)
	}
	return nil
}

func parsePassphraseParameters(data []byte) (passphraseParameters, error) {
	if len(data) == 0 || len(data) > maxWrapParameterSize {
		return passphraseParameters{}, ErrAuthenticationFailed
	}
	var parameters passphraseParameters
	if err := cborx.UnmarshalLimit(data, &parameters, maxWrapParameterSize); err != nil {
		return passphraseParameters{}, ErrAuthenticationFailed
	}
	canonical, err := cborx.Marshal(parameters)
	if err != nil || !bytes.Equal(canonical, data) {
		clearBytes(canonical)
		return passphraseParameters{}, ErrAuthenticationFailed
	}
	clearBytes(canonical)
	if parameters.KDF != PassphraseKDF || len(parameters.Salt) != passphraseSaltBytes ||
		parameters.Iterations < MinPBKDF2Iterations || parameters.Iterations > MaxPBKDF2Iterations ||
		parameters.KEKBytes != dekBytes || len(parameters.Nonce) != nonceBytes || parameters.TagBytes != tagBytes {
		return passphraseParameters{}, ErrAuthenticationFailed
	}
	return parameters, nil
}

type providerAADMetadata struct {
	EnvelopeAAD []byte `cbor:"envelope_aad"`
	Provider    string `cbor:"provider"`
	Algorithm   string `cbor:"algorithm"`
	Parameters  []byte `cbor:"parameters"`
}

func providerAAD(aad []byte, provider, algorithm string, parameters []byte) []byte {
	data, err := cborx.Marshal(providerAADMetadata{
		EnvelopeAAD: aad,
		Provider:    provider,
		Algorithm:   algorithm,
		Parameters:  parameters,
	})
	if err != nil {
		panic(err)
	}
	return data
}

func validatePassphrase(passphrase []byte) error {
	if len(passphrase) < minPassphraseBytes || len(passphrase) > maxPassphraseBytes {
		return fmt.Errorf("%w: development passphrase length is outside policy", ErrPassphraseUnavailable)
	}
	return nil
}
