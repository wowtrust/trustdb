// Package keyenvelope implements the versioned, authenticated envelope used
// for software-managed private keys. It deliberately owns no signer or proof
// semantics: callers supply trusted descriptor metadata and receive the same
// private key bytes after successful authentication.
package keyenvelope

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"

	"github.com/emmansun/gmsm/sm4"

	"github.com/wowtrust/trustdb/internal/cborx"
)

const (
	SchemaV1         = "trustdb.software-key-envelope.v1"
	ContentAlgorithm = "SM4-GCM"
	WrapAlgorithm    = "SM4-GCM"
	ObjectType       = "software-private-key"

	dekBytes             = 16
	nonceBytes           = 12
	tagBytes             = 16
	maxEnvelopeBytes     = 16 << 10
	maxPrivateKeyBytes   = 4096
	maxWrapParameterSize = 4096
	maxWrappedDEKBytes   = dekBytes + tagBytes
)

var (
	ErrInvalidEnvelope       = errors.New("invalid software key envelope")
	ErrNonCanonicalEnvelope  = errors.New("non-canonical software key envelope")
	ErrMetadataMismatch      = errors.New("software key envelope metadata mismatch")
	ErrUnsupportedKEK        = errors.New("unsupported key-encryption-key provider")
	ErrAuthenticationFailed  = errors.New("software key envelope authentication failed")
	ErrUnsafeEnvelopeStorage = errors.New("unsafe software key envelope storage")
)

// Metadata is copied from a validated key descriptor. Open compares every
// field before invoking a KEK provider so an envelope cannot change suite,
// identity, algorithm, or private-key encoding by editing its own metadata.
type Metadata struct {
	CryptoSuite        string `cbor:"crypto_suite" json:"crypto_suite"`
	KeyID              string `cbor:"key_id" json:"key_id"`
	KeyAlgorithm       string `cbor:"key_algorithm" json:"key_algorithm"`
	PrivateKeyEncoding string `cbor:"private_key_encoding" json:"private_key_encoding"`
}

type Envelope struct {
	SchemaVersion    string     `cbor:"schema_version" json:"schema_version"`
	ObjectType       string     `cbor:"object_type" json:"object_type"`
	Metadata         Metadata   `cbor:"metadata" json:"metadata"`
	ContentAlgorithm string     `cbor:"content_algorithm" json:"content_algorithm"`
	ContentNonce     []byte     `cbor:"content_nonce" json:"content_nonce"`
	Ciphertext       []byte     `cbor:"ciphertext" json:"ciphertext"`
	WrappedDEK       WrappedDEK `cbor:"wrapped_dek" json:"wrapped_dek"`
}

// WrappedDEK is provider-neutral. Parameters are canonical provider-owned
// bytes and are authenticated by the provider's wrap operation. An HSM or KMS
// adapter can therefore keep its KEK non-exportable while returning an opaque
// wrap and the metadata required to identify its operation.
type WrappedDEK struct {
	Provider   string `cbor:"provider" json:"provider"`
	Algorithm  string `cbor:"algorithm" json:"algorithm"`
	Parameters []byte `cbor:"parameters" json:"parameters"`
	Ciphertext []byte `cbor:"ciphertext" json:"ciphertext"`
}

// KEKProvider wraps and unwraps a DEK. Implementations must authenticate aad,
// return fresh parameters for every WrapDEK call, and keep diagnostic errors
// free of passphrases, credentials, provider handles, and private material.
type KEKProvider interface {
	Name() string
	WrapDEK(context.Context, []byte, []byte) (WrappedDEK, error)
	UnwrapDEK(context.Context, WrappedDEK, []byte) ([]byte, error)
}

// Seal encrypts plaintext with a fresh random SM4 DEK and nonce, then asks the
// selected provider to wrap that DEK. The returned bytes are canonical CBOR.
func Seal(ctx context.Context, metadata Metadata, plaintext []byte, provider KEKProvider) ([]byte, error) {
	return sealWithRand(ctx, metadata, plaintext, provider, rand.Reader)
}

func sealWithRand(ctx context.Context, metadata Metadata, plaintext []byte, provider KEKProvider, random io.Reader) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateMetadata(metadata); err != nil {
		return nil, err
	}
	if len(plaintext) == 0 || len(plaintext) > maxPrivateKeyBytes {
		return nil, invalid("private key size is invalid")
	}
	if provider == nil || !validName(provider.Name()) {
		return nil, fmt.Errorf("%w: invalid provider", ErrUnsupportedKEK)
	}
	if random == nil {
		return nil, invalid("random source is nil")
	}

	dek := make([]byte, dekBytes)
	defer clearBytes(dek)
	contentNonce := make([]byte, nonceBytes)
	if _, err := io.ReadFull(random, dek); err != nil {
		return nil, fmt.Errorf("generate envelope DEK: %w", err)
	}
	if _, err := io.ReadFull(random, contentNonce); err != nil {
		return nil, fmt.Errorf("generate envelope nonce: %w", err)
	}
	aad, err := contentAAD(metadata)
	if err != nil {
		return nil, err
	}
	ciphertext, err := sm4Seal(dek, contentNonce, plaintext, aad)
	if err != nil {
		return nil, err
	}
	wrapped, err := provider.WrapDEK(ctx, dek, wrapAAD(metadata, provider.Name()))
	if err != nil {
		clearBytes(ciphertext)
		clearWrappedDEK(&wrapped)
		return nil, fmt.Errorf("wrap software key DEK: %w", err)
	}
	if wrapped.Provider != provider.Name() {
		clearBytes(ciphertext)
		clearWrappedDEK(&wrapped)
		return nil, fmt.Errorf("%w: provider returned mismatched metadata", ErrUnsupportedKEK)
	}
	envelope := Envelope{
		SchemaVersion:    SchemaV1,
		ObjectType:       ObjectType,
		Metadata:         metadata,
		ContentAlgorithm: ContentAlgorithm,
		ContentNonce:     contentNonce,
		Ciphertext:       ciphertext,
		WrappedDEK:       wrapped,
	}
	if err := envelope.Validate(); err != nil {
		clearEnvelope(&envelope)
		return nil, err
	}
	encoded, err := cborx.Marshal(envelope)
	clearEnvelope(&envelope)
	if err != nil {
		return nil, fmt.Errorf("marshal software key envelope: %w", err)
	}
	if len(encoded) > maxEnvelopeBytes {
		clearBytes(encoded)
		return nil, invalid("encoded envelope is too large")
	}
	return encoded, nil
}

// Open authenticates canonical envelope bytes against trusted metadata before
// returning private key bytes. All AEAD failures intentionally collapse to one
// secret-safe error.
func Open(ctx context.Context, data []byte, expected Metadata, providers ...KEKProvider) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	envelope, err := Unmarshal(data)
	if err != nil {
		return nil, err
	}
	defer clearEnvelope(&envelope)
	if envelope.Metadata != expected {
		return nil, ErrMetadataMismatch
	}
	provider, err := selectProvider(envelope.WrappedDEK.Provider, providers)
	if err != nil {
		return nil, err
	}
	dek, err := provider.UnwrapDEK(ctx, envelope.WrappedDEK, wrapAAD(expected, provider.Name()))
	if err != nil {
		clearBytes(dek)
		return nil, ErrAuthenticationFailed
	}
	defer clearBytes(dek)
	if len(dek) != dekBytes {
		return nil, ErrAuthenticationFailed
	}
	aad, err := contentAAD(expected)
	if err != nil {
		return nil, err
	}
	plaintext, err := sm4Open(dek, envelope.ContentNonce, envelope.Ciphertext, aad)
	if err != nil {
		return nil, ErrAuthenticationFailed
	}
	if len(plaintext) == 0 || len(plaintext) > maxPrivateKeyBytes {
		clearBytes(plaintext)
		return nil, ErrAuthenticationFailed
	}
	return plaintext, nil
}

// Rewrap authenticates the existing envelope, unwraps its DEK, and wraps that
// same DEK with a fresh KEK operation. Content nonce and ciphertext stay
// unchanged, preserving the private/public identity across KEK rotation.
func Rewrap(ctx context.Context, data []byte, expected Metadata, oldProvider, newProvider KEKProvider) ([]byte, error) {
	envelope, err := Unmarshal(data)
	if err != nil {
		return nil, err
	}
	defer clearEnvelope(&envelope)
	if envelope.Metadata != expected {
		return nil, ErrMetadataMismatch
	}
	if oldProvider == nil || oldProvider.Name() != envelope.WrappedDEK.Provider {
		return nil, ErrUnsupportedKEK
	}
	if newProvider == nil || !validName(newProvider.Name()) {
		return nil, ErrUnsupportedKEK
	}
	dek, err := oldProvider.UnwrapDEK(ctx, envelope.WrappedDEK, wrapAAD(expected, oldProvider.Name()))
	if err != nil || len(dek) != dekBytes {
		clearBytes(dek)
		return nil, ErrAuthenticationFailed
	}
	defer clearBytes(dek)
	aad, err := contentAAD(expected)
	if err != nil {
		return nil, err
	}
	plaintext, err := sm4Open(dek, envelope.ContentNonce, envelope.Ciphertext, aad)
	if err != nil {
		return nil, ErrAuthenticationFailed
	}
	clearBytes(plaintext)
	wrapped, err := newProvider.WrapDEK(ctx, dek, wrapAAD(expected, newProvider.Name()))
	if err != nil {
		clearWrappedDEK(&wrapped)
		return nil, fmt.Errorf("rewrap software key DEK: %w", err)
	}
	if wrapped.Provider != newProvider.Name() {
		clearWrappedDEK(&wrapped)
		return nil, ErrUnsupportedKEK
	}
	if wrapped.Provider == envelope.WrappedDEK.Provider && bytes.Equal(wrapped.Parameters, envelope.WrappedDEK.Parameters) {
		clearWrappedDEK(&wrapped)
		return nil, invalid("KEK rotation reused provider parameters")
	}
	clearBytes(envelope.WrappedDEK.Parameters)
	clearBytes(envelope.WrappedDEK.Ciphertext)
	envelope.WrappedDEK = wrapped
	if err := envelope.Validate(); err != nil {
		return nil, err
	}
	encoded, err := cborx.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("marshal rotated software key envelope: %w", err)
	}
	return encoded, nil
}

func Marshal(envelope Envelope) ([]byte, error) {
	if err := envelope.Validate(); err != nil {
		return nil, err
	}
	data, err := cborx.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("marshal software key envelope: %w", err)
	}
	if len(data) > maxEnvelopeBytes {
		return nil, invalid("encoded envelope is too large")
	}
	return data, nil
}

func Unmarshal(data []byte) (Envelope, error) {
	if len(data) == 0 || len(data) > maxEnvelopeBytes {
		return Envelope{}, invalid("encoded envelope size is invalid")
	}
	var envelope Envelope
	if err := cborx.UnmarshalLimit(data, &envelope, maxEnvelopeBytes); err != nil {
		return Envelope{}, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	if err := envelope.Validate(); err != nil {
		clearEnvelope(&envelope)
		return Envelope{}, err
	}
	canonical, err := cborx.Marshal(envelope)
	if err != nil {
		clearEnvelope(&envelope)
		return Envelope{}, fmt.Errorf("%w: re-encode failed", ErrInvalidEnvelope)
	}
	if !bytes.Equal(canonical, data) {
		clearBytes(canonical)
		clearEnvelope(&envelope)
		return Envelope{}, ErrNonCanonicalEnvelope
	}
	clearBytes(canonical)
	cloned := cloneEnvelope(envelope)
	clearEnvelope(&envelope)
	return cloned, nil
}

func (e Envelope) Validate() error {
	if e.SchemaVersion != SchemaV1 {
		return invalid("schema_version is unsupported")
	}
	if e.ObjectType != ObjectType {
		return invalid("object_type is unsupported")
	}
	if err := validateMetadata(e.Metadata); err != nil {
		return err
	}
	if e.ContentAlgorithm != ContentAlgorithm {
		return invalid("content algorithm is unsupported")
	}
	if len(e.ContentNonce) != nonceBytes {
		return invalid("content nonce size is invalid")
	}
	if len(e.Ciphertext) <= tagBytes || len(e.Ciphertext) > maxPrivateKeyBytes+tagBytes {
		return invalid("ciphertext size is invalid")
	}
	if !validName(e.WrappedDEK.Provider) || !validName(e.WrappedDEK.Algorithm) {
		return invalid("wrapped DEK provider metadata is invalid")
	}
	if len(e.WrappedDEK.Parameters) == 0 || len(e.WrappedDEK.Parameters) > maxWrapParameterSize {
		return invalid("wrapped DEK parameters size is invalid")
	}
	if len(e.WrappedDEK.Ciphertext) == 0 || len(e.WrappedDEK.Ciphertext) > maxWrappedDEKBytes+4096 {
		return invalid("wrapped DEK ciphertext size is invalid")
	}
	return nil
}

type aadMetadata struct {
	Domain             string `cbor:"domain"`
	ObjectType         string `cbor:"object_type"`
	CryptoSuite        string `cbor:"crypto_suite"`
	KeyID              string `cbor:"key_id"`
	KeyAlgorithm       string `cbor:"key_algorithm"`
	PrivateKeyEncoding string `cbor:"private_key_encoding"`
	ContentAlgorithm   string `cbor:"content_algorithm"`
}

type wrapAADMetadata struct {
	Metadata aadMetadata `cbor:"metadata"`
	Provider string      `cbor:"provider"`
}

func contentAAD(metadata Metadata) ([]byte, error) {
	return cborx.Marshal(aadFor(metadata))
}

func wrapAAD(metadata Metadata, provider string) []byte {
	data, err := cborx.Marshal(wrapAADMetadata{Metadata: aadFor(metadata), Provider: provider})
	if err != nil {
		panic(err)
	}
	return data
}

func aadFor(metadata Metadata) aadMetadata {
	return aadMetadata{
		Domain:             SchemaV1,
		ObjectType:         ObjectType,
		CryptoSuite:        metadata.CryptoSuite,
		KeyID:              metadata.KeyID,
		KeyAlgorithm:       metadata.KeyAlgorithm,
		PrivateKeyEncoding: metadata.PrivateKeyEncoding,
		ContentAlgorithm:   ContentAlgorithm,
	}
}

func sm4Seal(key, nonce, plaintext, aad []byte) ([]byte, error) {
	aead, err := newSM4GCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, invalid("nonce size is invalid")
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

func sm4Open(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := newSM4GCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() || len(ciphertext) < aead.Overhead() {
		return nil, ErrAuthenticationFailed
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrAuthenticationFailed
	}
	return plaintext, nil
}

func newSM4GCM(key []byte) (cipher.AEAD, error) {
	if len(key) != dekBytes {
		return nil, ErrAuthenticationFailed
	}
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, ErrAuthenticationFailed
	}
	aead, err := cipher.NewGCMWithTagSize(block, tagBytes)
	if err != nil {
		return nil, ErrAuthenticationFailed
	}
	if aead.NonceSize() != nonceBytes || aead.Overhead() != tagBytes {
		return nil, ErrAuthenticationFailed
	}
	return aead, nil
}

func validateMetadata(metadata Metadata) error {
	for name, value := range map[string]string{
		"crypto_suite":         metadata.CryptoSuite,
		"key_id":               metadata.KeyID,
		"key_algorithm":        metadata.KeyAlgorithm,
		"private_key_encoding": metadata.PrivateKeyEncoding,
	} {
		if !validName(value) {
			return invalid(name + " is invalid")
		}
	}
	return nil
}

func validName(value string) bool {
	if value == "" || len(value) > 256 || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

func selectProvider(name string, providers []KEKProvider) (KEKProvider, error) {
	var selected KEKProvider
	for _, provider := range providers {
		if provider == nil || provider.Name() != name {
			continue
		}
		if selected != nil {
			return nil, fmt.Errorf("%w: duplicate provider registration", ErrUnsupportedKEK)
		}
		selected = provider
	}
	if selected == nil {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedKEK, name)
	}
	return selected, nil
}

func cloneEnvelope(envelope Envelope) Envelope {
	envelope.ContentNonce = append([]byte(nil), envelope.ContentNonce...)
	envelope.Ciphertext = append([]byte(nil), envelope.Ciphertext...)
	envelope.WrappedDEK.Parameters = append([]byte(nil), envelope.WrappedDEK.Parameters...)
	envelope.WrappedDEK.Ciphertext = append([]byte(nil), envelope.WrappedDEK.Ciphertext...)
	return envelope
}

func clearEnvelope(envelope *Envelope) {
	if envelope == nil {
		return
	}
	clearBytes(envelope.ContentNonce)
	clearBytes(envelope.Ciphertext)
	clearWrappedDEK(&envelope.WrappedDEK)
}

func clearWrappedDEK(wrapped *WrappedDEK) {
	if wrapped == nil {
		return
	}
	clearBytes(wrapped.Parameters)
	clearBytes(wrapped.Ciphertext)
}

func clearBytes(data []byte) {
	clear(data)
	runtime.KeepAlive(data)
}

func invalid(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalidEnvelope, message)
}
