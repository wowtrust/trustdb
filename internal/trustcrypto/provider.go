package trustcrypto

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"strings"

	"github.com/emmansun/gmsm/sm3"

	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/model"
)

var (
	ErrUnsupportedAlgorithm  = errors.New("unsupported cryptographic algorithm")
	ErrUnsupportedEncoding   = errors.New("unsupported cryptographic encoding")
	ErrUnsupportedCapability = errors.New("unsupported provider capability")
	ErrInvalidKeyDescriptor  = errors.New("invalid public-key descriptor")
	ErrInvalidKeyHandle      = errors.New("invalid non-exportable key handle")
)

// Capability describes an operation that a key provider explicitly exposes.
// Core services must check capabilities instead of inferring them from a
// concrete software-key type.
type Capability uint32

const (
	CapabilitySign Capability = 1 << iota
	CapabilityPublicKey
)

type CapabilitySet uint32

func (set CapabilitySet) Supports(capability Capability) bool {
	return Capability(set)&capability == capability
}

// KeyHandle identifies private key material without exposing or serializing
// that material. Software, remote, PKCS#11, and SDF providers can all use the
// same handle shape.
type KeyHandle struct {
	Provider  string
	KeyID     string
	Algorithm string
}

func (h KeyHandle) Validate() error {
	if strings.TrimSpace(h.Provider) == "" || strings.TrimSpace(h.KeyID) == "" || strings.TrimSpace(h.Algorithm) == "" {
		return fmt.Errorf("%w: provider, key_id, and algorithm are required", ErrInvalidKeyHandle)
	}
	return nil
}

// PublicKeyDescriptor carries the suite and encoding needed to interpret
// public key bytes. Bytes are copied at every provider boundary.
type PublicKeyDescriptor struct {
	Suite     cryptosuite.ID
	KeyID     string
	Algorithm string
	Encoding  string
	Bytes     []byte
}

func (d PublicKeyDescriptor) Clone() PublicKeyDescriptor {
	d.Bytes = append([]byte(nil), d.Bytes...)
	return d
}

// Signer is the only private-key capability visible to core services. It has
// no private-key export method. Implementations must be safe for concurrent
// calls because batch proof workers may sign receipts in parallel.
type Signer interface {
	Handle() KeyHandle
	Capabilities() CapabilitySet
	PublicKey(context.Context) (PublicKeyDescriptor, error)
	Sign(context.Context, []byte) (model.Signature, error)
}

type Verifier interface {
	Algorithm() string
	Encoding() string
	Verify(context.Context, PublicKeyDescriptor, []byte, model.Signature) error
}

type HashFactory interface {
	Algorithm() string
	Size() int
	New() hash.Hash
	Sum([]byte) []byte
	Sum32([]byte) [32]byte
}

// Provider supplies public operations for one immutable cryptographic suite.
// Private-key custody remains behind a Signer supplied by the selected key
// provider.
type Provider interface {
	Suite() cryptosuite.ID
	HashFactory(string) (HashFactory, error)
	Verifier(string, string) (Verifier, error)
}

type intlV1Provider struct{}

type cnSMV1Provider struct{}

func (intlV1Provider) Suite() cryptosuite.ID { return cryptosuite.INTLV1 }

func (intlV1Provider) HashFactory(algorithm string) (HashFactory, error) {
	return HashFactoryForSuite(cryptosuite.INTLV1, algorithm)
}

func (intlV1Provider) Verifier(algorithm, encoding string) (Verifier, error) {
	if algorithm != cryptosuite.SignatureEd25519 {
		return nil, fmt.Errorf("%w: signature %q for suite %s", ErrUnsupportedAlgorithm, algorithm, cryptosuite.INTLV1)
	}
	if encoding != cryptosuite.Ed25519PublicKeyEncoding {
		return nil, fmt.Errorf("%w: public key %q for %s", ErrUnsupportedEncoding, encoding, algorithm)
	}
	return ed25519Verifier{}, nil
}

func (cnSMV1Provider) Suite() cryptosuite.ID { return cryptosuite.CNSMV1 }

func (cnSMV1Provider) HashFactory(algorithm string) (HashFactory, error) {
	return HashFactoryForSuite(cryptosuite.CNSMV1, algorithm)
}

func (cnSMV1Provider) Verifier(algorithm, encoding string) (Verifier, error) {
	if algorithm != cryptosuite.SignatureSM2SM3 {
		return nil, fmt.Errorf("%w: signature %q for suite %s", ErrUnsupportedAlgorithm, algorithm, cryptosuite.CNSMV1)
	}
	if encoding != cryptosuite.SM2PublicKeyEncoding {
		return nil, fmt.Errorf("%w: public key %q for %s", ErrUnsupportedEncoding, encoding, algorithm)
	}
	return sm2Verifier{}, nil
}

func ProviderForSuite(suiteID cryptosuite.ID) (Provider, error) {
	if _, err := cryptosuite.RequireAvailable(suiteID); err != nil {
		return nil, err
	}
	return providerForKnownSuite(suiteID)
}

func providerForKnownSuite(suiteID cryptosuite.ID) (Provider, error) {
	if _, err := cryptosuite.RequireKnown(suiteID); err != nil {
		return nil, err
	}
	switch suiteID {
	case cryptosuite.INTLV1:
		return intlV1Provider{}, nil
	case cryptosuite.CNSMV1:
		return cnSMV1Provider{}, nil
	default:
		return nil, fmt.Errorf("%w: provider for suite %s", ErrUnsupportedAlgorithm, suiteID)
	}
}

func DefaultProvider() Provider {
	return intlV1Provider{}
}

// HashFactoryForSuite exposes hash primitives for known suites without
// changing the production availability gate enforced by ProviderForSuite.
// This lets reserved suites complete vector, Merkle, and interoperability
// work while claim/signature generation remains unavailable until every
// provider capability is implemented.
func HashFactoryForSuite(suiteID cryptosuite.ID, algorithm string) (HashFactory, error) {
	suite, err := cryptosuite.RequireKnown(suiteID)
	if err != nil {
		return nil, err
	}
	if !suiteUsesHashAlgorithm(suite, algorithm) {
		return nil, fmt.Errorf("%w: hash %q for suite %s", ErrUnsupportedAlgorithm, algorithm, suiteID)
	}
	switch algorithm {
	case cryptosuite.HashSHA256:
		return sha256Factory{}, nil
	case cryptosuite.HashSM3:
		return sm3Factory{}, nil
	default:
		return nil, fmt.Errorf("%w: hash %q for suite %s", ErrUnsupportedAlgorithm, algorithm, suiteID)
	}
}

func suiteUsesHashAlgorithm(suite cryptosuite.Suite, algorithm string) bool {
	for _, spec := range []cryptosuite.HashSpec{
		suite.ContentHash,
		suite.ClaimHash,
		suite.SignatureHash,
		suite.RecordIDHash,
		suite.KeyEventHash,
		suite.KeyFingerprintHash,
		suite.StorageIntegrityHash,
		suite.Merkle.Hash,
		suite.AnchorDigest,
	} {
		if spec.Algorithm == algorithm {
			return true
		}
	}
	return false
}

func ValidatePublicKey(provider Provider, descriptor PublicKeyDescriptor) error {
	if provider == nil {
		return fmt.Errorf("%w: crypto provider is nil", ErrInvalidKeyDescriptor)
	}
	if descriptor.Suite != provider.Suite() {
		return fmt.Errorf("%w: descriptor suite %s does not match provider suite %s", cryptosuite.ErrMixedSuite, descriptor.Suite, provider.Suite())
	}
	verifier, err := provider.Verifier(descriptor.Algorithm, descriptor.Encoding)
	if err != nil {
		return err
	}
	switch verifier.Algorithm() {
	case cryptosuite.SignatureEd25519:
		if len(descriptor.Bytes) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: ed25519 public key size %d", ErrInvalidKeyDescriptor, len(descriptor.Bytes))
		}
	case cryptosuite.SignatureSM2SM3:
		if err := validateSM2PublicKey(descriptor.Bytes); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: public key validation for %q", ErrUnsupportedAlgorithm, verifier.Algorithm())
	}
	return nil
}

func ValidateSigner(ctx context.Context, suiteID cryptosuite.ID, signer Signer) error {
	provider, err := ProviderForSuite(suiteID)
	if err != nil {
		return err
	}
	return ValidateSignerWithProvider(ctx, provider, signer)
}

func ValidateSignerWithProvider(ctx context.Context, provider Provider, signer Signer) error {
	if provider == nil {
		return fmt.Errorf("%w: crypto provider is nil", ErrInvalidKeyDescriptor)
	}
	if err := ValidateSignerHandle(provider.Suite(), signer); err != nil {
		return err
	}
	descriptor, err := signer.PublicKey(ctx)
	if err != nil {
		return fmt.Errorf("read signer public key: %w", err)
	}
	if descriptor.KeyID != "" && descriptor.KeyID != signer.Handle().KeyID {
		return fmt.Errorf("%w: signer key_id %q does not match public key key_id %q", ErrInvalidKeyDescriptor, signer.Handle().KeyID, descriptor.KeyID)
	}
	return ValidatePublicKey(provider, descriptor)
}

func ValidateSignerHandle(suiteID cryptosuite.ID, signer Signer) error {
	if signer == nil {
		return fmt.Errorf("%w: signer is nil", ErrInvalidKeyHandle)
	}
	suite, err := cryptosuite.RequireAvailable(suiteID)
	if err != nil {
		return err
	}
	if !signer.Capabilities().Supports(CapabilitySign) {
		return fmt.Errorf("%w: sign", ErrUnsupportedCapability)
	}
	if !signer.Capabilities().Supports(CapabilityPublicKey) {
		return fmt.Errorf("%w: public_key", ErrUnsupportedCapability)
	}
	handle := signer.Handle()
	if err := handle.Validate(); err != nil {
		return err
	}
	if handle.Algorithm != suite.Signature.Algorithm {
		return fmt.Errorf("%w: signer algorithm %q for suite %s", ErrUnsupportedAlgorithm, handle.Algorithm, suiteID)
	}
	return nil
}

func Sign(ctx context.Context, suiteID cryptosuite.ID, signer Signer, message []byte) (model.Signature, error) {
	suite, err := cryptosuite.RequireAvailable(suiteID)
	if err != nil {
		return model.Signature{}, err
	}
	return signWithSuite(ctx, suite, signer, message)
}

func signForKnownSuite(ctx context.Context, suiteID cryptosuite.ID, signer Signer, message []byte) (model.Signature, error) {
	suite, err := cryptosuite.RequireKnown(suiteID)
	if err != nil {
		return model.Signature{}, err
	}
	return signWithSuite(ctx, suite, signer, message)
}

func signWithSuite(ctx context.Context, suite cryptosuite.Suite, signer Signer, message []byte) (model.Signature, error) {
	if signer == nil {
		return model.Signature{}, fmt.Errorf("%w: signer is nil", ErrInvalidKeyHandle)
	}
	if err := ctx.Err(); err != nil {
		return model.Signature{}, err
	}
	if !signer.Capabilities().Supports(CapabilitySign) {
		return model.Signature{}, fmt.Errorf("%w: sign", ErrUnsupportedCapability)
	}
	handle := signer.Handle()
	if err := handle.Validate(); err != nil {
		return model.Signature{}, err
	}
	if handle.Algorithm != suite.Signature.Algorithm {
		return model.Signature{}, fmt.Errorf("%w: signer algorithm %q for suite %s", ErrUnsupportedAlgorithm, handle.Algorithm, suite.ID)
	}
	sig, err := signer.Sign(ctx, message)
	if err != nil {
		return model.Signature{}, err
	}
	if sig.Alg != suite.Signature.Algorithm {
		return model.Signature{}, fmt.Errorf("%w: provider returned signature algorithm %q", ErrUnsupportedAlgorithm, sig.Alg)
	}
	if sig.KeyID != handle.KeyID {
		return model.Signature{}, fmt.Errorf("%w: provider returned signature key_id %q for handle %q", ErrInvalidKeyHandle, sig.KeyID, handle.KeyID)
	}
	if err := validateSignatureEncoding(suite, sig.Signature); err != nil {
		return model.Signature{}, err
	}
	sig.Signature = append([]byte(nil), sig.Signature...)
	return sig, nil
}

func Verify(ctx context.Context, provider Provider, descriptor PublicKeyDescriptor, message []byte, sig model.Signature) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ValidatePublicKey(provider, descriptor); err != nil {
		return err
	}
	if descriptor.KeyID != "" && descriptor.KeyID != sig.KeyID {
		return fmt.Errorf("%w: signature key_id %q does not match public key key_id %q", ErrInvalidKeyDescriptor, sig.KeyID, descriptor.KeyID)
	}
	verifier, err := provider.Verifier(descriptor.Algorithm, descriptor.Encoding)
	if err != nil {
		return err
	}
	return verifier.Verify(ctx, descriptor, message, sig)
}

// VerifySignatureForSuite exposes public verification for a known suite
// without enabling its production signing/generation paths. Reserved suites
// use this for conformance fixtures and offline-verifier development.
func VerifySignatureForSuite(ctx context.Context, suiteID cryptosuite.ID, descriptor PublicKeyDescriptor, message []byte, sig model.Signature) error {
	provider, err := providerForKnownSuite(suiteID)
	if err != nil {
		return err
	}
	return Verify(ctx, provider, descriptor, message, sig)
}

// ValidatePublicKeyForSuite validates a descriptor for a known suite without
// enabling that suite for production signing or evidence generation.
func ValidatePublicKeyForSuite(suiteID cryptosuite.ID, descriptor PublicKeyDescriptor) error {
	provider, err := providerForKnownSuite(suiteID)
	if err != nil {
		return err
	}
	return ValidatePublicKey(provider, descriptor)
}

type sha256Factory struct{}

func (sha256Factory) Algorithm() string { return cryptosuite.HashSHA256 }
func (sha256Factory) Size() int         { return sha256.Size }
func (sha256Factory) New() hash.Hash    { return sha256.New() }
func (sha256Factory) Sum(data []byte) []byte {
	sum := sha256.Sum256(data)
	return append([]byte(nil), sum[:]...)
}
func (sha256Factory) Sum32(data []byte) [32]byte { return sha256.Sum256(data) }

type sm3Factory struct{}

func (sm3Factory) Algorithm() string { return cryptosuite.HashSM3 }
func (sm3Factory) Size() int         { return sm3.Size }
func (sm3Factory) New() hash.Hash    { return sm3.New() }
func (sm3Factory) Sum(data []byte) []byte {
	sum := sm3.Sum(data)
	return append([]byte(nil), sum[:]...)
}
func (sm3Factory) Sum32(data []byte) [32]byte { return sm3.Sum(data) }

type ed25519Verifier struct{}

func (ed25519Verifier) Algorithm() string { return cryptosuite.SignatureEd25519 }
func (ed25519Verifier) Encoding() string  { return cryptosuite.Ed25519PublicKeyEncoding }

func (ed25519Verifier) Verify(ctx context.Context, descriptor PublicKeyDescriptor, message []byte, sig model.Signature) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if sig.Alg != cryptosuite.SignatureEd25519 {
		return fmt.Errorf("%w: signature %q", ErrUnsupportedAlgorithm, sig.Alg)
	}
	if len(sig.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("%w: ed25519 signature size %d", ErrUnsupportedEncoding, len(sig.Signature))
	}
	if !ed25519.Verify(ed25519.PublicKey(descriptor.Bytes), message, sig.Signature) {
		return errors.New("ed25519 signature verification failed")
	}
	return nil
}

type softwareEd25519Signer struct {
	handle     KeyHandle
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

func NewEd25519Signer(keyID string, privateKey ed25519.PrivateKey) (Signer, error) {
	if strings.TrimSpace(keyID) == "" {
		return nil, fmt.Errorf("%w: key_id is required", ErrInvalidKeyHandle)
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: ed25519 private key size %d", ErrInvalidKeyHandle, len(privateKey))
	}
	privateCopy := append(ed25519.PrivateKey(nil), privateKey...)
	publicCopy := append(ed25519.PublicKey(nil), privateCopy.Public().(ed25519.PublicKey)...)
	return &softwareEd25519Signer{
		handle: KeyHandle{
			Provider:  "software",
			KeyID:     keyID,
			Algorithm: cryptosuite.SignatureEd25519,
		},
		privateKey: privateCopy,
		publicKey:  publicCopy,
	}, nil
}

func MustNewEd25519Signer(keyID string, privateKey ed25519.PrivateKey) Signer {
	signer, err := NewEd25519Signer(keyID, privateKey)
	if err != nil {
		panic(err)
	}
	return signer
}

func NewEd25519PublicKey(keyID string, publicKey ed25519.PublicKey) (PublicKeyDescriptor, error) {
	descriptor := PublicKeyDescriptor{
		Suite:     cryptosuite.INTLV1,
		KeyID:     keyID,
		Algorithm: cryptosuite.SignatureEd25519,
		Encoding:  cryptosuite.Ed25519PublicKeyEncoding,
		Bytes:     append([]byte(nil), publicKey...),
	}
	if err := ValidatePublicKey(DefaultProvider(), descriptor); err != nil {
		return PublicKeyDescriptor{}, err
	}
	return descriptor, nil
}

func MustNewEd25519PublicKey(keyID string, publicKey ed25519.PublicKey) PublicKeyDescriptor {
	descriptor, err := NewEd25519PublicKey(keyID, publicKey)
	if err != nil {
		panic(err)
	}
	return descriptor
}

func (s *softwareEd25519Signer) Handle() KeyHandle { return s.handle }

func (*softwareEd25519Signer) Capabilities() CapabilitySet {
	return CapabilitySet(CapabilitySign | CapabilityPublicKey)
}

func (s *softwareEd25519Signer) PublicKey(ctx context.Context) (PublicKeyDescriptor, error) {
	if err := ctx.Err(); err != nil {
		return PublicKeyDescriptor{}, err
	}
	return NewEd25519PublicKey(s.handle.KeyID, s.publicKey)
}

func (s *softwareEd25519Signer) Sign(ctx context.Context, message []byte) (model.Signature, error) {
	if err := ctx.Err(); err != nil {
		return model.Signature{}, err
	}
	return model.Signature{
		Alg:       cryptosuite.SignatureEd25519,
		KeyID:     s.handle.KeyID,
		Signature: ed25519.Sign(s.privateKey, message),
	}, nil
}
