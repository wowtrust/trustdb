package sdk

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"

	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/keydescriptor"
	"github.com/wowtrust/trustdb/v2/internal/model"
	"github.com/wowtrust/trustdb/v2/internal/trustcrypto"
)

// CryptoSuite identifies one immutable TrustDB cryptographic profile.
type CryptoSuite = cryptosuite.ID

const (
	CryptoSuiteINTLV1 CryptoSuite = cryptosuite.INTLV1
	CryptoSuiteCNSMV1 CryptoSuite = cryptosuite.CNSMV1

	HashAlgorithmSHA256 = cryptosuite.HashSHA256
	HashAlgorithmSM3    = cryptosuite.HashSM3

	SignatureAlgorithmEd25519 = cryptosuite.SignatureEd25519
	SignatureAlgorithmSM2SM3  = cryptosuite.SignatureSM2SM3

	PublicKeyEncodingEd25519 = cryptosuite.Ed25519PublicKeyEncoding
	PublicKeyEncodingSM2     = cryptosuite.SM2PublicKeyEncoding

	SM2DefaultUserID = cryptosuite.SM2DefaultUserID
)

// KeyDescriptor is the public, suite-aware identity boundary used by the SDK.
// PublicKey and CertificateChain contain only public material. Provider names
// the private-key boundary for signers ("software", "remote", "pkcs11",
// "sdf", or an application-defined callback provider).
type KeyDescriptor struct {
	CryptoSuite       CryptoSuite
	Provider          string
	KeyID             string
	Algorithm         string
	PublicKeyEncoding string
	PublicKey         []byte
	SM2UserID         string
	CertificateChain  [][]byte
}

func (d KeyDescriptor) Clone() KeyDescriptor {
	d.PublicKey = append([]byte(nil), d.PublicKey...)
	d.CertificateChain = cloneBytesList(d.CertificateChain)
	return d
}

// Validate verifies the immutable suite, key encoding, SM2 user ID, and
// optional certificate chain without accessing a provider or network.
func (d KeyDescriptor) Validate() error {
	if strings.TrimSpace(d.Provider) == "" {
		return errors.New("sdk: key descriptor provider is required")
	}
	if strings.TrimSpace(d.KeyID) == "" {
		return errors.New("sdk: key descriptor key_id is required")
	}
	suite, err := cryptosuite.RequireAvailable(d.CryptoSuite)
	if err != nil {
		return fmt.Errorf("sdk: key descriptor crypto_suite: %w", err)
	}
	if d.Algorithm != suite.Signature.Algorithm {
		return fmt.Errorf("sdk: key descriptor algorithm %q does not match suite %s", d.Algorithm, suite.ID)
	}
	if d.PublicKeyEncoding != suite.Signature.PublicKeyEncoding {
		return fmt.Errorf("sdk: key descriptor public key encoding %q does not match suite %s", d.PublicKeyEncoding, suite.ID)
	}
	if suite.ID == cryptosuite.CNSMV1 {
		if d.SM2UserID != suite.Signature.SM2UserID {
			return errors.New("sdk: key descriptor SM2 user ID does not match CN_SM_V1")
		}
	} else if d.SM2UserID != "" {
		return fmt.Errorf("sdk: key descriptor SM2 user ID is not allowed for suite %s", suite.ID)
	}
	if err := trustcrypto.ValidatePublicKeyForSuite(d.CryptoSuite, d.internalPublicKey()); err != nil {
		return fmt.Errorf("sdk: key descriptor public key: %w", err)
	}
	// Reuse the canonical descriptor validator for certificate count, size,
	// algorithm, chain ordering, and leaf-key binding.
	publicDescriptor := keydescriptor.Descriptor{
		SchemaVersion: keydescriptor.SchemaV1,
		Kind:          keydescriptor.KindVerifier,
		Provider:      keydescriptor.ProviderPublic,
		CryptoSuite:   d.CryptoSuite,
		KeyID:         d.KeyID,
		Algorithm:     d.Algorithm,
		SM2UserID:     d.SM2UserID,
		PublicKey: keydescriptor.PublicKeyMaterial{
			Encoding: d.PublicKeyEncoding,
			Bytes:    append([]byte(nil), d.PublicKey...),
		},
		CertificateChain: cloneBytesList(d.CertificateChain),
	}
	if err := publicDescriptor.Validate(); err != nil {
		return fmt.Errorf("sdk: key descriptor certificate metadata: %w", err)
	}
	return nil
}

func (d KeyDescriptor) internalPublicKey() trustcrypto.PublicKeyDescriptor {
	return trustcrypto.PublicKeyDescriptor{
		Suite:     d.CryptoSuite,
		KeyID:     d.KeyID,
		Algorithm: d.Algorithm,
		Encoding:  d.PublicKeyEncoding,
		Bytes:     append([]byte(nil), d.PublicKey...),
	}
}

// Signer represents a software, HSM, SDF, KMS, or remote private key without
// exposing private key bytes to the SDK. Implementations must be safe for
// concurrent calls because batch and stream APIs may sign in parallel.
type Signer interface {
	Descriptor() KeyDescriptor
	Sign(context.Context, []byte) ([]byte, error)
}

type callbackSigner struct {
	descriptor KeyDescriptor
	callback   func(context.Context, []byte) ([]byte, error)
}

// NewCallbackSigner binds a non-exportable key descriptor to an application
// callback. The SDK validates every returned signature against descriptor's
// public key before it can enter a claim.
func NewCallbackSigner(
	descriptor KeyDescriptor,
	callback func(context.Context, []byte) ([]byte, error),
) (Signer, error) {
	if callback == nil {
		return nil, errors.New("sdk: signer callback is nil")
	}
	if err := descriptor.Validate(); err != nil {
		return nil, err
	}
	return &callbackSigner{descriptor: descriptor.Clone(), callback: callback}, nil
}

func (s *callbackSigner) Descriptor() KeyDescriptor { return s.descriptor.Clone() }

func (s *callbackSigner) Sign(ctx context.Context, message []byte) ([]byte, error) {
	if err := nonNilContext(ctx).Err(); err != nil {
		return nil, err
	}
	signature, err := s.callback(nonNilContext(ctx), append([]byte(nil), message...))
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), signature...), nil
}

type softwareSigner struct {
	descriptor KeyDescriptor
	signer     trustcrypto.Signer
}

func (s *softwareSigner) Descriptor() KeyDescriptor { return s.descriptor.Clone() }

func (s *softwareSigner) Sign(ctx context.Context, message []byte) ([]byte, error) {
	signature, err := s.signer.Sign(nonNilContext(ctx), append([]byte(nil), message...))
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), signature.Signature...), nil
}

// NewINTLV1SoftwareSigner is the simple local Ed25519 constructor. Production
// callers may instead use NewCallbackSigner to keep private keys outside the
// process.
func NewINTLV1SoftwareSigner(keyID string, privateKey ed25519.PrivateKey) (Signer, error) {
	internal, err := trustcrypto.NewEd25519Signer(keyID, privateKey)
	if err != nil {
		return nil, err
	}
	publicKey, err := internal.PublicKey(context.Background())
	if err != nil {
		return nil, err
	}
	return newSoftwareSigner(internal, publicKey, "")
}

// NewCNSMV1SoftwareSigner is a development/reference SM2 constructor.
// Production keys should remain behind NewCallbackSigner.
func NewCNSMV1SoftwareSigner(keyID string, privateKey []byte) (Signer, error) {
	internal, err := trustcrypto.NewSM2Signer(keyID, privateKey)
	if err != nil {
		return nil, err
	}
	publicKey, err := internal.PublicKey(context.Background())
	if err != nil {
		return nil, err
	}
	return newSoftwareSigner(internal, publicKey, cryptosuite.SM2DefaultUserID)
}

func newSoftwareSigner(internal trustcrypto.Signer, publicKey trustcrypto.PublicKeyDescriptor, sm2UserID string) (Signer, error) {
	descriptor := KeyDescriptor{
		CryptoSuite:       publicKey.Suite,
		Provider:          keydescriptor.ProviderSoftware,
		KeyID:             publicKey.KeyID,
		Algorithm:         publicKey.Algorithm,
		PublicKeyEncoding: publicKey.Encoding,
		PublicKey:         append([]byte(nil), publicKey.Bytes...),
		SM2UserID:         sm2UserID,
	}
	if err := descriptor.Validate(); err != nil {
		return nil, err
	}
	return &softwareSigner{descriptor: descriptor, signer: internal}, nil
}

// GenerateCNSMV1SoftwareKey returns a development/reference SM2 key pair.
// Production private keys should be generated and retained by an HSM/SDF/KMS.
func GenerateCNSMV1SoftwareKey() (publicKey, privateKey []byte, err error) {
	return trustcrypto.GenerateSM2Key()
}

// NewINTLV1PublicKey creates an explicit INTL_V1 verifier descriptor.
func NewINTLV1PublicKey(keyID string, publicKey ed25519.PublicKey) (KeyDescriptor, error) {
	internal, err := trustcrypto.NewEd25519PublicKey(keyID, publicKey)
	if err != nil {
		return KeyDescriptor{}, err
	}
	return keyDescriptorFromInternal(internal, "")
}

// NewCNSMV1PublicKey creates an explicit CN_SM_V1 verifier descriptor.
func NewCNSMV1PublicKey(keyID string, publicKey []byte) (KeyDescriptor, error) {
	internal, err := trustcrypto.NewSM2PublicKey(keyID, publicKey)
	if err != nil {
		return KeyDescriptor{}, err
	}
	return keyDescriptorFromInternal(internal, cryptosuite.SM2DefaultUserID)
}

func keyDescriptorFromInternal(internal trustcrypto.PublicKeyDescriptor, sm2UserID string) (KeyDescriptor, error) {
	descriptor := KeyDescriptor{
		CryptoSuite:       internal.Suite,
		Provider:          keydescriptor.ProviderPublic,
		KeyID:             internal.KeyID,
		Algorithm:         internal.Algorithm,
		PublicKeyEncoding: internal.Encoding,
		PublicKey:         append([]byte(nil), internal.Bytes...),
		SM2UserID:         sm2UserID,
	}
	if err := descriptor.Validate(); err != nil {
		return KeyDescriptor{}, err
	}
	return descriptor, nil
}

type sdkSignerAdapter struct {
	signer     Signer
	descriptor KeyDescriptor
}

func signerAdapter(signer Signer) (*sdkSignerAdapter, error) {
	if signer == nil {
		return nil, errors.New("sdk: signer is nil")
	}
	descriptor := signer.Descriptor().Clone()
	if err := descriptor.Validate(); err != nil {
		return nil, err
	}
	return &sdkSignerAdapter{signer: signer, descriptor: descriptor}, nil
}

func (s *sdkSignerAdapter) Handle() trustcrypto.KeyHandle {
	return trustcrypto.KeyHandle{
		Provider:  s.descriptor.Provider,
		KeyID:     s.descriptor.KeyID,
		Algorithm: s.descriptor.Algorithm,
	}
}

func (*sdkSignerAdapter) Capabilities() trustcrypto.CapabilitySet {
	return trustcrypto.CapabilitySet(trustcrypto.CapabilitySign | trustcrypto.CapabilityPublicKey)
}

func (s *sdkSignerAdapter) PublicKey(ctx context.Context) (trustcrypto.PublicKeyDescriptor, error) {
	if err := nonNilContext(ctx).Err(); err != nil {
		return trustcrypto.PublicKeyDescriptor{}, err
	}
	return s.descriptor.internalPublicKey(), nil
}

func (s *sdkSignerAdapter) Sign(ctx context.Context, message []byte) (model.Signature, error) {
	ctx = nonNilContext(ctx)
	if err := ctx.Err(); err != nil {
		return model.Signature{}, err
	}
	raw, err := s.signer.Sign(ctx, append([]byte(nil), message...))
	if err != nil {
		return model.Signature{}, err
	}
	signature := model.Signature{
		Alg:       s.descriptor.Algorithm,
		KeyID:     s.descriptor.KeyID,
		Signature: append([]byte(nil), raw...),
	}
	provider, err := trustcrypto.ProviderForSuite(s.descriptor.CryptoSuite)
	if err != nil {
		return model.Signature{}, err
	}
	if err := trustcrypto.Verify(ctx, provider, s.descriptor.internalPublicKey(), message, signature); err != nil {
		return model.Signature{}, fmt.Errorf("sdk: signer returned an invalid signature: %w", err)
	}
	return signature, nil
}

func cloneBytesList(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for index := range in {
		out[index] = append([]byte(nil), in[index]...)
	}
	return out
}
