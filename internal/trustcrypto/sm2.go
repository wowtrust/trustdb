package trustcrypto

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/emmansun/gmsm/sm2"

	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/model"
)

const (
	SM2PrivateKeySize = 32
	SM2PublicKeySize  = 65
)

const canonicalSM2UserID = cryptosuite.SM2DefaultUserID

type sm2ASN1Signature struct {
	R *big.Int
	S *big.Int
}

func validateSignatureEncoding(suite cryptosuite.Suite, signature []byte) error {
	switch suite.Signature.Encoding {
	case cryptosuite.Ed25519SignatureEncoding:
		if len(signature) != ed25519.SignatureSize {
			return fmt.Errorf("%w: ed25519 signature size %d", ErrUnsupportedEncoding, len(signature))
		}
		return nil
	case cryptosuite.SM2SignatureEncoding:
		return ValidateSM2SignatureDER(signature)
	default:
		return fmt.Errorf("%w: signature encoding %q", ErrUnsupportedEncoding, suite.Signature.Encoding)
	}
}

// ValidateSM2SignatureDER accepts exactly one canonical ASN.1 DER
// SEQUENCE(INTEGER r, INTEGER s). It rejects trailing bytes, non-minimal
// integer encodings, negative/zero values, and values outside the SM2 order.
func ValidateSM2SignatureDER(signature []byte) error {
	if len(signature) < 8 || len(signature) > 72 {
		return fmt.Errorf("%w: SM2 DER signature size %d", ErrUnsupportedEncoding, len(signature))
	}
	var parsed sm2ASN1Signature
	rest, err := asn1.Unmarshal(signature, &parsed)
	if err != nil || len(rest) != 0 || parsed.R == nil || parsed.S == nil {
		return fmt.Errorf("%w: invalid SM2 DER signature", ErrUnsupportedEncoding)
	}
	order := sm2.P256().Params().N
	if parsed.R.Sign() <= 0 || parsed.S.Sign() <= 0 || parsed.R.Cmp(order) >= 0 || parsed.S.Cmp(order) >= 0 {
		return fmt.Errorf("%w: SM2 signature integers are out of range", ErrUnsupportedEncoding)
	}
	canonical, err := asn1.Marshal(parsed)
	if err != nil || !bytes.Equal(canonical, signature) {
		return fmt.Errorf("%w: non-canonical SM2 DER signature", ErrUnsupportedEncoding)
	}
	return nil
}

func validateSM2PublicKey(encoded []byte) error {
	if len(encoded) != SM2PublicKeySize || encoded[0] != 0x04 {
		return fmt.Errorf("%w: SM2 public key must be a 65-byte uncompressed point", ErrInvalidKeyDescriptor)
	}
	publicKey, err := sm2.NewPublicKey(encoded)
	if err != nil {
		return fmt.Errorf("%w: invalid SM2 public key: %v", ErrInvalidKeyDescriptor, err)
	}
	canonical := elliptic.Marshal(sm2.P256(), publicKey.X, publicKey.Y)
	if !bytes.Equal(canonical, encoded) {
		return fmt.Errorf("%w: non-canonical SM2 public key", ErrInvalidKeyDescriptor)
	}
	return nil
}

type sm2Verifier struct{}

func (sm2Verifier) Algorithm() string { return cryptosuite.SignatureSM2SM3 }
func (sm2Verifier) Encoding() string  { return cryptosuite.SM2PublicKeyEncoding }

func (sm2Verifier) Verify(ctx context.Context, descriptor PublicKeyDescriptor, message []byte, sig model.Signature) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if sig.Alg != cryptosuite.SignatureSM2SM3 {
		return fmt.Errorf("%w: signature %q", ErrUnsupportedAlgorithm, sig.Alg)
	}
	if err := ValidateSM2SignatureDER(sig.Signature); err != nil {
		return err
	}
	publicKey, err := sm2.NewPublicKey(descriptor.Bytes)
	if err != nil {
		return fmt.Errorf("%w: invalid SM2 public key: %v", ErrInvalidKeyDescriptor, err)
	}
	if !sm2.VerifyASN1WithSM2(publicKey, []byte(canonicalSM2UserID), message, sig.Signature) {
		return errors.New("SM2-SM3 signature verification failed")
	}
	return nil
}

type softwareSM2Signer struct {
	handle     KeyHandle
	privateKey *sm2.PrivateKey
	publicKey  []byte
}

// NewSM2Signer creates the development/reference software signer. Production
// CN_SM_V1 deployments must use an approved external key provider; core code
// still cannot select CN_SM_V1 while the suite remains reserved.
func NewSM2Signer(keyID string, privateKey []byte) (Signer, error) {
	if strings.TrimSpace(keyID) == "" {
		return nil, fmt.Errorf("%w: key_id is required", ErrInvalidKeyHandle)
	}
	if len(privateKey) != SM2PrivateKeySize {
		return nil, fmt.Errorf("%w: SM2 private key size %d", ErrInvalidKeyHandle, len(privateKey))
	}
	privateCopy := append([]byte(nil), privateKey...)
	parsed, err := sm2.NewPrivateKey(privateCopy)
	clear(privateCopy)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid SM2 private key: %v", ErrInvalidKeyHandle, err)
	}
	publicKey := elliptic.Marshal(sm2.P256(), parsed.X, parsed.Y)
	return &softwareSM2Signer{
		handle: KeyHandle{
			Provider:  "software",
			KeyID:     keyID,
			Algorithm: cryptosuite.SignatureSM2SM3,
		},
		privateKey: parsed,
		publicKey:  publicKey,
	}, nil
}

func NewSM2PublicKey(keyID string, publicKey []byte) (PublicKeyDescriptor, error) {
	descriptor := PublicKeyDescriptor{
		Suite:     cryptosuite.CNSMV1,
		KeyID:     keyID,
		Algorithm: cryptosuite.SignatureSM2SM3,
		Encoding:  cryptosuite.SM2PublicKeyEncoding,
		Bytes:     append([]byte(nil), publicKey...),
	}
	if err := ValidatePublicKey(cnSMV1Provider{}, descriptor); err != nil {
		return PublicKeyDescriptor{}, err
	}
	return descriptor, nil
}

func (s *softwareSM2Signer) Handle() KeyHandle { return s.handle }

func (*softwareSM2Signer) Capabilities() CapabilitySet {
	return CapabilitySet(CapabilitySign | CapabilityPublicKey)
}

func (s *softwareSM2Signer) PublicKey(ctx context.Context) (PublicKeyDescriptor, error) {
	if err := ctx.Err(); err != nil {
		return PublicKeyDescriptor{}, err
	}
	return NewSM2PublicKey(s.handle.KeyID, s.publicKey)
}

func (s *softwareSM2Signer) Sign(ctx context.Context, message []byte) (model.Signature, error) {
	if err := ctx.Err(); err != nil {
		return model.Signature{}, err
	}
	signature, err := s.privateKey.SignWithSM2(rand.Reader, []byte(canonicalSM2UserID), message)
	if err != nil {
		return model.Signature{}, fmt.Errorf("sign SM2-SM3 message: %w", err)
	}
	if err := ValidateSM2SignatureDER(signature); err != nil {
		return model.Signature{}, fmt.Errorf("provider returned invalid SM2 signature: %w", err)
	}
	return model.Signature{
		Alg:       cryptosuite.SignatureSM2SM3,
		KeyID:     s.handle.KeyID,
		Signature: append([]byte(nil), signature...),
	}, nil
}
