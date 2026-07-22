package trustcrypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/wowtrust/trustdb/internal/model"
)

const (
	Ed25519PublicKeySize  = ed25519.PublicKeySize
	Ed25519PrivateKeySize = ed25519.PrivateKeySize
)

func GenerateEd25519Key() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	return pub, priv, nil
}

func NewNonce(size int) ([]byte, error) {
	if size < 16 {
		return nil, errors.New("nonce must be at least 16 bytes")
	}
	nonce := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return nonce, nil
}

func HashBytes(alg string, data []byte) ([]byte, error) {
	switch alg {
	case model.DefaultHashAlg:
		sum := sha256.Sum256(data)
		return sum[:], nil
	default:
		return nil, fmt.Errorf("unsupported hash alg: %s", alg)
	}
}

func HashReader(alg string, r io.Reader) (sum []byte, bytesRead int64, err error) {
	h, err := newHash(alg)
	if err != nil {
		return nil, 0, err
	}
	n, err := io.Copy(h, r)
	if err != nil {
		return nil, n, fmt.Errorf("hash reader: %w", err)
	}
	return h.Sum(nil), n, nil
}

func SignEd25519(keyID string, privateKey ed25519.PrivateKey, message []byte) (model.Signature, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return model.Signature{}, fmt.Errorf("invalid ed25519 private key size: %d", len(privateKey))
	}
	return model.Signature{
		Alg:       model.DefaultSignatureAlg,
		KeyID:     keyID,
		Signature: ed25519.Sign(privateKey, message),
	}, nil
}

func VerifyEd25519(publicKey ed25519.PublicKey, message []byte, sig model.Signature) error {
	if sig.Alg != model.DefaultSignatureAlg {
		return fmt.Errorf("unsupported signature alg: %s", sig.Alg)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid ed25519 public key size: %d", len(publicKey))
	}
	if !ed25519.Verify(publicKey, message, sig.Signature) {
		return errors.New("ed25519 signature verification failed")
	}
	return nil
}

func newHash(alg string) (hash.Hash, error) {
	switch alg {
	case model.DefaultHashAlg:
		return sha256.New(), nil
	default:
		return nil, fmt.Errorf("unsupported hash alg: %s", alg)
	}
}
