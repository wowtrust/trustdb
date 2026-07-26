package trustcrypto

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/model"
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
	return HashBytesWithProvider(DefaultProvider(), alg, data)
}

func HashBytesForSuite(suiteID cryptosuite.ID, alg string, data []byte) ([]byte, error) {
	factory, err := HashFactoryForSuite(suiteID, alg)
	if err != nil {
		return nil, err
	}
	return factory.Sum(data), nil
}

func HashBytesWithProvider(provider Provider, alg string, data []byte) ([]byte, error) {
	if provider == nil {
		return nil, errors.New("crypto provider is required")
	}
	factory, err := provider.HashFactory(alg)
	if err != nil {
		return nil, err
	}
	return factory.Sum(data), nil
}

func HashReader(alg string, r io.Reader) (sum []byte, bytesRead int64, err error) {
	return HashReaderWithProvider(DefaultProvider(), alg, r)
}

func HashReaderForSuite(suiteID cryptosuite.ID, alg string, r io.Reader) (sum []byte, bytesRead int64, err error) {
	factory, err := HashFactoryForSuite(suiteID, alg)
	if err != nil {
		return nil, 0, err
	}
	return hashReader(factory, r)
}

func HashReaderWithProvider(provider Provider, alg string, r io.Reader) (sum []byte, bytesRead int64, err error) {
	if provider == nil {
		return nil, 0, errors.New("crypto provider is required")
	}
	factory, err := provider.HashFactory(alg)
	if err != nil {
		return nil, 0, err
	}
	return hashReader(factory, r)
}

func hashReader(factory HashFactory, r io.Reader) (sum []byte, bytesRead int64, err error) {
	if factory == nil {
		return nil, 0, errors.New("hash factory is required")
	}
	h := factory.New()
	n, err := io.Copy(h, r)
	if err != nil {
		return nil, n, fmt.Errorf("hash reader: %w", err)
	}
	return h.Sum(nil), n, nil
}

func SignEd25519(keyID string, privateKey ed25519.PrivateKey, message []byte) (model.Signature, error) {
	signer, err := NewEd25519Signer(keyID, privateKey)
	if err != nil {
		return model.Signature{}, err
	}
	return Sign(context.Background(), cryptosuite.INTLV1, signer, message)
}

func VerifyEd25519(publicKey ed25519.PublicKey, message []byte, sig model.Signature) error {
	descriptor, err := NewEd25519PublicKey("", publicKey)
	if err != nil {
		return err
	}
	return Verify(context.Background(), DefaultProvider(), descriptor, message, sig)
}
