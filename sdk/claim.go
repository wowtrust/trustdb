package sdk

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/wowtrust/trustdb/internal/claim"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
)

func BuildSignedFileClaim(raw io.Reader, id Identity, opts FileClaimOptions) (SignedClaim, error) {
	if raw == nil {
		return SignedClaim{}, errors.New("sdk: raw content reader is nil")
	}
	if len(id.PrivateKey) != trustcrypto.Ed25519PrivateKeySize {
		return SignedClaim{}, fmt.Errorf("sdk: invalid ed25519 private key size: %d", len(id.PrivateKey))
	}
	hashAlg := opts.HashAlg
	if hashAlg == "" {
		hashAlg = model.DefaultHashAlg
	}
	contentHash, n, err := trustcrypto.HashReader(hashAlg, raw)
	if err != nil {
		return SignedClaim{}, err
	}
	producedAt := opts.ProducedAt
	if producedAt.IsZero() {
		producedAt = time.Now().UTC()
	}
	nonce := opts.Nonce
	if len(nonce) == 0 {
		nonce, err = trustcrypto.NewNonce(16)
		if err != nil {
			return SignedClaim{}, err
		}
	}
	idempotencyKey := opts.IdempotencyKey
	if idempotencyKey == "" {
		idempotencyKey, err = randomIdempotencyKey()
		if err != nil {
			return SignedClaim{}, err
		}
	}
	eventType := opts.EventType
	if eventType == "" {
		eventType = "file.snapshot"
	}
	metadata := model.Metadata{
		EventType: eventType,
		Source:    opts.Source,
		Custom:    copyStringMap(opts.CustomMetadata),
	}
	content := model.Content{
		HashAlg:       hashAlg,
		ContentHash:   contentHash,
		ContentLength: n,
		MediaType:     opts.MediaType,
		StorageURI:    opts.StorageURI,
	}
	c, err := claim.NewFileClaim(
		id.TenantID,
		id.ClientID,
		id.KeyID,
		producedAt,
		nonce,
		idempotencyKey,
		content,
		metadata,
	)
	if err != nil {
		return SignedClaim{}, err
	}
	return claim.Sign(c, id.PrivateKey)
}

func VerifySignedClaim(signed SignedClaim, publicKey ed25519.PublicKey) (string, error) {
	verified, err := claim.Verify(signed, publicKey)
	if err != nil {
		return "", err
	}
	return verified.RecordID, nil
}

func randomIdempotencyKey() (string, error) {
	raw := make([]byte, 18)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", fmt.Errorf("sdk: generate idempotency key: %w", err)
	}
	return "sdk-" + base64.RawURLEncoding.EncodeToString(raw), nil
}

func copyStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
