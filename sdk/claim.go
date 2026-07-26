package sdk

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/wowtrust/trustdb/v2/internal/claim"
	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/model"
	"github.com/wowtrust/trustdb/v2/internal/trustcrypto"
)

func BuildSignedFileClaim(raw io.Reader, id Identity, opts FileClaimOptions) (SignedClaim, error) {
	return BuildSignedFileClaimContext(context.Background(), raw, id, opts)
}

// BuildSignedFileClaimContext hashes and signs one file with the suite bound
// to id. Cancellation is observed between Reader calls and propagated to
// callback/HSM/remote signers. It cannot forcibly interrupt an arbitrary
// Reader while that Reader is blocked inside Read.
func BuildSignedFileClaimContext(ctx context.Context, raw io.Reader, id Identity, opts FileClaimOptions) (SignedClaim, error) {
	if raw == nil {
		return SignedClaim{}, errors.New("sdk: raw content reader is nil")
	}
	ctx = nonNilContext(ctx)
	if err := ctx.Err(); err != nil {
		return SignedClaim{}, err
	}
	descriptor, signer, err := id.signingMaterial()
	if err != nil {
		return SignedClaim{}, err
	}
	provider, err := trustcrypto.ProviderForSuite(descriptor.CryptoSuite)
	if err != nil {
		return SignedClaim{}, err
	}
	suite, err := cryptosuite.RequireAvailable(descriptor.CryptoSuite)
	if err != nil {
		return SignedClaim{}, err
	}
	hashAlg := opts.HashAlg
	if hashAlg == "" {
		hashAlg = suite.ContentHash.Algorithm
	}
	contentHash, n, err := trustcrypto.HashReaderWithProvider(provider, hashAlg, readerWithContext(ctx, raw))
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
	c, err := claim.NewFileClaimForSuite(
		descriptor.CryptoSuite,
		id.TenantID,
		id.ClientID,
		descriptor.KeyID,
		producedAt,
		nonce,
		idempotencyKey,
		content,
		metadata,
	)
	if err != nil {
		return SignedClaim{}, err
	}
	return claim.SignWithProvider(ctx, provider, c, signer)
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func readerWithContext(ctx context.Context, reader io.Reader) io.Reader {
	return &contextReader{ctx: nonNilContext(ctx), reader: reader}
}

func (r *contextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.reader.Read(buffer)
	if contextErr := r.ctx.Err(); contextErr != nil {
		return n, contextErr
	}
	return n, err
}

func VerifySignedClaim(signed SignedClaim, publicKey KeyDescriptor) (string, error) {
	if err := publicKey.Validate(); err != nil {
		return "", err
	}
	provider, err := trustcrypto.ProviderForSuite(signed.CryptoSuite)
	if err != nil {
		return "", err
	}
	verified, err := claim.VerifyWithProvider(context.Background(), signed, publicKey.internalPublicKey(), provider)
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
