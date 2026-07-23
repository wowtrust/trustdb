package claim

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
)

const maxSigningInputBufferCapacity = 1 << 20

var signingInputBufferPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

type Verified struct {
	Claim     model.ClientClaim
	ClaimCBOR []byte
	Signature model.Signature
	RecordID  string
}

func NewFileClaim(tenantID, clientID, keyID string, producedAt time.Time, nonce []byte, idempotencyKey string, content model.Content, metadata model.Metadata) (model.ClientClaim, error) {
	if tenantID == "" || clientID == "" || keyID == "" {
		return model.ClientClaim{}, errors.New("tenant_id, client_id, and key_id are required")
	}
	if idempotencyKey == "" {
		return model.ClientClaim{}, errors.New("idempotency_key is required")
	}
	if len(nonce) < 16 {
		return model.ClientClaim{}, errors.New("nonce must be at least 16 bytes")
	}
	if content.HashAlg == "" {
		content.HashAlg = model.DefaultHashAlg
	}
	if len(content.ContentHash) == 0 {
		return model.ClientClaim{}, errors.New("content_hash is required")
	}
	if content.ContentLength < 0 {
		return model.ClientClaim{}, errors.New("content_length cannot be negative")
	}
	if metadata.EventType == "" {
		return model.ClientClaim{}, errors.New("metadata.event_type is required")
	}
	return model.ClientClaim{
		SchemaVersion:   model.SchemaClientClaim,
		TenantID:        tenantID,
		ClientID:        clientID,
		KeyID:           keyID,
		ProducedAtUnixN: producedAt.UTC().UnixNano(),
		Nonce:           append([]byte(nil), nonce...),
		IdempotencyKey:  idempotencyKey,
		Content:         content,
		Metadata:        metadata,
		TimeAttestation: model.TimeAttestation{Type: "none"},
	}, nil
}

func Canonical(claim model.ClientClaim) ([]byte, error) {
	if claim.SchemaVersion != model.SchemaClientClaim {
		return nil, fmt.Errorf("unexpected claim schema: %s", claim.SchemaVersion)
	}
	return cborx.Marshal(claim)
}

func SigningInput(claimCBOR []byte) []byte {
	out, err := trustcrypto.SignatureInputForSuite(cryptosuite.INTLV1, trustcrypto.SignaturePurposeClientClaim, claimCBOR)
	if err != nil {
		panic(err)
	}
	return out
}

func Sign(claim model.ClientClaim, privateKey ed25519.PrivateKey) (model.SignedClaim, error) {
	signer, err := trustcrypto.NewEd25519Signer(claim.KeyID, privateKey)
	if err != nil {
		return model.SignedClaim{}, err
	}
	return SignWithSigner(context.Background(), claim, signer)
}

func SignWithSigner(ctx context.Context, claim model.ClientClaim, signer trustcrypto.Signer) (model.SignedClaim, error) {
	return SignWithProvider(ctx, trustcrypto.DefaultProvider(), claim, signer)
}

func SignWithProvider(ctx context.Context, provider trustcrypto.Provider, claim model.ClientClaim, signer trustcrypto.Signer) (model.SignedClaim, error) {
	if provider == nil {
		return model.SignedClaim{}, errors.New("crypto provider is required")
	}
	if claim.SchemaVersion != model.SchemaClientClaim {
		return model.SignedClaim{}, fmt.Errorf("unexpected claim schema: %s", claim.SchemaVersion)
	}
	if signer == nil || signer.Handle().KeyID != claim.KeyID {
		return model.SignedClaim{}, errors.New("signer key_id does not match claim key_id")
	}
	input, buf, err := pooledClaimSigningInput(provider.Suite(), claim)
	if err != nil {
		return model.SignedClaim{}, err
	}
	defer releaseSigningInputBuffer(buf)
	sig, err := trustcrypto.Sign(ctx, provider.Suite(), signer, input)
	if err != nil {
		return model.SignedClaim{}, err
	}
	return model.SignedClaim{
		SchemaVersion: model.SchemaSignedClaim,
		Claim:         claim,
		Signature:     sig,
	}, nil
}

func Verify(signed model.SignedClaim, publicKey ed25519.PublicKey) (Verified, error) {
	descriptor, err := trustcrypto.NewEd25519PublicKey(signed.Claim.KeyID, publicKey)
	if err != nil {
		return Verified{}, err
	}
	return VerifyWithProvider(context.Background(), signed, descriptor, trustcrypto.DefaultProvider())
}

func VerifyWithProvider(ctx context.Context, signed model.SignedClaim, publicKey trustcrypto.PublicKeyDescriptor, provider trustcrypto.Provider) (Verified, error) {
	if provider == nil {
		return Verified{}, errors.New("crypto provider is required")
	}
	if signed.SchemaVersion != model.SchemaSignedClaim {
		return Verified{}, fmt.Errorf("unexpected signed claim schema: %s", signed.SchemaVersion)
	}
	claimCBOR, err := Canonical(signed.Claim)
	if err != nil {
		return Verified{}, err
	}
	if signed.Signature.KeyID != signed.Claim.KeyID {
		return Verified{}, errors.New("signature key_id does not match claim key_id")
	}
	input, buf, err := pooledSigningInput(provider.Suite(), claimCBOR)
	if err != nil {
		return Verified{}, err
	}
	defer releaseSigningInputBuffer(buf)
	if err := trustcrypto.Verify(ctx, provider, publicKey, input, signed.Signature); err != nil {
		return Verified{}, err
	}
	recordID, err := RecordIDWithProvider(provider, claimCBOR, signed.Signature)
	if err != nil {
		return Verified{}, err
	}
	return Verified{
		Claim:     signed.Claim,
		ClaimCBOR: claimCBOR,
		Signature: signed.Signature,
		RecordID:  recordID,
	}, nil
}

func pooledClaimSigningInput(suiteID cryptosuite.ID, claim model.ClientClaim) ([]byte, *bytes.Buffer, error) {
	buf := signingInputBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	prefix, err := trustcrypto.SignatureInputForSuite(suiteID, trustcrypto.SignaturePurposeClientClaim, nil)
	if err != nil {
		releaseSigningInputBuffer(buf)
		return nil, nil, err
	}
	buf.Write(prefix)
	if err := cborx.MarshalBuffer(buf, claim); err != nil {
		releaseSigningInputBuffer(buf)
		return nil, nil, err
	}
	return buf.Bytes(), buf, nil
}

func pooledSigningInput(suiteID cryptosuite.ID, claimCBOR []byte) ([]byte, *bytes.Buffer, error) {
	buf := signingInputBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	prefix, err := trustcrypto.SignatureInputForSuite(suiteID, trustcrypto.SignaturePurposeClientClaim, nil)
	if err != nil {
		releaseSigningInputBuffer(buf)
		return nil, nil, err
	}
	buf.Grow(len(prefix) + len(claimCBOR))
	buf.Write(prefix)
	buf.Write(claimCBOR)
	return buf.Bytes(), buf, nil
}

func releaseSigningInputBuffer(buf *bytes.Buffer) {
	if buf == nil || buf.Cap() > maxSigningInputBufferCapacity {
		return
	}
	buf.Reset()
	signingInputBufferPool.Put(buf)
}

func RecordID(claimCBOR []byte, sig model.Signature) string {
	return mustRecordIDWithProvider(trustcrypto.DefaultProvider(), claimCBOR, sig)
}

func RecordIDWithProvider(provider trustcrypto.Provider, claimCBOR []byte, sig model.Signature) (string, error) {
	if provider == nil {
		return "", errors.New("crypto provider is required")
	}
	suite, err := cryptosuite.RequireAvailable(provider.Suite())
	if err != nil {
		return "", err
	}
	factory, err := provider.HashFactory(suite.RecordIDHash.Algorithm)
	if err != nil {
		return "", err
	}
	h := factory.New()
	h.Write([]byte(suite.Domains.RecordID))
	h.Write([]byte{0})
	h.Write(claimCBOR)
	h.Write(sig.Signature)
	sum := h.Sum(nil)
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum)
	return "tr1" + strings.ToLower(enc), nil
}

func mustRecordIDWithProvider(provider trustcrypto.Provider, claimCBOR []byte, sig model.Signature) string {
	recordID, err := RecordIDWithProvider(provider, claimCBOR, sig)
	if err != nil {
		panic(err)
	}
	return recordID
}
