package claim

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ryan-wong-coder/trustdb/internal/cborx"
	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/trustcrypto"
)

const (
	signingDomain                 = "trustdb.client-claim.v1"
	recordDomain                  = "trustdb.record-id.v1"
	maxSigningInputBufferCapacity = 1 << 20
)

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
	out := make([]byte, 0, len(signingDomain)+1+len(claimCBOR))
	out = append(out, signingDomain...)
	out = append(out, 0)
	out = append(out, claimCBOR...)
	return out
}

func Sign(claim model.ClientClaim, privateKey ed25519.PrivateKey) (model.SignedClaim, error) {
	claimCBOR, err := Canonical(claim)
	if err != nil {
		return model.SignedClaim{}, err
	}
	input, buf := pooledSigningInput(claimCBOR)
	defer releaseSigningInputBuffer(buf)
	sig, err := trustcrypto.SignEd25519(claim.KeyID, privateKey, input)
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
	input, buf := pooledSigningInput(claimCBOR)
	defer releaseSigningInputBuffer(buf)
	if err := trustcrypto.VerifyEd25519(publicKey, input, signed.Signature); err != nil {
		return Verified{}, err
	}
	return Verified{
		Claim:     signed.Claim,
		ClaimCBOR: claimCBOR,
		Signature: signed.Signature,
		RecordID:  RecordID(claimCBOR, signed.Signature),
	}, nil
}

func pooledSigningInput(claimCBOR []byte) ([]byte, *bytes.Buffer) {
	buf := signingInputBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	buf.Grow(len(signingDomain) + 1 + len(claimCBOR))
	buf.WriteString(signingDomain)
	buf.WriteByte(0)
	buf.Write(claimCBOR)
	return buf.Bytes(), buf
}

func releaseSigningInputBuffer(buf *bytes.Buffer) {
	if buf == nil || buf.Cap() > maxSigningInputBufferCapacity {
		return
	}
	buf.Reset()
	signingInputBufferPool.Put(buf)
}

func RecordID(claimCBOR []byte, sig model.Signature) string {
	h := sha256.New()
	h.Write([]byte(recordDomain))
	h.Write([]byte{0})
	h.Write(claimCBOR)
	h.Write(sig.Signature)
	sum := h.Sum(nil)
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum)
	return "tr1" + strings.ToLower(enc)
}
