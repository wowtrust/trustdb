package receipt

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"sync"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
)

const (
	acceptedDomain           = "trustdb.accepted-receipt.v1"
	committedDomain          = "trustdb.committed-receipt.v1"
	maxSigningBufferCapacity = 1 << 20
)

var signingBufferPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

func SignAccepted(r model.AcceptedReceipt, keyID string, privateKey ed25519.PrivateKey) (model.AcceptedReceipt, error) {
	signer, err := trustcrypto.NewEd25519Signer(keyID, privateKey)
	if err != nil {
		return model.AcceptedReceipt{}, err
	}
	return SignAcceptedWithSigner(context.Background(), r, signer)
}

func SignAcceptedWithSigner(ctx context.Context, r model.AcceptedReceipt, signer trustcrypto.Signer) (model.AcceptedReceipt, error) {
	return SignAcceptedWithProvider(ctx, trustcrypto.DefaultProvider(), r, signer)
}

func SignAcceptedWithProvider(ctx context.Context, provider trustcrypto.Provider, r model.AcceptedReceipt, signer trustcrypto.Signer) (model.AcceptedReceipt, error) {
	if provider == nil {
		return model.AcceptedReceipt{}, fmt.Errorf("sign accepted receipt: crypto provider is required")
	}
	r.ServerSig = model.Signature{}
	input, buf, err := encodeDomainInput(provider.Suite(), trustcrypto.SignaturePurposeAcceptedReceipt, r)
	if err != nil {
		return model.AcceptedReceipt{}, err
	}
	defer releaseSigningBuffer(buf)
	sig, err := trustcrypto.Sign(ctx, provider.Suite(), signer, input)
	if err != nil {
		return model.AcceptedReceipt{}, err
	}
	r.ServerSig = sig
	return r, nil
}

func VerifyAccepted(r model.AcceptedReceipt, publicKey ed25519.PublicKey) error {
	descriptor, err := trustcrypto.NewEd25519PublicKey("", publicKey)
	if err != nil {
		return err
	}
	return VerifyAcceptedWithProvider(context.Background(), r, descriptor, trustcrypto.DefaultProvider())
}

func VerifyAcceptedWithProvider(ctx context.Context, r model.AcceptedReceipt, publicKey trustcrypto.PublicKeyDescriptor, provider trustcrypto.Provider) error {
	if provider == nil {
		return fmt.Errorf("verify accepted receipt: crypto provider is required")
	}
	sig := r.ServerSig
	r.ServerSig = model.Signature{}
	input, buf, err := encodeDomainInput(provider.Suite(), trustcrypto.SignaturePurposeAcceptedReceipt, r)
	if err != nil {
		return err
	}
	defer releaseSigningBuffer(buf)
	if err := trustcrypto.Verify(ctx, provider, publicKey, input, sig); err != nil {
		return fmt.Errorf("verify accepted receipt: %w", err)
	}
	return nil
}

func SignCommitted(r model.CommittedReceipt, keyID string, privateKey ed25519.PrivateKey) (model.CommittedReceipt, error) {
	signer, err := trustcrypto.NewEd25519Signer(keyID, privateKey)
	if err != nil {
		return model.CommittedReceipt{}, err
	}
	return SignCommittedWithSigner(context.Background(), r, signer)
}

func SignCommittedWithSigner(ctx context.Context, r model.CommittedReceipt, signer trustcrypto.Signer) (model.CommittedReceipt, error) {
	return SignCommittedWithProvider(ctx, trustcrypto.DefaultProvider(), r, signer)
}

func SignCommittedWithProvider(ctx context.Context, provider trustcrypto.Provider, r model.CommittedReceipt, signer trustcrypto.Signer) (model.CommittedReceipt, error) {
	if provider == nil {
		return model.CommittedReceipt{}, fmt.Errorf("sign committed receipt: crypto provider is required")
	}
	r.ServerSig = model.Signature{}
	input, buf, err := encodeDomainInput(provider.Suite(), trustcrypto.SignaturePurposeCommittedReceipt, r)
	if err != nil {
		return model.CommittedReceipt{}, err
	}
	defer releaseSigningBuffer(buf)
	sig, err := trustcrypto.Sign(ctx, provider.Suite(), signer, input)
	if err != nil {
		return model.CommittedReceipt{}, err
	}
	r.ServerSig = sig
	return r, nil
}

func VerifyCommitted(r model.CommittedReceipt, publicKey ed25519.PublicKey) error {
	descriptor, err := trustcrypto.NewEd25519PublicKey("", publicKey)
	if err != nil {
		return err
	}
	return VerifyCommittedWithProvider(context.Background(), r, descriptor, trustcrypto.DefaultProvider())
}

func VerifyCommittedWithProvider(ctx context.Context, r model.CommittedReceipt, publicKey trustcrypto.PublicKeyDescriptor, provider trustcrypto.Provider) error {
	if provider == nil {
		return fmt.Errorf("verify committed receipt: crypto provider is required")
	}
	sig := r.ServerSig
	r.ServerSig = model.Signature{}
	input, buf, err := encodeDomainInput(provider.Suite(), trustcrypto.SignaturePurposeCommittedReceipt, r)
	if err != nil {
		return err
	}
	defer releaseSigningBuffer(buf)
	if err := trustcrypto.Verify(ctx, provider, publicKey, input, sig); err != nil {
		return fmt.Errorf("verify committed receipt: %w", err)
	}
	return nil
}

func encodeDomainInput(suiteID cryptosuite.ID, purpose trustcrypto.SignaturePurpose, value any) ([]byte, *bytes.Buffer, error) {
	buf := signingBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	prefix, err := trustcrypto.SignatureInputForSuite(suiteID, purpose, nil)
	if err != nil {
		releaseSigningBuffer(buf)
		return nil, nil, err
	}
	buf.Write(prefix)
	if err := cborx.MarshalBuffer(buf, value); err != nil {
		releaseSigningBuffer(buf)
		return nil, nil, err
	}
	return buf.Bytes(), buf, nil
}

func releaseSigningBuffer(buf *bytes.Buffer) {
	if buf == nil || buf.Cap() > maxSigningBufferCapacity {
		return
	}
	buf.Reset()
	signingBufferPool.Put(buf)
}
