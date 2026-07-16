package receipt

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"sync"

	"github.com/ryan-wong-coder/trustdb/internal/cborx"
	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/trustcrypto"
)

const (
	acceptedDomain           = "trustdb.accepted-receipt.v1"
	committedDomain          = "trustdb.committed-receipt.v1"
	maxSigningBufferCapacity = 1 << 20
)

var signingBufferPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

func SignAccepted(r model.AcceptedReceipt, keyID string, privateKey ed25519.PrivateKey) (model.AcceptedReceipt, error) {
	r.ServerSig = model.Signature{}
	input, buf, err := encodeDomainInput(acceptedDomain, r)
	if err != nil {
		return model.AcceptedReceipt{}, err
	}
	defer releaseSigningBuffer(buf)
	sig, err := trustcrypto.SignEd25519(keyID, privateKey, input)
	if err != nil {
		return model.AcceptedReceipt{}, err
	}
	r.ServerSig = sig
	return r, nil
}

func VerifyAccepted(r model.AcceptedReceipt, publicKey ed25519.PublicKey) error {
	sig := r.ServerSig
	r.ServerSig = model.Signature{}
	input, buf, err := encodeDomainInput(acceptedDomain, r)
	if err != nil {
		return err
	}
	defer releaseSigningBuffer(buf)
	if err := trustcrypto.VerifyEd25519(publicKey, input, sig); err != nil {
		return fmt.Errorf("verify accepted receipt: %w", err)
	}
	return nil
}

func SignCommitted(r model.CommittedReceipt, keyID string, privateKey ed25519.PrivateKey) (model.CommittedReceipt, error) {
	r.ServerSig = model.Signature{}
	input, buf, err := encodeDomainInput(committedDomain, r)
	if err != nil {
		return model.CommittedReceipt{}, err
	}
	defer releaseSigningBuffer(buf)
	sig, err := trustcrypto.SignEd25519(keyID, privateKey, input)
	if err != nil {
		return model.CommittedReceipt{}, err
	}
	r.ServerSig = sig
	return r, nil
}

func VerifyCommitted(r model.CommittedReceipt, publicKey ed25519.PublicKey) error {
	sig := r.ServerSig
	r.ServerSig = model.Signature{}
	input, buf, err := encodeDomainInput(committedDomain, r)
	if err != nil {
		return err
	}
	defer releaseSigningBuffer(buf)
	if err := trustcrypto.VerifyEd25519(publicKey, input, sig); err != nil {
		return fmt.Errorf("verify committed receipt: %w", err)
	}
	return nil
}

func encodeDomainInput(domain string, value any) ([]byte, *bytes.Buffer, error) {
	buf := signingBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	buf.WriteString(domain)
	buf.WriteByte(0)
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
