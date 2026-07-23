package keystore

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
)

var crcTable = crc32.MakeTable(crc32.Castagnoli)

type Registry struct {
	mu       sync.RWMutex
	path     string
	signer   trustcrypto.Signer
	pub      trustcrypto.PublicKeyDescriptor
	provider trustcrypto.Provider
	events   []model.KeyEvent
	byKey    map[string]keyTimeline
	lastHash []byte
}

type keyTimeline struct {
	registered  model.KeyEvent
	revoked     *model.KeyEvent
	compromised *model.KeyEvent
}

func Open(path string, registrySigner trustcrypto.Signer, registryPub trustcrypto.PublicKeyDescriptor) (*Registry, error) {
	provider := trustcrypto.DefaultProvider()
	if registrySigner != nil {
		if err := trustcrypto.ValidateSignerHandle(provider.Suite(), registrySigner); err != nil {
			return nil, fmt.Errorf("keystore: invalid registry signer: %w", err)
		}
		signerPub, err := registrySigner.PublicKey(context.Background())
		if err != nil {
			return nil, fmt.Errorf("keystore: read registry public key: %w", err)
		}
		if err := trustcrypto.ValidatePublicKey(provider, signerPub); err != nil {
			return nil, fmt.Errorf("keystore: invalid signer public key: %w", err)
		}
		if len(registryPub.Bytes) == 0 {
			registryPub = signerPub
		} else if !samePublicKey(registryPub, signerPub) {
			return nil, errors.New("keystore: registry signer public key does not match configured registry public key")
		}
	}
	if len(registryPub.Bytes) != 0 {
		if err := trustcrypto.ValidatePublicKey(provider, registryPub); err != nil {
			return nil, fmt.Errorf("keystore: invalid registry public key: %w", err)
		}
	}
	r := &Registry{
		path:     path,
		signer:   registrySigner,
		pub:      registryPub.Clone(),
		provider: provider,
		byKey:    make(map[string]keyTimeline),
	}
	if err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

func samePublicKey(a, b trustcrypto.PublicKeyDescriptor) bool {
	return a.Suite == b.Suite &&
		a.Algorithm == b.Algorithm &&
		a.Encoding == b.Encoding &&
		(a.KeyID == "" || b.KeyID == "" || a.KeyID == b.KeyID) &&
		bytes.Equal(a.Bytes, b.Bytes)
}

func (r *Registry) RegisterClientKey(tenantID, clientID, keyID string, publicKey trustcrypto.PublicKeyDescriptor, validFrom, validUntil time.Time) (model.KeyEvent, error) {
	if r.signer == nil {
		return model.KeyEvent{}, errors.New("keystore: registry private key required")
	}
	if tenantID == "" || clientID == "" || keyID == "" {
		return model.KeyEvent{}, errors.New("keystore: tenant_id, client_id, and key_id are required")
	}
	if publicKey.KeyID != "" && publicKey.KeyID != keyID {
		return model.KeyEvent{}, fmt.Errorf("keystore: public key key_id %q does not match registration key_id %q", publicKey.KeyID, keyID)
	}
	if err := trustcrypto.ValidatePublicKey(r.provider, publicKey); err != nil {
		return model.KeyEvent{}, fmt.Errorf("keystore: invalid client public key: %w", err)
	}
	if !validUntil.IsZero() && !validUntil.After(validFrom) {
		return model.KeyEvent{}, errors.New("keystore: valid_until must be after valid_from")
	}
	ev := model.KeyEvent{
		SchemaVersion:   model.SchemaKeyEvent,
		Type:            model.KeyEventRegister,
		TenantID:        tenantID,
		ClientID:        clientID,
		KeyID:           keyID,
		Alg:             publicKey.Algorithm,
		PublicKey:       append([]byte(nil), publicKey.Bytes...),
		ValidFromUnixN:  validFrom.UTC().UnixNano(),
		ValidUntilUnixN: unixNanoOrZero(validUntil),
	}
	return r.appendEvent(ev)
}

func (r *Registry) RevokeClientKey(tenantID, clientID, keyID string, revokedAt time.Time, reason string) (model.KeyEvent, error) {
	if r.signer == nil {
		return model.KeyEvent{}, errors.New("keystore: registry private key required")
	}
	if tenantID == "" || clientID == "" || keyID == "" {
		return model.KeyEvent{}, errors.New("keystore: tenant_id, client_id, and key_id are required")
	}
	ev := model.KeyEvent{
		SchemaVersion:  model.SchemaKeyEvent,
		Type:           model.KeyEventRevoke,
		TenantID:       tenantID,
		ClientID:       clientID,
		KeyID:          keyID,
		Alg:            model.DefaultSignatureAlg,
		RevokedAtUnixN: revokedAt.UTC().UnixNano(),
		Reason:         reason,
	}
	return r.appendEvent(ev)
}

func (r *Registry) MarkClientKeyCompromised(tenantID, clientID, keyID string, compromisedAt time.Time, reason string) (model.KeyEvent, error) {
	if r.signer == nil {
		return model.KeyEvent{}, errors.New("keystore: registry private key required")
	}
	if tenantID == "" || clientID == "" || keyID == "" {
		return model.KeyEvent{}, errors.New("keystore: tenant_id, client_id, and key_id are required")
	}
	ev := model.KeyEvent{
		SchemaVersion:      model.SchemaKeyEvent,
		Type:               model.KeyEventCompromise,
		TenantID:           tenantID,
		ClientID:           clientID,
		KeyID:              keyID,
		Alg:                model.DefaultSignatureAlg,
		CompromisedAtUnixN: compromisedAt.UTC().UnixNano(),
		Reason:             reason,
	}
	return r.appendEvent(ev)
}

func (r *Registry) LookupClientKeyAt(tenantID, clientID, keyID string, at time.Time) (model.ClientKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	timeline, ok := r.byKey[identity(tenantID, clientID, keyID)]
	if !ok {
		return model.ClientKey{}, fmt.Errorf("keystore: key not found: %s/%s/%s", tenantID, clientID, keyID)
	}
	reg := timeline.registered
	atN := at.UTC().UnixNano()
	if atN < reg.ValidFromUnixN {
		return model.ClientKey{}, fmt.Errorf("keystore: key not valid yet")
	}
	if reg.ValidUntilUnixN != 0 && atN >= reg.ValidUntilUnixN {
		return model.ClientKey{}, fmt.Errorf("keystore: key expired")
	}
	status := model.KeyStatusValid
	var revokedAt, compromisedAt int64
	if timeline.revoked != nil && timeline.revoked.RevokedAtUnixN <= atN {
		status = model.KeyStatusRevoked
		revokedAt = timeline.revoked.RevokedAtUnixN
	}
	if timeline.compromised != nil && timeline.compromised.CompromisedAtUnixN <= atN {
		status = model.KeyStatusCompromised
		compromisedAt = timeline.compromised.CompromisedAtUnixN
	}
	if status != model.KeyStatusValid {
		return model.ClientKey{
			TenantID:           tenantID,
			ClientID:           clientID,
			KeyID:              keyID,
			Alg:                reg.Alg,
			PublicKey:          append([]byte(nil), reg.PublicKey...),
			ValidFromUnixN:     reg.ValidFromUnixN,
			ValidUntilUnixN:    reg.ValidUntilUnixN,
			Status:             status,
			RevokedAtUnixN:     revokedAt,
			CompromisedAtUnixN: compromisedAt,
		}, fmt.Errorf("keystore: key status is %s", status)
	}
	return model.ClientKey{
		TenantID:        tenantID,
		ClientID:        clientID,
		KeyID:           keyID,
		Alg:             reg.Alg,
		PublicKey:       append([]byte(nil), reg.PublicKey...),
		ValidFromUnixN:  reg.ValidFromUnixN,
		ValidUntilUnixN: reg.ValidUntilUnixN,
		Status:          status,
	}, nil
}

func (r *Registry) Events() []model.KeyEvent {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]model.KeyEvent, len(r.events))
	copy(out, r.events)
	return out
}

func (r *Registry) appendEvent(ev model.KeyEvent) (model.KeyEvent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.validateNextLocked(ev); err != nil {
		return model.KeyEvent{}, err
	}
	ev.Sequence = uint64(len(r.events) + 1)
	ev.PrevEventHash = append([]byte(nil), r.lastHash...)
	var err error
	ev.RegistrySignature, err = signEvent(ev, r.provider, r.signer)
	if err != nil {
		return model.KeyEvent{}, err
	}
	ev.EventHash, err = hashEventWithProvider(r.provider, ev)
	if err != nil {
		return model.KeyEvent{}, err
	}
	payload, err := cborx.Marshal(ev)
	if err != nil {
		return model.KeyEvent{}, err
	}
	if err := appendFrame(r.path, payload); err != nil {
		return model.KeyEvent{}, err
	}
	if err := r.applyLocked(ev); err != nil {
		return model.KeyEvent{}, err
	}
	return ev, nil
}

func (r *Registry) validateNextLocked(ev model.KeyEvent) error {
	switch ev.Type {
	case model.KeyEventRegister:
		id := identity(ev.TenantID, ev.ClientID, ev.KeyID)
		if _, exists := r.byKey[id]; exists {
			return fmt.Errorf("keystore: key already registered: %s", id)
		}
	case model.KeyEventRevoke:
		id := identity(ev.TenantID, ev.ClientID, ev.KeyID)
		timeline, exists := r.byKey[id]
		if !exists {
			return fmt.Errorf("keystore: cannot revoke missing key: %s", id)
		}
		if timeline.revoked != nil {
			return fmt.Errorf("keystore: key already revoked: %s", id)
		}
	case model.KeyEventCompromise:
		id := identity(ev.TenantID, ev.ClientID, ev.KeyID)
		timeline, exists := r.byKey[id]
		if !exists {
			return fmt.Errorf("keystore: cannot mark missing key compromised: %s", id)
		}
		if timeline.compromised != nil {
			return fmt.Errorf("keystore: key already compromised: %s", id)
		}
	default:
		return fmt.Errorf("keystore: unsupported key event type: %s", ev.Type)
	}
	return nil
}

func (r *Registry) load() error {
	if r.path == "" {
		return errors.New("keystore: path is required")
	}
	events, err := readFrames(r.path)
	if err != nil {
		return err
	}
	for i, ev := range events {
		if ev.Sequence != uint64(i+1) {
			return fmt.Errorf("keystore: sequence mismatch at event %d", i)
		}
		if !bytes.Equal(ev.PrevEventHash, r.lastHash) {
			return fmt.Errorf("keystore: hash chain mismatch at event %d", i)
		}
		if len(r.pub.Bytes) != 0 {
			if err := verifyEvent(ev, r.pub, r.provider); err != nil {
				return fmt.Errorf("keystore: event %d signature: %w", i, err)
			}
		}
		eventHash, err := hashEventWithProvider(r.provider, ev)
		if err != nil {
			return err
		}
		if !bytes.Equal(eventHash, ev.EventHash) {
			return fmt.Errorf("keystore: event hash mismatch at event %d", i)
		}
		if err := r.applyLoaded(ev); err != nil {
			return err
		}
	}
	return nil
}

func (r *Registry) applyLoaded(ev model.KeyEvent) error {
	if err := r.validateNextLoaded(ev); err != nil {
		return err
	}
	return r.applyLocked(ev)
}

func (r *Registry) validateNextLoaded(ev model.KeyEvent) error {
	switch ev.Type {
	case model.KeyEventRegister:
		if _, exists := r.byKey[identity(ev.TenantID, ev.ClientID, ev.KeyID)]; exists {
			return fmt.Errorf("keystore: duplicate register event for %s/%s/%s", ev.TenantID, ev.ClientID, ev.KeyID)
		}
	case model.KeyEventRevoke:
		id := identity(ev.TenantID, ev.ClientID, ev.KeyID)
		if _, exists := r.byKey[id]; !exists {
			return fmt.Errorf("keystore: revoke before register: %s", id)
		}
	case model.KeyEventCompromise:
		id := identity(ev.TenantID, ev.ClientID, ev.KeyID)
		if _, exists := r.byKey[id]; !exists {
			return fmt.Errorf("keystore: compromise before register: %s", id)
		}
	default:
		return fmt.Errorf("keystore: unsupported key event type: %s", ev.Type)
	}
	return nil
}

func (r *Registry) applyLocked(ev model.KeyEvent) error {
	id := identity(ev.TenantID, ev.ClientID, ev.KeyID)
	timeline := r.byKey[id]
	switch ev.Type {
	case model.KeyEventRegister:
		timeline.registered = ev
	case model.KeyEventRevoke:
		timeline.revoked = &ev
	case model.KeyEventCompromise:
		timeline.compromised = &ev
	default:
		return fmt.Errorf("keystore: unsupported key event type: %s", ev.Type)
	}
	r.byKey[id] = timeline
	r.events = append(r.events, ev)
	r.lastHash = append([]byte(nil), ev.EventHash...)
	return nil
}

func signEvent(ev model.KeyEvent, provider trustcrypto.Provider, signer trustcrypto.Signer) (model.Signature, error) {
	ev.RegistrySignature = model.Signature{}
	ev.EventHash = nil
	payload, err := cborx.Marshal(ev)
	if err != nil {
		return model.Signature{}, err
	}
	input, err := trustcrypto.SignatureInputForSuite(provider.Suite(), trustcrypto.SignaturePurposeKeyEvent, payload)
	if err != nil {
		return model.Signature{}, err
	}
	return trustcrypto.Sign(context.Background(), provider.Suite(), signer, input)
}

func verifyEvent(ev model.KeyEvent, pub trustcrypto.PublicKeyDescriptor, provider trustcrypto.Provider) error {
	sig := ev.RegistrySignature
	ev.RegistrySignature = model.Signature{}
	ev.EventHash = nil
	payload, err := cborx.Marshal(ev)
	if err != nil {
		return err
	}
	input, err := trustcrypto.SignatureInputForSuite(provider.Suite(), trustcrypto.SignaturePurposeKeyEvent, payload)
	if err != nil {
		return err
	}
	return trustcrypto.Verify(context.Background(), provider, pub, input, sig)
}

func hashEvent(ev model.KeyEvent) ([]byte, error) {
	return hashEventWithProvider(trustcrypto.DefaultProvider(), ev)
}

func hashEventWithProvider(provider trustcrypto.Provider, ev model.KeyEvent) ([]byte, error) {
	if provider == nil {
		return nil, errors.New("keystore: crypto provider is required")
	}
	ev.EventHash = nil
	payload, err := cborx.Marshal(ev)
	if err != nil {
		return nil, err
	}
	suite, err := cryptosuite.RequireAvailable(provider.Suite())
	if err != nil {
		return nil, err
	}
	factory, err := provider.HashFactory(suite.KeyEventHash.Algorithm)
	if err != nil {
		return nil, err
	}
	return factory.Sum(domainInput(suite.Domains.KeyEventHash, payload)), nil
}

func appendFrame(path string, payload []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	crc := crc32.Checksum(payload, crcTable)
	var trailer [4]byte
	binary.BigEndian.PutUint32(trailer[:], crc)
	if _, err := f.Write(header[:]); err != nil {
		return err
	}
	if _, err := f.Write(payload); err != nil {
		return err
	}
	if _, err := f.Write(trailer[:]); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return nil
}

func readFrames(path string) ([]model.KeyEvent, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []model.KeyEvent
	for {
		var header [4]byte
		if _, err := io.ReadFull(f, header[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			return nil, err
		}
		n := binary.BigEndian.Uint32(header[:])
		if n == 0 || n > cborx.DefaultMaxBytes {
			return nil, fmt.Errorf("keystore: invalid frame length: %d", n)
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(f, payload); err != nil {
			return nil, err
		}
		var trailer [4]byte
		if _, err := io.ReadFull(f, trailer[:]); err != nil {
			return nil, err
		}
		want := binary.BigEndian.Uint32(trailer[:])
		got := crc32.Checksum(payload, crcTable)
		if want != got {
			return nil, fmt.Errorf("keystore: crc mismatch")
		}
		var ev model.KeyEvent
		if err := cborx.Unmarshal(payload, &ev); err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
}

func domainInput(domain string, payload []byte) []byte {
	out := make([]byte, 0, len(domain)+1+len(payload))
	out = append(out, domain...)
	out = append(out, 0)
	out = append(out, payload...)
	return out
}

func identity(tenantID, clientID, keyID string) string {
	return tenantID + "\x00" + clientID + "\x00" + keyID
}

func unixNanoOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UTC().UnixNano()
}
