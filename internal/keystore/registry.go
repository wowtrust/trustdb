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
	"strings"
	"sync"
	"time"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/keydescriptor"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
)

const (
	SchemaRegistryV2     = "trustdb.key-registry.v2"
	registryFormatV2     = uint16(2)
	maxRegistryFrameSize = 4 << 20
)

var (
	registryMagic = []byte("TDBKEYR2\n")
	crcTable      = crc32.MakeTable(crc32.Castagnoli)

	ErrUnsupportedRegistryFormat = errors.New("unsupported key registry format")
	ErrConflictingKeyID          = errors.New("key ID conflicts with existing registry material")
)

// Manifest is the immutable header of a V2 key registry. The registry public
// key is recorded to bind every event to one signer, but callers must still
// provide the trusted public descriptor when reopening an existing registry.
type Manifest struct {
	SchemaVersion          string         `cbor:"schema_version" json:"schema_version"`
	FormatVersion          uint16         `cbor:"format_version" json:"format_version"`
	CryptoSuite            cryptosuite.ID `cbor:"crypto_suite" json:"crypto_suite"`
	RegistryKeyID          string         `cbor:"registry_key_id" json:"registry_key_id"`
	RegistryAlgorithm      string         `cbor:"registry_algorithm" json:"registry_algorithm"`
	RegistryPublicEncoding string         `cbor:"registry_public_encoding" json:"registry_public_encoding"`
	RegistryPublicKey      []byte         `cbor:"registry_public_key" json:"registry_public_key"`
}

func (m Manifest) publicKeyDescriptor() trustcrypto.PublicKeyDescriptor {
	return trustcrypto.PublicKeyDescriptor{
		Suite:     m.CryptoSuite,
		KeyID:     m.RegistryKeyID,
		Algorithm: m.RegistryAlgorithm,
		Encoding:  m.RegistryPublicEncoding,
		Bytes:     append([]byte(nil), m.RegistryPublicKey...),
	}
}

func (m Manifest) clone() Manifest {
	m.RegistryPublicKey = append([]byte(nil), m.RegistryPublicKey...)
	return m
}

type Registry struct {
	mu          sync.RWMutex
	path        string
	signer      trustcrypto.Signer
	manifest    Manifest
	registryPub trustcrypto.PublicKeyDescriptor
	events      []model.KeyEvent
	byKey       map[string]keyTimeline
	lastHash    []byte
	durableEnd  int64
}

type keyTimeline struct {
	registered  model.KeyEvent
	descriptor  keydescriptor.Descriptor
	revoked     *model.KeyEvent
	compromised *model.KeyEvent
	rotated     *model.KeyEvent
}

func Open(path string, registrySigner trustcrypto.Signer, trustedRegistryPub trustcrypto.PublicKeyDescriptor) (*Registry, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("keystore: path is required")
	}
	if registrySigner != nil {
		signerPub, err := validateLifecycleSigner(registrySigner)
		if err != nil {
			return nil, fmt.Errorf("keystore: invalid registry signer: %w", err)
		}
		if len(trustedRegistryPub.Bytes) == 0 {
			trustedRegistryPub = signerPub
		} else if !samePublicKey(trustedRegistryPub, signerPub) {
			return nil, errors.New("keystore: registry signer public key does not match trusted registry public key")
		}
	}
	if len(trustedRegistryPub.Bytes) != 0 {
		if strings.TrimSpace(trustedRegistryPub.KeyID) == "" {
			return nil, errors.New("keystore: trusted registry public key requires key_id")
		}
		if err := trustcrypto.ValidatePublicKeyForSuite(trustedRegistryPub.Suite, trustedRegistryPub); err != nil {
			return nil, fmt.Errorf("keystore: invalid trusted registry public key: %w", err)
		}
	}

	_, statErr := os.Stat(path)
	if errors.Is(statErr, os.ErrNotExist) {
		if registrySigner == nil {
			return nil, errors.New("keystore: registry signer is required to initialize a V2 registry")
		}
		manifest := manifestForPublicKey(trustedRegistryPub)
		if err := initializeRegistry(path, manifest); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	} else if statErr != nil {
		return nil, statErr
	}

	manifest, events, durableEnd, truncatedTail, err := readRegistry(path)
	if err != nil {
		return nil, err
	}
	if len(trustedRegistryPub.Bytes) == 0 {
		return nil, errors.New("keystore: trusted registry public descriptor is required to verify an existing registry")
	}
	manifestPub := manifest.publicKeyDescriptor()
	if !samePublicKey(manifestPub, trustedRegistryPub) {
		return nil, errors.New("keystore: trusted registry public key does not match V2 manifest")
	}
	if registrySigner != nil && truncatedTail {
		if err := truncateAndSync(path, durableEnd); err != nil {
			return nil, fmt.Errorf("keystore: repair incomplete registry tail: %w", err)
		}
	}

	r := &Registry{
		path:        path,
		signer:      registrySigner,
		manifest:    manifest.clone(),
		registryPub: manifestPub,
		byKey:       make(map[string]keyTimeline),
		durableEnd:  durableEnd,
	}
	for i, event := range events {
		if err := r.loadEvent(i, event); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func manifestForPublicKey(publicKey trustcrypto.PublicKeyDescriptor) Manifest {
	return Manifest{
		SchemaVersion:          SchemaRegistryV2,
		FormatVersion:          registryFormatV2,
		CryptoSuite:            publicKey.Suite,
		RegistryKeyID:          publicKey.KeyID,
		RegistryAlgorithm:      publicKey.Algorithm,
		RegistryPublicEncoding: publicKey.Encoding,
		RegistryPublicKey:      append([]byte(nil), publicKey.Bytes...),
	}
}

func validateLifecycleSigner(signer trustcrypto.Signer) (trustcrypto.PublicKeyDescriptor, error) {
	if signer == nil {
		return trustcrypto.PublicKeyDescriptor{}, errors.New("signer is nil")
	}
	if !signer.Capabilities().Supports(trustcrypto.CapabilitySign) || !signer.Capabilities().Supports(trustcrypto.CapabilityPublicKey) {
		return trustcrypto.PublicKeyDescriptor{}, trustcrypto.ErrUnsupportedCapability
	}
	handle := signer.Handle()
	if err := handle.Validate(); err != nil {
		return trustcrypto.PublicKeyDescriptor{}, err
	}
	publicKey, err := signer.PublicKey(context.Background())
	if err != nil {
		return trustcrypto.PublicKeyDescriptor{}, fmt.Errorf("read registry public key: %w", err)
	}
	suite, err := cryptosuite.RequireKnown(publicKey.Suite)
	if err != nil {
		return trustcrypto.PublicKeyDescriptor{}, err
	}
	if handle.KeyID != publicKey.KeyID || handle.Algorithm != suite.Signature.Algorithm || publicKey.Algorithm != suite.Signature.Algorithm {
		return trustcrypto.PublicKeyDescriptor{}, errors.New("signer handle and public key metadata differ")
	}
	if err := trustcrypto.ValidatePublicKeyForSuite(publicKey.Suite, publicKey); err != nil {
		return trustcrypto.PublicKeyDescriptor{}, err
	}
	return publicKey.Clone(), nil
}

func samePublicKey(a, b trustcrypto.PublicKeyDescriptor) bool {
	return a.Suite == b.Suite &&
		a.KeyID == b.KeyID &&
		a.Algorithm == b.Algorithm &&
		a.Encoding == b.Encoding &&
		bytes.Equal(a.Bytes, b.Bytes)
}

func (r *Registry) Manifest() Manifest {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.manifest.clone()
}

func (r *Registry) Suite() cryptosuite.ID {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.manifest.CryptoSuite
}

func (r *Registry) RegisterClientKey(tenantID, clientID string, descriptor keydescriptor.Descriptor, validFrom, validUntil time.Time) (model.KeyEvent, error) {
	if r.signer == nil {
		return model.KeyEvent{}, errors.New("keystore: registry signer is required")
	}
	encoded, err := validateRegistrationDescriptor(r.manifest.CryptoSuite, descriptor)
	if err != nil {
		return model.KeyEvent{}, err
	}
	if tenantID == "" || clientID == "" {
		return model.KeyEvent{}, errors.New("keystore: tenant_id and client_id are required")
	}
	validFrom, validUntil, err = constrainValidityToCertificate(descriptor, validFrom, validUntil)
	if err != nil {
		return model.KeyEvent{}, err
	}
	event := model.KeyEvent{
		SchemaVersion:   model.SchemaKeyEvent,
		CryptoSuite:     r.manifest.CryptoSuite,
		Type:            model.KeyEventRegister,
		TenantID:        tenantID,
		ClientID:        clientID,
		KeyID:           descriptor.KeyID,
		KeyDescriptor:   encoded,
		ValidFromUnixN:  validFrom.UTC().UnixNano(),
		ValidUntilUnixN: unixNanoOrZero(validUntil),
	}
	return r.appendEvent(event)
}

func (r *Registry) RotateClientKey(tenantID, clientID, previousKeyID string, descriptor keydescriptor.Descriptor, rotatedAt, validUntil time.Time, reason string) (model.KeyEvent, error) {
	if r.signer == nil {
		return model.KeyEvent{}, errors.New("keystore: registry signer is required")
	}
	encoded, err := validateRegistrationDescriptor(r.manifest.CryptoSuite, descriptor)
	if err != nil {
		return model.KeyEvent{}, err
	}
	if tenantID == "" || clientID == "" || previousKeyID == "" || descriptor.KeyID == previousKeyID {
		return model.KeyEvent{}, errors.New("keystore: tenant_id, client_id, distinct previous_key_id, and key_id are required")
	}
	rotatedAt, validUntil, err = constrainValidityToCertificate(descriptor, rotatedAt, validUntil)
	if err != nil {
		return model.KeyEvent{}, err
	}
	event := model.KeyEvent{
		SchemaVersion:   model.SchemaKeyEvent,
		CryptoSuite:     r.manifest.CryptoSuite,
		Type:            model.KeyEventRotate,
		TenantID:        tenantID,
		ClientID:        clientID,
		KeyID:           descriptor.KeyID,
		PreviousKeyID:   previousKeyID,
		KeyDescriptor:   encoded,
		ValidFromUnixN:  rotatedAt.UTC().UnixNano(),
		ValidUntilUnixN: unixNanoOrZero(validUntil),
		RotatedAtUnixN:  rotatedAt.UTC().UnixNano(),
		Reason:          reason,
	}
	return r.appendEvent(event)
}

func (r *Registry) RevokeClientKey(tenantID, clientID, keyID string, revokedAt time.Time, reason string) (model.KeyEvent, error) {
	return r.appendStatusEvent(model.KeyEventRevoke, tenantID, clientID, keyID, revokedAt, reason)
}

func (r *Registry) MarkClientKeyCompromised(tenantID, clientID, keyID string, compromisedAt time.Time, reason string) (model.KeyEvent, error) {
	return r.appendStatusEvent(model.KeyEventCompromise, tenantID, clientID, keyID, compromisedAt, reason)
}

func (r *Registry) appendStatusEvent(eventType, tenantID, clientID, keyID string, at time.Time, reason string) (model.KeyEvent, error) {
	if r.signer == nil {
		return model.KeyEvent{}, errors.New("keystore: registry signer is required")
	}
	if tenantID == "" || clientID == "" || keyID == "" {
		return model.KeyEvent{}, errors.New("keystore: tenant_id, client_id, and key_id are required")
	}
	event := model.KeyEvent{
		SchemaVersion: model.SchemaKeyEvent,
		CryptoSuite:   r.manifest.CryptoSuite,
		Type:          eventType,
		TenantID:      tenantID,
		ClientID:      clientID,
		KeyID:         keyID,
		Reason:        reason,
	}
	switch eventType {
	case model.KeyEventRevoke:
		event.RevokedAtUnixN = at.UTC().UnixNano()
	case model.KeyEventCompromise:
		event.CompromisedAtUnixN = at.UTC().UnixNano()
	default:
		return model.KeyEvent{}, fmt.Errorf("keystore: unsupported status event type: %s", eventType)
	}
	return r.appendEvent(event)
}

func validateRegistrationDescriptor(registrySuite cryptosuite.ID, descriptor keydescriptor.Descriptor) ([]byte, error) {
	if err := descriptor.Validate(); err != nil {
		return nil, fmt.Errorf("keystore: invalid key descriptor: %w", err)
	}
	if descriptor.CryptoSuite != registrySuite {
		return nil, fmt.Errorf("keystore: %w: registry is %s, key is %s", cryptosuite.ErrMixedSuite, registrySuite, descriptor.CryptoSuite)
	}
	encoded, err := keydescriptor.Marshal(descriptor)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

func constrainValidityToCertificate(descriptor keydescriptor.Descriptor, validFrom, validUntil time.Time) (time.Time, time.Time, error) {
	validFrom = validFrom.UTC()
	validUntil = validUntil.UTC()
	if validFrom.IsZero() {
		return time.Time{}, time.Time{}, errors.New("keystore: valid_from is required")
	}
	if !validUntil.IsZero() && !validUntil.After(validFrom) {
		return time.Time{}, time.Time{}, errors.New("keystore: valid_until must be after valid_from")
	}
	certificates, err := descriptor.CertificateMetadata()
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	if len(certificates) == 0 {
		return validFrom, validUntil, nil
	}
	leafNotBefore := time.Unix(0, certificates[0].NotBeforeUnixN).UTC()
	leafNotAfter := time.Unix(0, certificates[0].NotAfterUnixN).UTC()
	if validFrom.Before(leafNotBefore) || !validFrom.Before(leafNotAfter) {
		return time.Time{}, time.Time{}, errors.New("keystore: valid_from is outside the leaf certificate validity interval")
	}
	if validUntil.IsZero() {
		validUntil = leafNotAfter
	} else if validUntil.After(leafNotAfter) {
		return time.Time{}, time.Time{}, errors.New("keystore: valid_until exceeds the leaf certificate validity interval")
	}
	return validFrom, validUntil, nil
}

func (r *Registry) LookupClientKeyAt(tenantID, clientID, keyID string, at time.Time) (model.ClientKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	timeline, ok := r.byKey[identity(tenantID, clientID, keyID)]
	if !ok {
		return model.ClientKey{}, fmt.Errorf("keystore: key not found: %s/%s/%s", tenantID, clientID, keyID)
	}
	registered := timeline.registered
	atN := at.UTC().UnixNano()
	key := clientKeyFromTimeline(tenantID, clientID, timeline)
	if atN < registered.ValidFromUnixN {
		return key, errors.New("keystore: key not valid yet")
	}
	if registered.ValidUntilUnixN != 0 && atN >= registered.ValidUntilUnixN {
		return key, errors.New("keystore: key expired")
	}
	if timeline.rotated != nil && timeline.rotated.RotatedAtUnixN <= atN {
		key.Status = model.KeyStatusRevoked
		key.RevokedAtUnixN = timeline.rotated.RotatedAtUnixN
	}
	if timeline.revoked != nil && timeline.revoked.RevokedAtUnixN <= atN {
		key.Status = model.KeyStatusRevoked
		key.RevokedAtUnixN = timeline.revoked.RevokedAtUnixN
	}
	if timeline.compromised != nil && timeline.compromised.CompromisedAtUnixN <= atN {
		key.Status = model.KeyStatusCompromised
		key.CompromisedAtUnixN = timeline.compromised.CompromisedAtUnixN
	}
	if key.Status != model.KeyStatusValid {
		return key, fmt.Errorf("keystore: key status is %s", key.Status)
	}
	return key, nil
}

func clientKeyFromTimeline(tenantID, clientID string, timeline keyTimeline) model.ClientKey {
	descriptor := timeline.descriptor
	return model.ClientKey{
		TenantID:          tenantID,
		ClientID:          clientID,
		KeyID:             descriptor.KeyID,
		CryptoSuite:       descriptor.CryptoSuite,
		Alg:               descriptor.Algorithm,
		PublicKeyEncoding: descriptor.PublicKey.Encoding,
		PublicKey:         append([]byte(nil), descriptor.PublicKey.Bytes...),
		SM2UserID:         descriptor.SM2UserID,
		CertificateChain:  cloneBytesList(descriptor.CertificateChain),
		Provider:          descriptor.Provider,
		KeyDescriptor:     append([]byte(nil), timeline.registered.KeyDescriptor...),
		ValidFromUnixN:    timeline.registered.ValidFromUnixN,
		ValidUntilUnixN:   timeline.registered.ValidUntilUnixN,
		Status:            model.KeyStatusValid,
	}
}

func (r *Registry) Events() []model.KeyEvent {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]model.KeyEvent, len(r.events))
	for i := range r.events {
		out[i] = cloneEvent(r.events[i])
	}
	return out
}

func (r *Registry) appendEvent(event model.KeyEvent) (model.KeyEvent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if existing, ok := r.idempotentEventLocked(event); ok {
		return cloneEvent(existing), nil
	}
	if err := r.validateNextLocked(event); err != nil {
		return model.KeyEvent{}, err
	}
	event.Sequence = uint64(len(r.events) + 1)
	event.PrevEventHash = append([]byte(nil), r.lastHash...)
	signature, err := signEvent(event, r.signer, r.registryPub)
	if err != nil {
		return model.KeyEvent{}, err
	}
	event.RegistrySignature = signature
	event.EventHash, err = hashEvent(event)
	if err != nil {
		return model.KeyEvent{}, err
	}
	payload, err := cborx.Marshal(event)
	if err != nil {
		return model.KeyEvent{}, err
	}
	frame, err := encodeFrame(payload)
	if err != nil {
		return model.KeyEvent{}, err
	}
	if err := appendAndSync(r.path, frame); err != nil {
		return model.KeyEvent{}, err
	}
	r.durableEnd += int64(len(frame))
	if err := r.applyLocked(event); err != nil {
		return model.KeyEvent{}, err
	}
	return cloneEvent(event), nil
}

func (r *Registry) idempotentEventLocked(candidate model.KeyEvent) (model.KeyEvent, bool) {
	timeline, exists := r.byKey[identity(candidate.TenantID, candidate.ClientID, candidate.KeyID)]
	if !exists {
		return model.KeyEvent{}, false
	}
	var existing *model.KeyEvent
	switch candidate.Type {
	case model.KeyEventRegister, model.KeyEventRotate:
		existing = &timeline.registered
	case model.KeyEventRevoke:
		existing = timeline.revoked
	case model.KeyEventCompromise:
		existing = timeline.compromised
	}
	if existing == nil || !sameUnsignedEvent(*existing, candidate) {
		return model.KeyEvent{}, false
	}
	return *existing, true
}

func sameUnsignedEvent(a, b model.KeyEvent) bool {
	clearEventEnvelope(&a)
	clearEventEnvelope(&b)
	aBytes, aErr := cborx.Marshal(a)
	bBytes, bErr := cborx.Marshal(b)
	return aErr == nil && bErr == nil && bytes.Equal(aBytes, bBytes)
}

func clearEventEnvelope(event *model.KeyEvent) {
	event.Sequence = 0
	event.PrevEventHash = nil
	event.EventHash = nil
	event.RegistrySignature = model.Signature{}
}

func (r *Registry) validateNextLocked(event model.KeyEvent) error {
	_, err := validateEventShape(r.manifest.CryptoSuite, event)
	if err != nil {
		return err
	}
	id := identity(event.TenantID, event.ClientID, event.KeyID)
	switch event.Type {
	case model.KeyEventRegister:
		if _, exists := r.byKey[id]; exists {
			return fmt.Errorf("keystore: %w: %s", ErrConflictingKeyID, id)
		}
	case model.KeyEventRotate:
		if _, exists := r.byKey[id]; exists {
			return fmt.Errorf("keystore: %w: %s", ErrConflictingKeyID, id)
		}
		previousID := identity(event.TenantID, event.ClientID, event.PreviousKeyID)
		previous, exists := r.byKey[previousID]
		if !exists {
			return fmt.Errorf("keystore: cannot rotate missing key: %s", previousID)
		}
		if previous.rotated != nil || previous.revoked != nil {
			return fmt.Errorf("keystore: previous key is already retired: %s", previousID)
		}
		if event.RotatedAtUnixN < previous.registered.ValidFromUnixN {
			return errors.New("keystore: rotated_at precedes previous key validity")
		}
	case model.KeyEventRevoke:
		timeline, exists := r.byKey[id]
		if !exists {
			return fmt.Errorf("keystore: cannot revoke missing key: %s", id)
		}
		if timeline.revoked != nil || timeline.rotated != nil {
			return fmt.Errorf("keystore: key is already retired: %s", id)
		}
		if event.RevokedAtUnixN < timeline.registered.ValidFromUnixN {
			return errors.New("keystore: revoked_at precedes key validity")
		}
	case model.KeyEventCompromise:
		timeline, exists := r.byKey[id]
		if !exists {
			return fmt.Errorf("keystore: cannot mark missing key compromised: %s", id)
		}
		if timeline.compromised != nil {
			return fmt.Errorf("keystore: key is already marked compromised: %s", id)
		}
	default:
		return fmt.Errorf("keystore: unsupported key event type: %s", event.Type)
	}
	return nil
}

func validateEventShape(suiteID cryptosuite.ID, event model.KeyEvent) (keydescriptor.Descriptor, error) {
	if event.SchemaVersion != model.SchemaKeyEvent {
		return keydescriptor.Descriptor{}, fmt.Errorf("keystore: key event schema must be %s", model.SchemaKeyEvent)
	}
	if event.CryptoSuite != suiteID {
		return keydescriptor.Descriptor{}, fmt.Errorf("keystore: %w: registry is %s, event is %s", cryptosuite.ErrMixedSuite, suiteID, event.CryptoSuite)
	}
	if event.TenantID == "" || event.ClientID == "" || event.KeyID == "" {
		return keydescriptor.Descriptor{}, errors.New("keystore: event identity is incomplete")
	}
	if len(event.Reason) > 4096 || strings.ContainsAny(event.Reason, "\x00\r\n") {
		return keydescriptor.Descriptor{}, errors.New("keystore: event reason is invalid")
	}
	switch event.Type {
	case model.KeyEventRegister, model.KeyEventRotate:
		descriptor, err := keydescriptor.Unmarshal(event.KeyDescriptor)
		if err != nil {
			return keydescriptor.Descriptor{}, fmt.Errorf("keystore: event key descriptor: %w", err)
		}
		if descriptor.KeyID != event.KeyID || descriptor.CryptoSuite != suiteID {
			return keydescriptor.Descriptor{}, errors.New("keystore: event descriptor identity or suite mismatch")
		}
		// Unix epoch is a valid lifecycle boundary. Do not use zero as a
		// sentinel for ValidFromUnixN; callers may intentionally register a
		// key that has been valid since 1970-01-01T00:00:00Z.
		if event.ValidUntilUnixN != 0 && event.ValidUntilUnixN <= event.ValidFromUnixN {
			return keydescriptor.Descriptor{}, errors.New("keystore: event validity interval is invalid")
		}
		if event.Type == model.KeyEventRotate {
			if event.PreviousKeyID == "" || event.PreviousKeyID == event.KeyID || event.RotatedAtUnixN != event.ValidFromUnixN || event.RevokedAtUnixN != 0 || event.CompromisedAtUnixN != 0 {
				return keydescriptor.Descriptor{}, errors.New("keystore: rotation linkage or time is invalid")
			}
		} else if event.PreviousKeyID != "" || event.RotatedAtUnixN != 0 || event.RevokedAtUnixN != 0 || event.CompromisedAtUnixN != 0 || event.Reason != "" {
			return keydescriptor.Descriptor{}, errors.New("keystore: registration contains rotation fields")
		}
		return descriptor, nil
	case model.KeyEventRevoke:
		if len(event.KeyDescriptor) != 0 || event.PreviousKeyID != "" || event.ValidFromUnixN != 0 || event.ValidUntilUnixN != 0 || event.RotatedAtUnixN != 0 || event.RevokedAtUnixN == 0 || event.CompromisedAtUnixN != 0 {
			return keydescriptor.Descriptor{}, errors.New("keystore: revocation fields are invalid")
		}
	case model.KeyEventCompromise:
		if len(event.KeyDescriptor) != 0 || event.PreviousKeyID != "" || event.ValidFromUnixN != 0 || event.ValidUntilUnixN != 0 || event.RotatedAtUnixN != 0 || event.RevokedAtUnixN != 0 || event.CompromisedAtUnixN == 0 {
			return keydescriptor.Descriptor{}, errors.New("keystore: compromise fields are invalid")
		}
	default:
		return keydescriptor.Descriptor{}, fmt.Errorf("keystore: unsupported key event type: %s", event.Type)
	}
	return keydescriptor.Descriptor{}, nil
}

func (r *Registry) loadEvent(index int, event model.KeyEvent) error {
	if event.Sequence != uint64(index+1) {
		return fmt.Errorf("keystore: sequence mismatch at event %d", index)
	}
	if !bytes.Equal(event.PrevEventHash, r.lastHash) {
		return fmt.Errorf("keystore: hash chain mismatch at event %d", index)
	}
	if err := verifyEvent(event, r.registryPub); err != nil {
		return fmt.Errorf("keystore: event %d signature: %w", index, err)
	}
	eventHash, err := hashEvent(event)
	if err != nil {
		return err
	}
	if !bytes.Equal(eventHash, event.EventHash) {
		return fmt.Errorf("keystore: event hash mismatch at event %d", index)
	}
	if err := r.validateNextLocked(event); err != nil {
		return fmt.Errorf("keystore: event %d lifecycle: %w", index, err)
	}
	return r.applyLocked(event)
}

func (r *Registry) applyLocked(event model.KeyEvent) error {
	descriptor, err := validateEventShape(r.manifest.CryptoSuite, event)
	if err != nil {
		return err
	}
	id := identity(event.TenantID, event.ClientID, event.KeyID)
	switch event.Type {
	case model.KeyEventRegister:
		r.byKey[id] = keyTimeline{registered: cloneEvent(event), descriptor: descriptor.Clone()}
	case model.KeyEventRotate:
		previousID := identity(event.TenantID, event.ClientID, event.PreviousKeyID)
		previous := r.byKey[previousID]
		rotated := cloneEvent(event)
		previous.rotated = &rotated
		r.byKey[previousID] = previous
		r.byKey[id] = keyTimeline{registered: cloneEvent(event), descriptor: descriptor.Clone()}
	case model.KeyEventRevoke:
		timeline := r.byKey[id]
		revoked := cloneEvent(event)
		timeline.revoked = &revoked
		r.byKey[id] = timeline
	case model.KeyEventCompromise:
		timeline := r.byKey[id]
		compromised := cloneEvent(event)
		timeline.compromised = &compromised
		r.byKey[id] = timeline
	default:
		return fmt.Errorf("keystore: unsupported key event type: %s", event.Type)
	}
	r.events = append(r.events, cloneEvent(event))
	r.lastHash = append([]byte(nil), event.EventHash...)
	return nil
}

func signEvent(event model.KeyEvent, signer trustcrypto.Signer, registryPub trustcrypto.PublicKeyDescriptor) (model.Signature, error) {
	unsigned := cloneEvent(event)
	unsigned.RegistrySignature = model.Signature{}
	unsigned.EventHash = nil
	payload, err := cborx.Marshal(unsigned)
	if err != nil {
		return model.Signature{}, err
	}
	input, err := trustcrypto.SignatureInputForSuite(event.CryptoSuite, trustcrypto.SignaturePurposeKeyEvent, payload)
	if err != nil {
		return model.Signature{}, err
	}
	signature, err := signer.Sign(context.Background(), input)
	if err != nil {
		return model.Signature{}, err
	}
	if err := trustcrypto.VerifySignatureForSuite(context.Background(), event.CryptoSuite, registryPub, input, signature); err != nil {
		return model.Signature{}, fmt.Errorf("keystore: registry signer returned unverifiable signature: %w", err)
	}
	return signature, nil
}

func verifyEvent(event model.KeyEvent, registryPub trustcrypto.PublicKeyDescriptor) error {
	signature := event.RegistrySignature
	unsigned := cloneEvent(event)
	unsigned.RegistrySignature = model.Signature{}
	unsigned.EventHash = nil
	payload, err := cborx.Marshal(unsigned)
	if err != nil {
		return err
	}
	input, err := trustcrypto.SignatureInputForSuite(event.CryptoSuite, trustcrypto.SignaturePurposeKeyEvent, payload)
	if err != nil {
		return err
	}
	return trustcrypto.VerifySignatureForSuite(context.Background(), event.CryptoSuite, registryPub, input, signature)
}

func hashEvent(event model.KeyEvent) ([]byte, error) {
	suite, err := cryptosuite.RequireKnown(event.CryptoSuite)
	if err != nil {
		return nil, err
	}
	unsignedHash := cloneEvent(event)
	unsignedHash.EventHash = nil
	payload, err := cborx.Marshal(unsignedHash)
	if err != nil {
		return nil, err
	}
	factory, err := trustcrypto.HashFactoryForSuite(event.CryptoSuite, suite.KeyEventHash.Algorithm)
	if err != nil {
		return nil, err
	}
	return factory.Sum(domainInput(suite.Domains.KeyEventHash, payload)), nil
}

func initializeRegistry(path string, manifest Manifest) error {
	if err := validateManifest(manifest); err != nil {
		return err
	}
	payload, err := cborx.Marshal(manifest)
	if err != nil {
		return err
	}
	frame, err := encodeFrame(payload)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".registry-v2-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		_ = tmp.Close()
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if err := writeAll(tmp, registryMagic); err != nil {
		return err
	}
	if err := writeAll(tmp, frame); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Link(tmpPath, path); err != nil {
		return err
	}
	if err := os.Remove(tmpPath); err != nil {
		return err
	}
	cleanup = false
	return syncRegistryDirectory(filepath.Dir(path))
}

func validateManifest(manifest Manifest) error {
	if manifest.SchemaVersion != SchemaRegistryV2 || manifest.FormatVersion != registryFormatV2 {
		return fmt.Errorf("keystore: %w: expected %s format %d", ErrUnsupportedRegistryFormat, SchemaRegistryV2, registryFormatV2)
	}
	publicKey := manifest.publicKeyDescriptor()
	if strings.TrimSpace(publicKey.KeyID) == "" {
		return errors.New("keystore: registry manifest key_id is required")
	}
	if err := trustcrypto.ValidatePublicKeyForSuite(manifest.CryptoSuite, publicKey); err != nil {
		return fmt.Errorf("keystore: invalid registry manifest public key: %w", err)
	}
	return nil
}

func readRegistry(path string) (Manifest, []model.KeyEvent, int64, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return Manifest{}, nil, 0, false, err
	}
	defer file.Close()
	magic := make([]byte, len(registryMagic))
	if _, err := io.ReadFull(file, magic); err != nil || !bytes.Equal(magic, registryMagic) {
		return Manifest{}, nil, 0, false, fmt.Errorf("keystore: %w: expected %s; V1 registries are not read or migrated", ErrUnsupportedRegistryFormat, SchemaRegistryV2)
	}
	manifestPayload, end, state, err := readFrame(file)
	if err != nil {
		return Manifest{}, nil, 0, false, err
	}
	if state != frameComplete {
		return Manifest{}, nil, 0, false, fmt.Errorf("keystore: %w: incomplete V2 manifest", ErrUnsupportedRegistryFormat)
	}
	var manifest Manifest
	if err := decodeCanonical(manifestPayload, &manifest); err != nil {
		return Manifest{}, nil, 0, false, fmt.Errorf("keystore: decode V2 manifest: %w", err)
	}
	if err := validateManifest(manifest); err != nil {
		return Manifest{}, nil, 0, false, err
	}
	events := make([]model.KeyEvent, 0)
	durableEnd := end
	for {
		payload, nextEnd, frameState, err := readFrame(file)
		if err != nil {
			return Manifest{}, nil, 0, false, err
		}
		switch frameState {
		case frameEOF:
			return manifest, events, durableEnd, false, nil
		case framePartial:
			return manifest, events, durableEnd, true, nil
		case frameComplete:
			var event model.KeyEvent
			if err := decodeCanonical(payload, &event); err != nil {
				return Manifest{}, nil, 0, false, fmt.Errorf("keystore: decode event %d: %w", len(events), err)
			}
			events = append(events, event)
			durableEnd = nextEnd
		}
	}
}

type frameReadState uint8

const (
	frameComplete frameReadState = iota
	frameEOF
	framePartial
)

func readFrame(file *os.File) ([]byte, int64, frameReadState, error) {
	start, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, 0, frameEOF, err
	}
	var header [4]byte
	n, err := io.ReadFull(file, header[:])
	if errors.Is(err, io.EOF) && n == 0 {
		return nil, start, frameEOF, nil
	}
	if err != nil {
		return nil, start, framePartial, nil
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > maxRegistryFrameSize {
		return nil, 0, frameEOF, fmt.Errorf("keystore: invalid registry frame length: %d", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(file, payload); err != nil {
		return nil, start, framePartial, nil
	}
	var trailer [4]byte
	if _, err := io.ReadFull(file, trailer[:]); err != nil {
		return nil, start, framePartial, nil
	}
	want := binary.BigEndian.Uint32(trailer[:])
	got := crc32.Checksum(payload, crcTable)
	if want != got {
		return nil, 0, frameEOF, errors.New("keystore: registry frame CRC mismatch")
	}
	end, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, 0, frameEOF, err
	}
	return payload, end, frameComplete, nil
}

func encodeFrame(payload []byte) ([]byte, error) {
	if len(payload) == 0 || len(payload) > maxRegistryFrameSize {
		return nil, fmt.Errorf("keystore: registry frame size is invalid: %d", len(payload))
	}
	frame := make([]byte, 4+len(payload)+4)
	binary.BigEndian.PutUint32(frame[:4], uint32(len(payload)))
	copy(frame[4:], payload)
	binary.BigEndian.PutUint32(frame[4+len(payload):], crc32.Checksum(payload, crcTable))
	return frame, nil
}

func decodeCanonical(payload []byte, value any) error {
	if err := cborx.UnmarshalLimit(payload, value, maxRegistryFrameSize); err != nil {
		return err
	}
	canonical, err := cborx.Marshal(value)
	if err != nil {
		return err
	}
	if !bytes.Equal(canonical, payload) {
		return errors.New("non-canonical deterministic CBOR")
	}
	return nil
}

func appendAndSync(path string, frame []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := writeAll(file, frame); err != nil {
		return err
	}
	return file.Sync()
}

func truncateAndSync(path string, size int64) error {
	file, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := file.Truncate(size); err != nil {
		return err
	}
	return file.Sync()
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
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

func unixNanoOrZero(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.UTC().UnixNano()
}

func cloneEvent(event model.KeyEvent) model.KeyEvent {
	event.KeyDescriptor = append([]byte(nil), event.KeyDescriptor...)
	event.PrevEventHash = append([]byte(nil), event.PrevEventHash...)
	event.EventHash = append([]byte(nil), event.EventHash...)
	event.RegistrySignature.Signature = append([]byte(nil), event.RegistrySignature.Signature...)
	return event
}

func cloneBytesList(values [][]byte) [][]byte {
	if values == nil {
		return nil
	}
	out := make([][]byte, len(values))
	for i := range values {
		out[i] = append([]byte(nil), values[i]...)
	}
	return out
}
