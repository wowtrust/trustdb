package sdfsigner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"

	"github.com/emmansun/gmsm/sm3"

	"github.com/wowtrust/trustdb/v2/internal/cborx"
	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/keydescriptor"
	"github.com/wowtrust/trustdb/v2/sdk/signerplugin"
)

const (
	RecoveryBundleSchemaV1 = "trustdb.sdf-recovery-bundle.v1"

	MaxRecoveryBundleBytes       = 16 << 20
	MaxRecoverySignerDescriptors = 128
	MaxRecoveryWrappedSM4Keys    = 1024

	maxRecoveryDescriptorBytes = 2 << 20
	recoveryChecksumBytes      = 32
)

var (
	ErrInvalidRecoveryBundle      = errors.New("invalid SDF recovery bundle")
	ErrNonCanonicalRecoveryBundle = errors.New("non-canonical SDF recovery bundle")
)

// RecoveryBundle is the provider-owned, non-secret recovery inventory.
// SignerDescriptors and WrappedSM4Keys contain their complete canonical CBOR
// objects. ChecksumSM3 detects accidental corruption only; backup v5 must
// authenticate and encrypt this complete artifact before off-host storage.
type RecoveryBundle struct {
	SchemaVersion     string         `cbor:"schema_version"`
	Device            DeviceIdentity `cbor:"device"`
	SignerDescriptors [][]byte       `cbor:"signer_descriptors"`
	WrappedSM4Keys    [][]byte       `cbor:"wrapped_sm4_keys"`
	ChecksumSM3       []byte         `cbor:"checksum_sm3"`
}

type recoveryBundlePayload struct {
	SchemaVersion     string         `cbor:"schema_version"`
	Device            DeviceIdentity `cbor:"device"`
	SignerDescriptors [][]byte       `cbor:"signer_descriptors"`
	WrappedSM4Keys    [][]byte       `cbor:"wrapped_sm4_keys"`
}

// RestoredRecoveryBundle contains validated, detached provider references.
// RestoreRecoveryBundle has already rebound every signer descriptor to the
// live device/public key and tested every wrapped key against the live KEK.
type RestoredRecoveryBundle struct {
	SignerDescriptors []keydescriptor.Descriptor
	WrappedSM4Keys    []WrappedSM4Key
}

// ExportRecoveryBundle creates one deterministic provider recovery artifact
// after rebinding every supplied reference to this live device. It contains no
// credential value, private key, plaintext SM4 key, adapter configuration,
// native path, or opaque same-session handle.
func (p *Plugin) ExportRecoveryBundle(
	ctx context.Context,
	descriptors []keydescriptor.Descriptor,
	wrappedKeys []WrappedSM4Key,
) ([]byte, error) {
	if p == nil {
		return nil, providerError(newFault(faultUnavailable))
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	closed := p.closed
	device := p.identity
	config := p.config
	info := p.info
	required := p.required
	p.mu.Unlock()
	if closed {
		return nil, providerError(newFault(faultUnavailable))
	}
	if len(descriptors) == 0 || len(descriptors) > MaxRecoverySignerDescriptors ||
		len(wrappedKeys) > MaxRecoveryWrappedSM4Keys {
		return nil, recoveryError("inventory count is invalid")
	}
	for _, descriptor := range descriptors {
		if !validRecoveryDescriptor(descriptor, device) ||
			descriptor.SDF.DeviceRef != config.DeviceRef ||
			descriptor.SDF.CredentialRef != config.CredentialRef {
			return nil, recoveryError("signer reference does not match")
		}
		key := recoveryPluginKey(descriptor, info.PluginID)
		keyIndex, _, err := p.validateKey(key)
		if err != nil {
			return nil, recoveryError("signer reference is invalid")
		}
		publicKey, err := p.readPublicKey(ctx, keyIndex)
		if err != nil {
			return nil, providerError(err)
		}
		if !bytes.Equal(publicKey, descriptor.PublicKey.Bytes) {
			return nil, recoveryError("signer public key does not match")
		}
	}
	if len(wrappedKeys) != 0 {
		if required&SM4Capabilities != SM4Capabilities {
			return nil, recoveryError("SM4 KEK capability is unavailable")
		}
		for _, wrapped := range wrappedKeys {
			if err := wrapped.Validate(); err != nil ||
				wrapped.Device != device ||
				wrapped.KEKID != config.KEKID ||
				wrapped.KEKIndex != config.KEKIndex {
				return nil, recoveryError("wrapped key binding does not match")
			}
		}
	}

	bundle := RecoveryBundle{
		SchemaVersion:     RecoveryBundleSchemaV1,
		Device:            device,
		SignerDescriptors: make([][]byte, 0, len(descriptors)),
		WrappedSM4Keys:    make([][]byte, 0, len(wrappedKeys)),
	}
	totalBytes := 0
	for _, descriptor := range descriptors {
		if !validRecoveryDescriptor(descriptor, device) {
			return nil, recoveryError("signer descriptor is invalid")
		}
		encoded, err := keydescriptor.Marshal(descriptor)
		if err != nil || len(encoded) == 0 || len(encoded) > maxRecoveryDescriptorBytes {
			return nil, recoveryError("signer descriptor cannot be encoded")
		}
		if totalBytes > MaxRecoveryBundleBytes-len(encoded) {
			return nil, recoveryError("inventory is too large")
		}
		totalBytes += len(encoded)
		bundle.SignerDescriptors = append(bundle.SignerDescriptors, encoded)
	}
	for _, wrapped := range wrappedKeys {
		if err := wrapped.Validate(); err != nil || wrapped.Device != device {
			return nil, recoveryError("wrapped key is invalid")
		}
		encoded, err := MarshalWrappedSM4Key(wrapped)
		if err != nil {
			return nil, recoveryError("wrapped key cannot be encoded")
		}
		if totalBytes > MaxRecoveryBundleBytes-len(encoded) {
			return nil, recoveryError("inventory is too large")
		}
		totalBytes += len(encoded)
		bundle.WrappedSM4Keys = append(bundle.WrappedSM4Keys, encoded)
	}
	sort.Slice(bundle.SignerDescriptors, func(i, j int) bool {
		return bytes.Compare(bundle.SignerDescriptors[i], bundle.SignerDescriptors[j]) < 0
	})
	sort.Slice(bundle.WrappedSM4Keys, func(i, j int) bool {
		return bytes.Compare(bundle.WrappedSM4Keys[i], bundle.WrappedSM4Keys[j]) < 0
	})
	if err := validateRecoveryInventory(bundle); err != nil {
		return nil, err
	}
	checksum, err := bundle.calculateChecksum()
	if err != nil {
		return nil, err
	}
	bundle.ChecksumSM3 = checksum
	encoded, err := cborx.Marshal(bundle)
	if err != nil {
		return nil, recoveryError("bundle cannot be encoded")
	}
	if len(encoded) == 0 || len(encoded) > MaxRecoveryBundleBytes {
		return nil, recoveryError("encoded bundle length is invalid")
	}
	return encoded, nil
}

// RestoreRecoveryBundle strictly decodes a provider recovery artifact and
// rebinds it to this plugin's live device, credential identity, public keys,
// and KEK. It never persists or publishes a partially restored inventory.
func (p *Plugin) RestoreRecoveryBundle(ctx context.Context, encoded []byte) (RestoredRecoveryBundle, error) {
	if p == nil {
		return RestoredRecoveryBundle{}, providerError(newFault(faultUnavailable))
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return RestoredRecoveryBundle{}, err
	}
	bundle, descriptors, wrappedKeys, err := decodeRecoveryBundle(encoded)
	if err != nil {
		return RestoredRecoveryBundle{}, err
	}

	p.mu.Lock()
	closed := p.closed
	identity := p.identity
	config := p.config
	info := p.info
	required := p.required
	p.mu.Unlock()
	if closed {
		return RestoredRecoveryBundle{}, providerError(newFault(faultUnavailable))
	}
	if bundle.Device != identity || bundle.Device.DeviceID != config.DeviceRef {
		return RestoredRecoveryBundle{}, recoveryError("device identity does not match")
	}
	for _, descriptor := range descriptors {
		if descriptor.SDF == nil ||
			descriptor.SDF.DeviceRef != config.DeviceRef ||
			descriptor.SDF.CredentialRef != config.CredentialRef {
			return RestoredRecoveryBundle{}, recoveryError("signer reference does not match")
		}
	}
	if len(wrappedKeys) != 0 {
		if required&SM4Capabilities != SM4Capabilities {
			return RestoredRecoveryBundle{}, recoveryError("SM4 KEK capability is unavailable")
		}
		for _, wrapped := range wrappedKeys {
			if wrapped.Device != identity ||
				wrapped.KEKID != config.KEKID ||
				wrapped.KEKIndex != config.KEKIndex {
				return RestoredRecoveryBundle{}, recoveryError("wrapped key binding does not match")
			}
		}
	}

	type recoveredPublicKey struct {
		cacheKey string
		bytes    []byte
	}
	recoveredPublicKeys := make([]recoveredPublicKey, 0, len(descriptors))
	for _, descriptor := range descriptors {
		key := recoveryPluginKey(descriptor, info.PluginID)
		keyIndex, cacheKey, err := p.validateKey(key)
		if err != nil {
			return RestoredRecoveryBundle{}, recoveryError("signer reference is invalid")
		}
		publicKey, err := p.readPublicKey(ctx, keyIndex)
		if err != nil {
			return RestoredRecoveryBundle{}, providerError(err)
		}
		if !bytes.Equal(publicKey, descriptor.PublicKey.Bytes) {
			return RestoredRecoveryBundle{}, recoveryError("signer public key does not match")
		}
		recoveredPublicKeys = append(recoveredPublicKeys, recoveredPublicKey{
			cacheKey: cacheKey,
			bytes:    publicKey,
		})
	}
	for _, wrapped := range wrappedKeys {
		session, err := p.ImportSM4Session(ctx, wrapped)
		if err != nil {
			return RestoredRecoveryBundle{}, err
		}
		if err := session.CloseContext(ctx); err != nil {
			return RestoredRecoveryBundle{}, err
		}
	}
	acceptances := make([]publicKeyAcceptance, len(recoveredPublicKeys))
	for i := range recoveredPublicKeys {
		acceptances[i] = publicKeyAcceptance{
			cacheKey: recoveredPublicKeys[i].cacheKey,
			bytes:    recoveredPublicKeys[i].bytes,
		}
	}
	if err := p.acceptPublicKeysAtomically(acceptances); err != nil {
		return RestoredRecoveryBundle{}, providerError(err)
	}
	return RestoredRecoveryBundle{
		SignerDescriptors: cloneRecoveryDescriptors(descriptors),
		WrappedSM4Keys:    cloneRecoveryWrappedKeys(wrappedKeys),
	}, nil
}

func decodeRecoveryBundle(encoded []byte) (RecoveryBundle, []keydescriptor.Descriptor, []WrappedSM4Key, error) {
	if len(encoded) == 0 || len(encoded) > MaxRecoveryBundleBytes {
		return RecoveryBundle{}, nil, nil, recoveryError("encoded bundle length is invalid")
	}
	var bundle RecoveryBundle
	if err := cborx.UnmarshalLimits(
		encoded,
		&bundle,
		MaxRecoveryBundleBytes,
		MaxRecoveryWrappedSM4Keys,
		16,
	); err != nil {
		return RecoveryBundle{}, nil, nil, recoveryError("bundle cannot be decoded")
	}
	if bundle.SchemaVersion != RecoveryBundleSchemaV1 ||
		len(bundle.ChecksumSM3) != recoveryChecksumBytes {
		return RecoveryBundle{}, nil, nil, recoveryError("schema or checksum is invalid")
	}
	if err := validateIdentity(bundle.Device); err != nil {
		return RecoveryBundle{}, nil, nil, recoveryError("device identity is invalid")
	}
	if err := validateRecoveryInventory(bundle); err != nil {
		return RecoveryBundle{}, nil, nil, err
	}
	checksum, err := bundle.calculateChecksum()
	if err != nil {
		return RecoveryBundle{}, nil, nil, err
	}
	if !bytes.Equal(checksum, bundle.ChecksumSM3) {
		return RecoveryBundle{}, nil, nil, recoveryError("checksum does not match")
	}
	canonical, err := cborx.Marshal(bundle)
	if err != nil {
		return RecoveryBundle{}, nil, nil, recoveryError("bundle cannot be re-encoded")
	}
	if !bytes.Equal(canonical, encoded) {
		return RecoveryBundle{}, nil, nil, ErrNonCanonicalRecoveryBundle
	}

	descriptors := make([]keydescriptor.Descriptor, 0, len(bundle.SignerDescriptors))
	for _, encodedDescriptor := range bundle.SignerDescriptors {
		descriptor, err := keydescriptor.Unmarshal(encodedDescriptor)
		if err != nil || !validRecoveryDescriptor(descriptor, bundle.Device) {
			return RecoveryBundle{}, nil, nil, recoveryError("signer descriptor is invalid")
		}
		descriptors = append(descriptors, descriptor)
	}
	wrappedKeys := make([]WrappedSM4Key, 0, len(bundle.WrappedSM4Keys))
	for _, encodedWrapped := range bundle.WrappedSM4Keys {
		wrapped, err := UnmarshalWrappedSM4Key(encodedWrapped)
		if err != nil || wrapped.Device != bundle.Device {
			return RecoveryBundle{}, nil, nil, recoveryError("wrapped key is invalid")
		}
		wrappedKeys = append(wrappedKeys, wrapped)
	}
	bundle.SignerDescriptors = cloneBytesList(bundle.SignerDescriptors)
	bundle.WrappedSM4Keys = cloneBytesList(bundle.WrappedSM4Keys)
	bundle.ChecksumSM3 = append([]byte(nil), bundle.ChecksumSM3...)
	return bundle, descriptors, wrappedKeys, nil
}

func validateRecoveryInventory(bundle RecoveryBundle) error {
	if len(bundle.SignerDescriptors) == 0 ||
		len(bundle.SignerDescriptors) > MaxRecoverySignerDescriptors ||
		len(bundle.WrappedSM4Keys) > MaxRecoveryWrappedSM4Keys {
		return recoveryError("inventory count is invalid")
	}
	if !strictlySortedByteSlices(bundle.SignerDescriptors) ||
		!strictlySortedByteSlices(bundle.WrappedSM4Keys) {
		return recoveryError("inventory order or uniqueness is invalid")
	}
	keyIDs := make(map[string]struct{}, len(bundle.SignerDescriptors))
	handles := make(map[string]struct{}, len(bundle.SignerDescriptors))
	for _, encoded := range bundle.SignerDescriptors {
		if len(encoded) == 0 || len(encoded) > maxRecoveryDescriptorBytes {
			return recoveryError("signer descriptor length is invalid")
		}
		descriptor, err := keydescriptor.Unmarshal(encoded)
		if err != nil || !validRecoveryDescriptor(descriptor, bundle.Device) {
			return recoveryError("signer descriptor is invalid")
		}
		if _, exists := keyIDs[descriptor.KeyID]; exists {
			return recoveryError("signer descriptor identity is duplicated")
		}
		keyIDs[descriptor.KeyID] = struct{}{}
		handle := descriptor.SDF.DeviceRef + "\x00" +
			strconv.FormatUint(uint64(descriptor.SDF.KeyIndex), 10) + "\x00" +
			descriptor.SDF.CredentialRef
		if _, exists := handles[handle]; exists {
			return recoveryError("signer provider handle is duplicated")
		}
		handles[handle] = struct{}{}
	}
	for _, encoded := range bundle.WrappedSM4Keys {
		if len(encoded) == 0 || len(encoded) > maxWrappedSM4Envelope {
			return recoveryError("wrapped key length is invalid")
		}
		wrapped, err := UnmarshalWrappedSM4Key(encoded)
		if err != nil || wrapped.Device != bundle.Device {
			return recoveryError("wrapped key is invalid")
		}
	}
	return nil
}

func validRecoveryDescriptor(descriptor keydescriptor.Descriptor, device DeviceIdentity) bool {
	return descriptor.Validate() == nil &&
		descriptor.SchemaVersion == keydescriptor.SchemaV1 &&
		descriptor.Kind == keydescriptor.KindSigner &&
		descriptor.Provider == keydescriptor.ProviderSDF &&
		descriptor.CryptoSuite == cryptosuite.CNSMV1 &&
		descriptor.Algorithm == cryptosuite.SignatureSM2SM3 &&
		descriptor.SM2UserID == cryptosuite.SM2DefaultUserID &&
		descriptor.SDF != nil &&
		descriptor.SDF.DeviceRef == device.DeviceID &&
		descriptor.SDF.KeyIndex != 0
}

func recoveryPluginKey(descriptor keydescriptor.Descriptor, pluginID string) signerplugin.Key {
	return signerplugin.Key{
		Binding: signerplugin.Binding{
			ProtocolVersion:   signerplugin.ProtocolVersion,
			PluginID:          pluginID,
			ProviderKind:      signerplugin.ProviderSDF,
			CryptoSuite:       signerplugin.SuiteCNSMV1,
			Algorithm:         signerplugin.AlgorithmSM2SM3,
			PublicKeyEncoding: signerplugin.SM2PublicKeyEncoding,
			SignatureEncoding: signerplugin.SM2SignatureEncoding,
			KeyID:             descriptor.KeyID,
			SM2UserID:         signerplugin.SM2DefaultUserID,
		},
		Reference: signerplugin.KeyReference{
			SDF: &signerplugin.SDFKeyReference{
				DeviceRef:     descriptor.SDF.DeviceRef,
				KeyIndex:      descriptor.SDF.KeyIndex,
				CredentialRef: descriptor.SDF.CredentialRef,
			},
		},
	}
}

func (bundle RecoveryBundle) calculateChecksum() ([]byte, error) {
	payload := recoveryBundlePayload{
		SchemaVersion:     bundle.SchemaVersion,
		Device:            bundle.Device,
		SignerDescriptors: bundle.SignerDescriptors,
		WrappedSM4Keys:    bundle.WrappedSM4Keys,
	}
	encoded, err := cborx.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: checksum payload cannot be encoded", ErrInvalidRecoveryBundle)
	}
	digest := sm3.Sum(encoded)
	return append([]byte(nil), digest[:]...), nil
}

func strictlySortedByteSlices(values [][]byte) bool {
	for i := 1; i < len(values); i++ {
		if bytes.Compare(values[i-1], values[i]) >= 0 {
			return false
		}
	}
	return true
}

func cloneRecoveryDescriptors(values []keydescriptor.Descriptor) []keydescriptor.Descriptor {
	cloned := make([]keydescriptor.Descriptor, len(values))
	for i := range values {
		cloned[i] = values[i].Clone()
	}
	return cloned
}

func cloneRecoveryWrappedKeys(values []WrappedSM4Key) []WrappedSM4Key {
	cloned := make([]WrappedSM4Key, len(values))
	for i := range values {
		cloned[i] = values[i].Clone()
	}
	return cloned
}

func cloneBytesList(values [][]byte) [][]byte {
	cloned := make([][]byte, len(values))
	for i := range values {
		cloned[i] = append([]byte(nil), values[i]...)
	}
	return cloned
}

func recoveryError(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalidRecoveryBundle, message)
}
