// Package sdfsigner implements TrustDB's optional SDF signer sidecar.
//
// The portable contract deliberately does not import CGO or a vendor SDK.
// Native SDF ABI differences are confined to a separately supplied adapter
// library loaded only by the build-tagged sidecar.
package sdfsigner

import (
	"context"
	"errors"
	"time"

	"github.com/wowtrust/trustdb/v2/sdk/signerplugin"
)

const (
	DefaultPluginID           = "trustdb.sdf.v1"
	DefaultMaxConcurrentSigns = 16

	MaxAdapterConfigBytes = 64 << 10
	MaxCredentialBytes    = 4096
	MaxRandomBytes        = 1 << 20
	MaxWrappedKeyBytes    = 4096
	MaxSM4OperationBytes  = 16 << 20
	SM4KeyBytes           = 16
	SM4BlockBytes         = 16

	DefaultSessionCloseTimeout = 2 * time.Second
)

// Capability is negotiated with the adapter before the signer starts. The
// values are part of the TrustDB adapter ABI and must not be reinterpreted as
// vendor SDF algorithm identifiers.
type Capability uint64

const (
	CapabilityHealth Capability = 1 << iota
	CapabilitySM2Sign
	CapabilitySM2PublicKey
	CapabilityRandom
	CapabilitySM4KEKGenerate
	CapabilitySM4KEKImport
	CapabilitySM4CBC
	CapabilitySM4MAC
)

const SigningCapabilities = CapabilityHealth |
	CapabilitySM2Sign |
	CapabilitySM2PublicKey

const SM4Capabilities = CapabilitySM4KEKGenerate |
	CapabilitySM4KEKImport |
	CapabilitySM4CBC |
	CapabilitySM4MAC

const AllCapabilities = SigningCapabilities |
	CapabilityRandom |
	SM4Capabilities

var (
	ErrInvalidConfiguration  = errors.New("invalid SDF signer configuration")
	ErrDeviceIdentityChanged = errors.New("SDF device identity changed")
	ErrKeyIdentityChanged    = errors.New("SDF key identity changed")
)

// Config binds one sidecar to one exact SDF device, credential reference, and
// KEK index. AdapterConfig is passed only to the isolated native adapter.
type Config struct {
	PluginID             string
	DeviceRef            string
	CredentialRef        string
	Credential           CredentialSource
	KEKID                string
	KEKIndex             uint32
	RequiredCapabilities Capability
	MaxConcurrentSigns   uint32
}

// DeviceIdentity is the restart-stable public identity returned by an
// adapter. DeviceID must equal Config.DeviceRef. The remaining fields are
// pinned for the sidecar lifetime so device replacement fails closed.
type DeviceIdentity struct {
	AdapterID      string `cbor:"adapter_id" json:"adapter_id"`
	AdapterVersion string `cbor:"adapter_version" json:"adapter_version"`
	DeviceID       string `cbor:"device_id" json:"device_id"`
	Serial         string `cbor:"serial" json:"serial"`
	Firmware       string `cbor:"firmware" json:"firmware"`
}

// Backend discovers one configured device. Native library loading and device
// configuration remain outside the portable fake-device contract.
type Backend interface {
	Discover(context.Context, string) (Device, error)
	Close() error
}

// Device exposes only public identity/capabilities and isolated sessions.
type Device interface {
	Identity(context.Context) (DeviceIdentity, error)
	Capabilities(context.Context) (Capability, error)
	OpenSession(context.Context) (Session, error)
}

// Session is the narrow vendor-neutral SDF contract. The adapter must perform
// SM2 over the exact 32-byte digest prepared by the sidecar, returning raw
// 32-byte r followed by 32-byte s. SM2 private keys, SM4 KEKs, and imported
// SM4 session keys are addressed only by opaque handles and cannot be exported.
type Session interface {
	Health(context.Context) error
	PublicKey(context.Context, uint32, []byte) ([]byte, error)
	SignSM2Digest(context.Context, uint32, []byte, []byte) ([]byte, error)
	Random(context.Context, uint32) ([]byte, error)
	GenerateSM4KeyWithKEK(context.Context, uint32, []byte) ([]byte, SessionKeyHandle, error)
	ImportSM4KeyWithKEK(context.Context, uint32, []byte, []byte) (SessionKeyHandle, error)
	EncryptSM4CBC(context.Context, SessionKeyHandle, []byte, []byte) ([]byte, error)
	DecryptSM4CBC(context.Context, SessionKeyHandle, []byte, []byte) ([]byte, error)
	CalculateSM4MAC(context.Context, SessionKeyHandle, []byte, []byte) ([]byte, error)
	DestroySessionKey(context.Context, SessionKeyHandle) error
	Close() error
}

// SessionKeyHandle is deliberately opaque outside this package. It is valid
// only for the native session that created it and is never serializable.
type SessionKeyHandle struct {
	value uint64
}

func newSessionKeyHandle(value uint64) SessionKeyHandle {
	return SessionKeyHandle{value: value}
}

func (h SessionKeyHandle) adapterValue() uint64 {
	return h.value
}

// WrappedSM4Key is the versioned durable representation of a generated SDF
// session key. ChecksumSM3 detects accidental corruption; it is unkeyed and
// therefore is not an authenticity control. Device KEK protection and any
// enclosing backup AEAD/MAC remain separate requirements. This object is not
// automatically included in TrustDB logical backups.
type WrappedSM4Key struct {
	SchemaVersion string         `cbor:"schema_version" json:"schema_version"`
	CryptoSuite   string         `cbor:"crypto_suite" json:"crypto_suite"`
	Algorithm     string         `cbor:"algorithm" json:"algorithm"`
	Device        DeviceIdentity `cbor:"device" json:"device"`
	KEKID         string         `cbor:"kek_id" json:"kek_id"`
	KEKIndex      uint32         `cbor:"kek_index" json:"kek_index"`
	Wrapped       []byte         `cbor:"wrapped" json:"wrapped"`
	ChecksumSM3   []byte         `cbor:"checksum_sm3" json:"checksum_sm3"`
}

// CredentialSource reads an access credential just in time. Implementations
// return a fresh mutable slice so callers can clear it immediately.
type CredentialSource interface {
	Read(context.Context) ([]byte, error)
}

type faultClass uint8

const (
	faultInvalid faultClass = iota + 1
	faultNotFound
	faultPrecondition
	faultAuthentication
	faultPermission
	faultUnsupported
	faultBusy
	faultUnavailable
	faultInternal
)

// Fault prevents raw vendor status codes, paths, device identifiers, key
// indexes, and credentials from crossing the sidecar boundary.
type Fault struct {
	class faultClass
}

func (e *Fault) Error() string {
	if e == nil {
		return ""
	}
	return "SDF provider operation failed"
}

func newFault(class faultClass) error {
	return &Fault{class: class}
}

func providerError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var fault *Fault
	if !errors.As(err, &fault) || fault == nil {
		return signerplugin.NewProviderError(signerplugin.ErrorInternal, "SDF provider operation failed")
	}
	switch fault.class {
	case faultInvalid:
		return signerplugin.NewProviderError(signerplugin.ErrorInvalidArgument, "SDF request is invalid")
	case faultNotFound:
		return signerplugin.NewProviderError(signerplugin.ErrorKeyNotFound, "SDF key was not found")
	case faultPrecondition:
		return signerplugin.NewProviderError(signerplugin.ErrorFailedPrecondition, "SDF key or device identity changed")
	case faultAuthentication:
		return signerplugin.NewProviderError(signerplugin.ErrorUnauthenticated, "SDF device authentication failed")
	case faultPermission:
		return signerplugin.NewProviderError(signerplugin.ErrorPermissionDenied, "SDF device denied the operation")
	case faultUnsupported:
		return signerplugin.NewProviderError(signerplugin.ErrorUnsupported, "SDF capability is unsupported")
	case faultBusy:
		return signerplugin.NewProviderError(signerplugin.ErrorBusy, "SDF device is busy")
	case faultUnavailable:
		return signerplugin.NewProviderError(signerplugin.ErrorUnavailable, "SDF device is unavailable")
	default:
		return signerplugin.NewProviderError(signerplugin.ErrorInternal, "SDF provider operation failed")
	}
}
