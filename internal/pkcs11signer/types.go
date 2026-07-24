// Package pkcs11signer implements the provider side of TrustDB's supervised
// signer-plugin protocol for PKCS#11 tokens. The portable package contains no
// native dependency; the Cryptoki adapter is compiled only with the pkcs11
// build tag.
package pkcs11signer

import (
	"context"
	"errors"
	"fmt"

	"github.com/wowtrust/trustdb/sdk/signerplugin"
)

const (
	DefaultPluginID           = "trustdb.pkcs11.v1"
	DefaultMaxConcurrentSigns = 16

	SignatureFormatRaw = "raw"
	SignatureFormatDER = "der"

	// MechanismFlagSign is CKF_SIGN from the PKCS#11 specification. Keeping
	// this value in the portable contract lets fake-token tests exercise the
	// startup capability gate without importing a native binding.
	MechanismFlagSign uint = 0x00000800
)

var (
	ErrInvalidConfiguration = errors.New("invalid PKCS#11 signer configuration")
	ErrTokenIdentityChanged = errors.New("PKCS#11 token identity changed")
	ErrKeyIdentityChanged   = errors.New("PKCS#11 key identity changed")
)

// Config binds one plugin process to one token and an explicit set of
// immutable TrustDB suite/mechanism profiles. TokenURI identifies a token,
// not a key. Key object selection remains in each descriptor-provided URI.
type Config struct {
	PluginID           string
	TokenURI           string
	Profiles           []Profile
	MaxConcurrentSigns uint32
	PIN                PINSource
}

// Profile maps one immutable TrustDB signature profile to one explicitly
// configured Cryptoki mechanism. Parameter is passed through byte-for-byte
// for vendor mechanisms and is never inferred from a token or key.
type Profile struct {
	CryptoSuite     string
	Mechanism       uint
	Parameter       []byte
	SignatureFormat string
}

func (p Profile) clone() Profile {
	p.Parameter = append([]byte(nil), p.Parameter...)
	return p
}

func (p Profile) capability() (signerplugin.AlgorithmCapability, error) {
	switch p.CryptoSuite {
	case signerplugin.SuiteINTLV1:
		if p.Mechanism == 0 || p.SignatureFormat != SignatureFormatRaw || len(p.Parameter) != 0 {
			return signerplugin.AlgorithmCapability{}, fmt.Errorf("%w: INTL_V1 requires a non-zero mechanism, raw output, and no mechanism parameter", ErrInvalidConfiguration)
		}
		return signerplugin.AlgorithmCapability{
			CryptoSuite:       signerplugin.SuiteINTLV1,
			Algorithm:         signerplugin.AlgorithmEd25519,
			PublicKeyEncoding: signerplugin.Ed25519PublicKeyEncoding,
			SignatureEncoding: signerplugin.Ed25519SignatureEncoding,
		}, nil
	case signerplugin.SuiteCNSMV1, signerplugin.SuiteFISCOBCOSGuomi:
		if p.Mechanism == 0 || (p.SignatureFormat != SignatureFormatRaw && p.SignatureFormat != SignatureFormatDER) {
			return signerplugin.AlgorithmCapability{}, fmt.Errorf("%w: CN_SM_V1 requires a non-zero mechanism and explicit raw or DER output", ErrInvalidConfiguration)
		}
		return signerplugin.AlgorithmCapability{
			CryptoSuite:       p.CryptoSuite,
			Algorithm:         signerplugin.AlgorithmSM2SM3,
			PublicKeyEncoding: signerplugin.SM2PublicKeyEncoding,
			SignatureEncoding: signerplugin.SM2SignatureEncoding,
			SM2UserID:         signerplugin.SM2DefaultUserID,
		}, nil
	default:
		return signerplugin.AlgorithmCapability{}, fmt.Errorf("%w: unsupported crypto suite", ErrInvalidConfiguration)
	}
}

// Mechanism is the minimum token capability needed by the portable provider.
type Mechanism struct {
	Type  uint
	Flags uint
}

// TokenIdentity is captured on startup and compared on every later operation.
// This prevents a replacement token from silently assuming an existing key
// URI after removal or restart.
type TokenIdentity struct {
	Label        string
	Manufacturer string
	Model        string
	Serial       string
}

// ObjectHandle is deliberately opaque outside this package. The provider
// contract contains no operation for reading private-key attributes.
type ObjectHandle struct {
	value uint64
}

func newObjectHandle(value uint64) ObjectHandle {
	return ObjectHandle{value: value}
}

// KeyMaterial contains only public material plus an opaque private handle.
// ECPoint is the token's CKA_EC_POINT representation, PublicValue supports
// modules that expose Ed25519 bytes through CKA_VALUE, and CertificateDER is
// the matching X.509 object when present.
type KeyMaterial struct {
	Private        ObjectHandle
	ECPoint        []byte
	PublicValue    []byte
	CertificateDER []byte
}

func (m KeyMaterial) clone() KeyMaterial {
	m.ECPoint = append([]byte(nil), m.ECPoint...)
	m.PublicValue = append([]byte(nil), m.PublicValue...)
	m.CertificateDER = append([]byte(nil), m.CertificateDER...)
	return m
}

// Backend discovers one configured token. Native module loading is outside
// the portable fake-token contract.
type Backend interface {
	Discover(context.Context, TokenSelector) (Token, error)
	Close() error
}

// Token exposes identity, mechanisms, and isolated sessions only.
type Token interface {
	Identity() TokenIdentity
	Mechanisms(context.Context) ([]Mechanism, error)
	OpenSession(context.Context) (Session, error)
}

// Session exposes login, exact object lookup, and signing. In particular, it
// has no private-key export or private-attribute operation.
type Session interface {
	Login(context.Context, []byte) error
	Lookup(context.Context, ObjectSelector) (KeyMaterial, error)
	Sign(context.Context, ObjectHandle, Profile, []byte) ([]byte, error)
	Close() error
}

// PINSource loads a PIN just in time for login. Implementations must return a
// fresh byte slice so the caller can clear it immediately after use.
type PINSource interface {
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

// Fault classifies backend failures without allowing native diagnostics,
// handles, URIs, PINs, or module paths to cross the plugin boundary.
type Fault struct {
	class faultClass
}

func (e *Fault) Error() string {
	if e == nil {
		return ""
	}
	return "PKCS#11 provider operation failed"
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
		return signerplugin.NewProviderError(signerplugin.ErrorInternal, "PKCS#11 provider operation failed")
	}
	switch fault.class {
	case faultInvalid:
		return signerplugin.NewProviderError(signerplugin.ErrorInvalidArgument, "PKCS#11 request is invalid")
	case faultNotFound:
		return signerplugin.NewProviderError(signerplugin.ErrorKeyNotFound, "PKCS#11 key was not found")
	case faultPrecondition:
		return signerplugin.NewProviderError(signerplugin.ErrorFailedPrecondition, "PKCS#11 key or token identity changed")
	case faultAuthentication:
		return signerplugin.NewProviderError(signerplugin.ErrorUnauthenticated, "PKCS#11 token login failed")
	case faultPermission:
		return signerplugin.NewProviderError(signerplugin.ErrorPermissionDenied, "PKCS#11 token denied the operation")
	case faultUnsupported:
		return signerplugin.NewProviderError(signerplugin.ErrorUnsupported, "PKCS#11 mechanism is unsupported")
	case faultBusy:
		return signerplugin.NewProviderError(signerplugin.ErrorBusy, "PKCS#11 token is busy")
	case faultUnavailable:
		return signerplugin.NewProviderError(signerplugin.ErrorUnavailable, "PKCS#11 token is unavailable")
	default:
		return signerplugin.NewProviderError(signerplugin.ErrorInternal, "PKCS#11 provider operation failed")
	}
}
