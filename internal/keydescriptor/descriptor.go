// Package keydescriptor defines the canonical, versioned configuration
// boundary between TrustDB core and software, remote, PKCS#11, or SDF keys.
package keydescriptor

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/formatregistry"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
)

const (
	SchemaV1 = "trustdb.key-descriptor.v1"

	KindSigner   = "signer"
	KindVerifier = "verifier"

	ProviderSoftware = "software"
	ProviderPublic   = "public"
	ProviderPKCS11   = "pkcs11"
	ProviderSDF      = "sdf"
	ProviderRemote   = "remote"

	SoftwareProtectionPlaintextDev = "plaintext-dev-v1"
	SoftwareProtectionSM4Envelope  = "sm4-envelope-v1"

	maxDescriptorBytes = 2 << 20
	maxStringBytes     = 4096
)

var (
	ErrInvalidDescriptor   = errors.New("invalid key descriptor")
	ErrNonCanonical        = errors.New("non-canonical key descriptor")
	ErrUnsupportedProvider = errors.New("unsupported key provider")
)

type Descriptor struct {
	SchemaVersion    string                `cbor:"schema_version" json:"schema_version"`
	Kind             string                `cbor:"kind" json:"kind"`
	Provider         string                `cbor:"provider" json:"provider"`
	CryptoSuite      cryptosuite.ID        `cbor:"crypto_suite" json:"crypto_suite"`
	KeyID            string                `cbor:"key_id" json:"key_id"`
	Algorithm        string                `cbor:"algorithm" json:"algorithm"`
	SM2UserID        string                `cbor:"sm2_user_id,omitempty" json:"sm2_user_id,omitempty"`
	PublicKey        PublicKeyMaterial     `cbor:"public_key" json:"public_key"`
	CertificateChain [][]byte              `cbor:"certificate_chain,omitempty" json:"certificate_chain,omitempty"`
	Software         *SoftwareKeyReference `cbor:"software,omitempty" json:"software,omitempty"`
	PKCS11           *PKCS11KeyReference   `cbor:"pkcs11,omitempty" json:"pkcs11,omitempty"`
	SDF              *SDFKeyReference      `cbor:"sdf,omitempty" json:"sdf,omitempty"`
	Remote           *RemoteKeyReference   `cbor:"remote,omitempty" json:"remote,omitempty"`
}

type PublicKeyMaterial struct {
	Encoding string `cbor:"encoding" json:"encoding"`
	Bytes    []byte `cbor:"bytes" json:"bytes"`
}

type SoftwareKeyReference struct {
	MaterialPath string `cbor:"material_path" json:"material_path"`
	Encoding     string `cbor:"encoding" json:"encoding"`
	Protection   string `cbor:"protection" json:"protection"`
}

type PKCS11KeyReference struct {
	URI string `cbor:"uri" json:"uri"`
}

type SDFKeyReference struct {
	DeviceRef     string `cbor:"device_ref" json:"device_ref"`
	KeyIndex      uint32 `cbor:"key_index" json:"key_index"`
	CredentialRef string `cbor:"credential_ref,omitempty" json:"credential_ref,omitempty"`
}

type RemoteKeyReference struct {
	Endpoint      string `cbor:"endpoint" json:"endpoint"`
	Handle        string `cbor:"handle" json:"handle"`
	CredentialRef string `cbor:"credential_ref" json:"credential_ref"`
}

type CertificateMetadata struct {
	Index          int    `json:"index"`
	SerialNumber   string `json:"serial_number"`
	Subject        string `json:"subject"`
	Issuer         string `json:"issuer"`
	NotBeforeUnixN int64  `json:"not_before_unix_nano"`
	NotAfterUnixN  int64  `json:"not_after_unix_nano"`
	IsCA           bool   `json:"is_ca"`
	SignatureAlg   string `json:"signature_algorithm"`
}

func (d Descriptor) Clone() Descriptor {
	d.PublicKey.Bytes = append([]byte(nil), d.PublicKey.Bytes...)
	d.CertificateChain = cloneBytesList(d.CertificateChain)
	if d.Software != nil {
		value := *d.Software
		d.Software = &value
	}
	if d.PKCS11 != nil {
		value := *d.PKCS11
		d.PKCS11 = &value
	}
	if d.SDF != nil {
		value := *d.SDF
		d.SDF = &value
	}
	if d.Remote != nil {
		value := *d.Remote
		d.Remote = &value
	}
	return d
}

func (d Descriptor) PublicKeyDescriptor() (trustcrypto.PublicKeyDescriptor, error) {
	if err := d.Validate(); err != nil {
		return trustcrypto.PublicKeyDescriptor{}, err
	}
	return trustcrypto.PublicKeyDescriptor{
		Suite: d.CryptoSuite, KeyID: d.KeyID, Algorithm: d.Algorithm,
		Encoding: d.PublicKey.Encoding, Bytes: append([]byte(nil), d.PublicKey.Bytes...),
	}, nil
}

// CertificateMetadata returns validated, non-secret certificate inventory
// suitable for operator inspection and registry validity enforcement.
func (d Descriptor) CertificateMetadata() ([]CertificateMetadata, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	metadata := make([]CertificateMetadata, len(d.CertificateChain))
	for i, der := range d.CertificateChain {
		certificate, err := smx509.ParseCertificate(der)
		if err != nil {
			return nil, invalid("certificate %d is invalid DER", i)
		}
		metadata[i] = CertificateMetadata{
			Index:          i,
			SerialNumber:   certificate.SerialNumber.String(),
			Subject:        certificate.Subject.String(),
			Issuer:         certificate.Issuer.String(),
			NotBeforeUnixN: certificate.NotBefore.UTC().UnixNano(),
			NotAfterUnixN:  certificate.NotAfter.UTC().UnixNano(),
			IsCA:           certificate.IsCA,
			SignatureAlg:   certificate.SignatureAlgorithm.String(),
		}
	}
	return metadata, nil
}

func (d Descriptor) Validate() error {
	if d.SchemaVersion != SchemaV1 {
		return invalid("schema_version must be %q", SchemaV1)
	}
	if d.Kind != KindSigner && d.Kind != KindVerifier {
		return invalid("kind %q is unsupported", d.Kind)
	}
	if !validIdentifier(d.KeyID, 256) {
		return invalid("key_id is empty, non-canonical, or too long")
	}
	suite, err := cryptosuite.RequireKnown(d.CryptoSuite)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidDescriptor, err)
	}
	if d.Algorithm != suite.Signature.Algorithm {
		return invalid("algorithm %q does not match suite %s", d.Algorithm, suite.ID)
	}
	if d.PublicKey.Encoding != suite.Signature.PublicKeyEncoding {
		return invalid("public key encoding %q does not match suite %s", d.PublicKey.Encoding, suite.ID)
	}
	publicKey := trustcrypto.PublicKeyDescriptor{
		Suite: d.CryptoSuite, KeyID: d.KeyID, Algorithm: d.Algorithm,
		Encoding: d.PublicKey.Encoding, Bytes: d.PublicKey.Bytes,
	}
	if err := trustcrypto.ValidatePublicKeyForSuite(d.CryptoSuite, publicKey); err != nil {
		return fmt.Errorf("%w: public key: %v", ErrInvalidDescriptor, err)
	}
	if suite.ID == cryptosuite.CNSMV1 {
		if d.SM2UserID != suite.Signature.SM2UserID {
			return invalid("sm2_user_id must be the suite-defined value")
		}
	} else if d.SM2UserID != "" {
		return invalid("sm2_user_id must be empty for suite %s", suite.ID)
	}
	if err := validateProviderUnion(d, suite); err != nil {
		return err
	}
	if err := validateCertificateChain(d, suite); err != nil {
		return err
	}
	return nil
}

func Marshal(d Descriptor) ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	data, err := cborx.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("marshal key descriptor: %w", err)
	}
	if len(data) > maxDescriptorBytes {
		return nil, invalid("encoded descriptor is too large")
	}
	return data, nil
}

func Unmarshal(data []byte) (Descriptor, error) {
	if len(data) > maxDescriptorBytes {
		return Descriptor{}, invalid("encoded descriptor is too large")
	}
	var descriptor Descriptor
	if err := cborx.UnmarshalLimit(data, &descriptor, maxDescriptorBytes); err != nil {
		return Descriptor{}, fmt.Errorf("%w: %v", ErrInvalidDescriptor, err)
	}
	if err := descriptor.Validate(); err != nil {
		return Descriptor{}, err
	}
	canonical, err := cborx.Marshal(descriptor)
	if err != nil {
		return Descriptor{}, fmt.Errorf("%w: re-encode: %v", ErrInvalidDescriptor, err)
	}
	if !bytes.Equal(canonical, data) {
		return Descriptor{}, ErrNonCanonical
	}
	return descriptor.Clone(), nil
}

func (d Descriptor) Redacted() Descriptor {
	redacted := d.Clone()
	if redacted.Software != nil && redacted.Software.MaterialPath != "" {
		redacted.Software.MaterialPath = "<redacted>"
	}
	if redacted.PKCS11 != nil && redacted.PKCS11.URI != "" {
		redacted.PKCS11.URI = "pkcs11:<redacted>"
	}
	if redacted.SDF != nil {
		if redacted.SDF.DeviceRef != "" {
			redacted.SDF.DeviceRef = "<redacted>"
		}
		if redacted.SDF.CredentialRef != "" {
			redacted.SDF.CredentialRef = "<redacted>"
		}
	}
	if redacted.Remote != nil {
		if redacted.Remote.Endpoint != "" {
			redacted.Remote.Endpoint = "<redacted>"
		}
		if redacted.Remote.Handle != "" {
			redacted.Remote.Handle = "<redacted>"
		}
		if redacted.Remote.CredentialRef != "" {
			redacted.Remote.CredentialRef = "<redacted>"
		}
	}
	return redacted
}

func (d Descriptor) String() string {
	redacted := d.Redacted()
	type plain Descriptor
	data, err := json.Marshal(plain(redacted))
	if err != nil {
		return `{"schema_version":"<invalid>"}`
	}
	return string(data)
}

func (d Descriptor) MarshalJSON() ([]byte, error) {
	redacted := d.Redacted()
	type plain Descriptor
	return json.Marshal(plain(redacted))
}

func validateProviderUnion(d Descriptor, suite cryptosuite.Suite) error {
	references := 0
	for _, present := range []bool{d.Software != nil, d.PKCS11 != nil, d.SDF != nil, d.Remote != nil} {
		if present {
			references++
		}
	}
	if d.Kind == KindVerifier {
		if d.Provider != ProviderPublic || references != 0 {
			return invalid("verifier descriptors require provider %q and no signer reference", ProviderPublic)
		}
		return nil
	}
	if references != 1 {
		return invalid("signer descriptors require exactly one provider reference")
	}
	switch d.Provider {
	case ProviderSoftware:
		if d.Software == nil {
			return invalid("software provider requires software reference")
		}
		return validateSoftwareReference(*d.Software, suite)
	case ProviderPKCS11:
		if d.PKCS11 == nil {
			return invalid("pkcs11 provider requires pkcs11 reference")
		}
		return validatePKCS11URI(d.PKCS11.URI)
	case ProviderSDF:
		if d.SDF == nil {
			return invalid("sdf provider requires sdf reference")
		}
		if !validReference(d.SDF.DeviceRef) || d.SDF.KeyIndex == 0 || !validOptionalReference(d.SDF.CredentialRef) {
			return invalid("sdf reference is incomplete or non-canonical")
		}
		return nil
	case ProviderRemote:
		if d.Remote == nil {
			return invalid("remote provider requires remote reference")
		}
		return validateRemoteReference(*d.Remote)
	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedProvider, d.Provider)
	}
}

func validateSoftwareReference(ref SoftwareKeyReference, suite cryptosuite.Suite) error {
	if ref.Encoding != suite.Signature.PrivateKeyEncoding {
		return invalid("software private key encoding %q does not match suite %s", ref.Encoding, suite.ID)
	}
	if !validRelativePath(ref.MaterialPath) {
		return invalid("software material_path must be a clean relative path")
	}
	switch ref.Protection {
	case SoftwareProtectionPlaintextDev, SoftwareProtectionSM4Envelope:
		return nil
	default:
		return invalid("software protection %q is unsupported", ref.Protection)
	}
}

func validatePKCS11URI(raw string) error {
	if len(raw) == 0 || len(raw) > maxStringBytes || strings.ContainsAny(raw, "\r\n\t") {
		return invalid("pkcs11 URI is empty or malformed")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "pkcs11" || u.Opaque == "" || u.RawQuery != "" || u.Fragment != "" || u.String() != raw {
		return invalid("pkcs11 URI is malformed")
	}
	seen := map[string]struct{}{}
	items := strings.Split(u.Opaque, ";")
	attributeNames := make([]string, 0, len(items))
	for _, item := range items {
		parts := strings.SplitN(item, "=", 2)
		if len(parts) != 2 || parts[1] == "" || !validPKCS11AttributeName(parts[0]) {
			return invalid("pkcs11 URI contains a non-canonical attribute")
		}
		if _, ok := seen[parts[0]]; ok {
			return invalid("pkcs11 URI contains a duplicate attribute")
		}
		seen[parts[0]] = struct{}{}
		attributeNames = append(attributeNames, parts[0])
		if parts[0] == "pin-value" {
			return invalid("pkcs11 URI must not contain pin-value")
		}
	}
	sortedNames := append([]string(nil), attributeNames...)
	sort.Strings(sortedNames)
	for i := range attributeNames {
		if attributeNames[i] != sortedNames[i] {
			return invalid("pkcs11 URI attributes must be sorted by name")
		}
	}
	if _, object := seen["object"]; !object {
		if _, id := seen["id"]; !id {
			return invalid("pkcs11 URI must identify object or id")
		}
	}
	if _, ok := seen["type"]; ok {
		for _, item := range strings.Split(u.Opaque, ";") {
			if item == "type=private" {
				return nil
			}
		}
		return invalid("pkcs11 URI type must be private")
	}
	return nil
}

func validPKCS11AttributeName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func validateRemoteReference(ref RemoteKeyReference) error {
	if !validReference(ref.Endpoint) || !validReference(ref.Handle) || !validReference(ref.CredentialRef) {
		return invalid("remote endpoint, handle, and credential_ref are required and must be within size limits")
	}
	u, err := url.Parse(ref.Endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return invalid("remote endpoint must be an HTTPS origin without credentials, query, or fragment")
	}
	return nil
}

func validateCertificateChain(d Descriptor, suite cryptosuite.Suite) error {
	if len(d.CertificateChain) == 0 {
		return nil
	}
	if len(d.CertificateChain) > formatregistry.MaxCertificateCountV2 {
		return invalid("certificate chain has too many certificates")
	}
	total := 0
	certificates := make([]*smx509.Certificate, len(d.CertificateChain))
	for i, der := range d.CertificateChain {
		total += len(der)
		if len(der) == 0 || len(der) > formatregistry.MaxCertificateBytesV2 || total > formatregistry.MaxCertificateChainBytesV2 {
			return invalid("certificate chain exceeds size limits")
		}
		certificate, err := smx509.ParseCertificate(der)
		if err != nil || !bytes.Equal(certificate.Raw, der) {
			return invalid("certificate %d is invalid DER", i)
		}
		if err := validateCertificateAlgorithm(certificate, suite); err != nil {
			return invalid("certificate %d: %v", i, err)
		}
		certificates[i] = certificate
	}
	leafBytes, err := certificatePublicKeyBytes(certificates[0], suite)
	if err != nil {
		return invalid("leaf certificate: %v", err)
	}
	if !bytes.Equal(leafBytes, d.PublicKey.Bytes) {
		return invalid("leaf certificate public key does not match descriptor")
	}
	if certificates[0].KeyUsage != 0 && certificates[0].KeyUsage&smx509.KeyUsageDigitalSignature == 0 {
		return invalid("leaf certificate does not permit digital signatures")
	}
	for i := 0; i+1 < len(certificates); i++ {
		if !certificates[i+1].IsCA {
			return invalid("certificate %d is not a CA", i+1)
		}
		if err := certificates[i].CheckSignatureFrom(certificates[i+1]); err != nil {
			return invalid("certificate %d is not signed by certificate %d", i, i+1)
		}
	}
	return nil
}

func validateCertificateAlgorithm(certificate *smx509.Certificate, suite cryptosuite.Suite) error {
	switch suite.ID {
	case cryptosuite.INTLV1:
		if certificate.SignatureAlgorithm != smx509.PureEd25519 {
			return errors.New("signature algorithm is not Ed25519")
		}
	case cryptosuite.CNSMV1:
		if certificate.SignatureAlgorithm != smx509.SM2WithSM3 {
			return errors.New("signature algorithm is not SM2-SM3")
		}
	default:
		return errors.New("certificate suite is unsupported")
	}
	return nil
}

func certificatePublicKeyBytes(certificate *smx509.Certificate, suite cryptosuite.Suite) ([]byte, error) {
	switch suite.ID {
	case cryptosuite.INTLV1:
		publicKey, ok := certificate.PublicKey.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("public key is not Ed25519")
		}
		return append([]byte(nil), publicKey...), nil
	case cryptosuite.CNSMV1:
		publicKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("public key is not SM2")
		}
		return elliptic.Marshal(sm2.P256(), publicKey.X, publicKey.Y), nil
	default:
		return nil, errors.New("certificate suite is unsupported")
	}
}

func validRelativePath(value string) bool {
	if value == "" || len(value) > maxStringBytes || path.IsAbs(value) || strings.ContainsAny(value, "\\\r\n\x00") {
		return false
	}
	clean := path.Clean(value)
	return clean == value && clean != "." && clean != ".." && !strings.HasPrefix(clean, "../")
}

func validIdentifier(value string, maxBytes int) bool {
	if value == "" || len(value) > maxBytes || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validReference(value string) bool {
	return validIdentifier(value, maxStringBytes)
}

func validOptionalReference(value string) bool {
	return value == "" || validReference(value)
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidDescriptor, fmt.Sprintf(format, args...))
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
