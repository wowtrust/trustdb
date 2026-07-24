// Package signerplugin defines TrustDB's public subprocess boundary for
// non-exportable signing providers.  It deliberately exposes only key
// metadata, public-key retrieval, health, and signing.  Cryptographic-suite
// registration, hashing, canonical framing, Merkle operations, and public
// verification remain host responsibilities.
package signerplugin

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	ProtocolVersion = "trustdb.signer-plugin.v1"
	ServiceName     = "trustdb.signerplugin.v1.SignerProvider"
	MaxMessageBytes = 16 << 20
	// MaxSignInputBytes leaves bounded room for binding and key-reference
	// metadata inside the enclosing gRPC message.
	MaxSignInputBytes = MaxMessageBytes - (64 << 10)

	maxIdentifierBytes = 256
	maxReferenceBytes  = 4096
	maxCapabilities    = 32
	maxAlgorithms      = 32
	maxConcurrentSigns = 1024
)

const (
	CapabilityHealth    = "health"
	CapabilityPublicKey = "public_key"
	CapabilitySign      = "sign"
)

const (
	ProviderPKCS11 = "pkcs11"
	ProviderSDF    = "sdf"
	ProviderRemote = "remote"
)

const (
	SuiteINTLV1 = "INTL_V1"
	SuiteCNSMV1 = "CN_SM_V1"

	AlgorithmEd25519 = "ed25519"
	AlgorithmSM2SM3  = "sm2-sm3"

	Ed25519PublicKeyEncoding = "raw-32-byte-rfc8032"
	Ed25519SignatureEncoding = "raw-64-byte-rfc8032"
	SM2PublicKeyEncoding     = "sec1-uncompressed-65-byte-sm2p256v1"
	SM2SignatureEncoding     = "asn1-der-sequence-r-s"
	SM2DefaultUserID         = "1234567812345678"
)

const (
	HealthServing = "serving"
)

var requiredCapabilities = []string{
	CapabilityHealth,
	CapabilityPublicKey,
	CapabilitySign,
}

// AlgorithmCapability is a complete, immutable signature profile advertised
// by a plugin.  The host only selects profiles that exactly match its own
// cryptographic-suite registry.
type AlgorithmCapability struct {
	CryptoSuite       string `cbor:"crypto_suite" json:"crypto_suite"`
	Algorithm         string `cbor:"algorithm" json:"algorithm"`
	PublicKeyEncoding string `cbor:"public_key_encoding" json:"public_key_encoding"`
	SignatureEncoding string `cbor:"signature_encoding" json:"signature_encoding"`
	SM2UserID         string `cbor:"sm2_user_id" json:"sm2_user_id"`
}

// Info is returned by a plugin implementation before Serve publishes its
// startup handshake.  PluginID and ProviderKind must remain stable across
// restarts of the configured executable.
type Info struct {
	PluginID           string                `cbor:"plugin_id" json:"plugin_id"`
	ProviderKind       string                `cbor:"provider_kind" json:"provider_kind"`
	Algorithms         []AlgorithmCapability `cbor:"algorithms" json:"algorithms"`
	MaxConcurrentSigns uint32                `cbor:"max_concurrent_signs" json:"max_concurrent_signs"`
}

type GetInfoRequest struct {
	ProtocolVersion string `cbor:"protocol_version" json:"protocol_version"`
}

type GetInfoResponse struct {
	ProtocolVersion    string                `cbor:"protocol_version" json:"protocol_version"`
	PluginID           string                `cbor:"plugin_id" json:"plugin_id"`
	ProviderKind       string                `cbor:"provider_kind" json:"provider_kind"`
	Capabilities       []string              `cbor:"capabilities" json:"capabilities"`
	Algorithms         []AlgorithmCapability `cbor:"algorithms" json:"algorithms"`
	MaxConcurrentSigns uint32                `cbor:"max_concurrent_signs" json:"max_concurrent_signs"`
}

type HealthRequest struct {
	ProtocolVersion string `cbor:"protocol_version" json:"protocol_version"`
	PluginID        string `cbor:"plugin_id" json:"plugin_id"`
}

type HealthResponse struct {
	ProtocolVersion string `cbor:"protocol_version" json:"protocol_version"`
	PluginID        string `cbor:"plugin_id" json:"plugin_id"`
	Status          string `cbor:"status" json:"status"`
}

// Binding repeats every security-relevant selection on each key RPC.  A host
// and server must compare request, response, startup Info, and local
// descriptor values exactly; none of these fields are hints or defaults.
type Binding struct {
	ProtocolVersion   string `cbor:"protocol_version" json:"protocol_version"`
	PluginID          string `cbor:"plugin_id" json:"plugin_id"`
	ProviderKind      string `cbor:"provider_kind" json:"provider_kind"`
	CryptoSuite       string `cbor:"crypto_suite" json:"crypto_suite"`
	Algorithm         string `cbor:"algorithm" json:"algorithm"`
	PublicKeyEncoding string `cbor:"public_key_encoding" json:"public_key_encoding"`
	SignatureEncoding string `cbor:"signature_encoding" json:"signature_encoding"`
	KeyID             string `cbor:"key_id" json:"key_id"`
	SM2UserID         string `cbor:"sm2_user_id" json:"sm2_user_id"`
}

type PKCS11KeyReference struct {
	URI string `cbor:"uri" json:"uri"`
}

type SDFKeyReference struct {
	DeviceRef     string `cbor:"device_ref" json:"device_ref"`
	KeyIndex      uint32 `cbor:"key_index" json:"key_index"`
	CredentialRef string `cbor:"credential_ref" json:"credential_ref"`
}

type RemoteKeyReference struct {
	Endpoint      string `cbor:"endpoint" json:"endpoint"`
	Handle        string `cbor:"handle" json:"handle"`
	CredentialRef string `cbor:"credential_ref" json:"credential_ref"`
}

// KeyReference contains non-secret provider references only.  It has no
// private-key material field and exactly one member must match ProviderKind.
type KeyReference struct {
	PKCS11 *PKCS11KeyReference `cbor:"pkcs11,omitempty" json:"pkcs11,omitempty"`
	SDF    *SDFKeyReference    `cbor:"sdf,omitempty" json:"sdf,omitempty"`
	Remote *RemoteKeyReference `cbor:"remote,omitempty" json:"remote,omitempty"`
}

// Key is the validated provider selection passed to plugin implementations.
type Key struct {
	Binding   Binding      `cbor:"binding" json:"binding"`
	Reference KeyReference `cbor:"reference" json:"reference"`
}

type GetPublicKeyRequest struct {
	Key Key `cbor:"key" json:"key"`
}

type GetPublicKeyResponse struct {
	Binding   Binding `cbor:"binding" json:"binding"`
	PublicKey []byte  `cbor:"public_key" json:"public_key"`
}

type SignRequest struct {
	Key     Key    `cbor:"key" json:"key"`
	Message []byte `cbor:"message" json:"message"`
}

type SignResponse struct {
	Binding   Binding `cbor:"binding" json:"binding"`
	Signature []byte  `cbor:"signature" json:"signature"`
}

func (i Info) response() GetInfoResponse {
	algorithms := append([]AlgorithmCapability(nil), i.Algorithms...)
	sort.Slice(algorithms, func(a, b int) bool {
		return capabilityKey(algorithms[a]) < capabilityKey(algorithms[b])
	})
	return GetInfoResponse{
		ProtocolVersion:    ProtocolVersion,
		PluginID:           i.PluginID,
		ProviderKind:       i.ProviderKind,
		Capabilities:       append([]string(nil), requiredCapabilities...),
		Algorithms:         algorithms,
		MaxConcurrentSigns: i.MaxConcurrentSigns,
	}
}

func cloneInfoResponse(in GetInfoResponse) GetInfoResponse {
	in.Capabilities = append([]string(nil), in.Capabilities...)
	in.Algorithms = append([]AlgorithmCapability(nil), in.Algorithms...)
	return in
}

func (b Binding) capability() AlgorithmCapability {
	return AlgorithmCapability{
		CryptoSuite:       b.CryptoSuite,
		Algorithm:         b.Algorithm,
		PublicKeyEncoding: b.PublicKeyEncoding,
		SignatureEncoding: b.SignatureEncoding,
		SM2UserID:         b.SM2UserID,
	}
}

func capabilityKey(capability AlgorithmCapability) string {
	return strings.Join([]string{
		capability.CryptoSuite,
		capability.Algorithm,
		capability.PublicKeyEncoding,
		capability.SignatureEncoding,
		capability.SM2UserID,
	}, "\x00")
}

func ValidateInfo(info Info) error {
	return ValidateGetInfoResponse(info.response())
}

func ValidateGetInfoResponse(info GetInfoResponse) error {
	if info.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("signer plugin protocol %q is incompatible with %q", info.ProtocolVersion, ProtocolVersion)
	}
	if err := validatePluginID(info.PluginID); err != nil {
		return err
	}
	if !validProviderKind(info.ProviderKind) {
		return fmt.Errorf("signer plugin provider_kind %q is unsupported", info.ProviderKind)
	}
	if len(info.Capabilities) == 0 || len(info.Capabilities) > maxCapabilities {
		return errors.New("signer plugin capabilities are missing or excessive")
	}
	seenCapabilities := make(map[string]struct{}, len(info.Capabilities))
	for _, capability := range info.Capabilities {
		if !validIdentifier(capability, 64) {
			return fmt.Errorf("signer plugin capability %q is invalid", capability)
		}
		if !knownCapability(capability) {
			return fmt.Errorf("signer plugin capability %q is unsupported by protocol v1", capability)
		}
		if _, exists := seenCapabilities[capability]; exists {
			return fmt.Errorf("signer plugin capability %q is duplicated", capability)
		}
		seenCapabilities[capability] = struct{}{}
	}
	for _, required := range requiredCapabilities {
		if _, ok := seenCapabilities[required]; !ok {
			return fmt.Errorf("signer plugin must advertise %q capability", required)
		}
	}
	if len(info.Algorithms) == 0 || len(info.Algorithms) > maxAlgorithms {
		return errors.New("signer plugin algorithms are missing or excessive")
	}
	seenAlgorithms := make(map[string]struct{}, len(info.Algorithms))
	for _, capability := range info.Algorithms {
		if err := validateAlgorithmCapability(capability); err != nil {
			return err
		}
		key := capabilityKey(capability)
		if _, exists := seenAlgorithms[key]; exists {
			return fmt.Errorf("signer plugin algorithm capability for %s/%s is duplicated", capability.CryptoSuite, capability.Algorithm)
		}
		seenAlgorithms[key] = struct{}{}
	}
	if info.MaxConcurrentSigns == 0 || info.MaxConcurrentSigns > maxConcurrentSigns {
		return fmt.Errorf("signer plugin max_concurrent_signs must be between 1 and %d", maxConcurrentSigns)
	}
	return nil
}

func knownCapability(capability string) bool {
	switch capability {
	case CapabilityHealth, CapabilityPublicKey, CapabilitySign:
		return true
	default:
		return false
	}
}

func ValidateBinding(binding Binding) error {
	if binding.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("signer plugin binding protocol %q is incompatible with %q", binding.ProtocolVersion, ProtocolVersion)
	}
	if err := validatePluginID(binding.PluginID); err != nil {
		return err
	}
	if !validProviderKind(binding.ProviderKind) {
		return fmt.Errorf("signer plugin provider_kind %q is unsupported", binding.ProviderKind)
	}
	if !validIdentifier(binding.KeyID, maxIdentifierBytes) {
		return errors.New("signer plugin key_id is empty, malformed, or too long")
	}
	return validateAlgorithmCapability(binding.capability())
}

func ValidateKey(key Key) error {
	if err := ValidateBinding(key.Binding); err != nil {
		return err
	}
	return validateKeyReference(key.Binding.ProviderKind, key.Reference)
}

func ValidateHealthRequest(request HealthRequest, info GetInfoResponse) error {
	if request.ProtocolVersion != ProtocolVersion || request.PluginID != info.PluginID {
		return errors.New("signer plugin health binding does not match startup info")
	}
	return nil
}

func ValidateHealthResponse(response HealthResponse, info GetInfoResponse) error {
	if response.ProtocolVersion != ProtocolVersion || response.PluginID != info.PluginID {
		return errors.New("signer plugin health response does not match startup info")
	}
	if response.Status != HealthServing {
		return fmt.Errorf("signer plugin health status %q is not serving", response.Status)
	}
	return nil
}

func ValidateBindingForInfo(binding Binding, info GetInfoResponse) error {
	if err := ValidateBinding(binding); err != nil {
		return err
	}
	if binding.PluginID != info.PluginID || binding.ProviderKind != info.ProviderKind {
		return errors.New("signer plugin binding identity does not match startup info")
	}
	wanted := capabilityKey(binding.capability())
	for _, capability := range info.Algorithms {
		if capabilityKey(capability) == wanted {
			return nil
		}
	}
	return fmt.Errorf("signer plugin does not advertise %s/%s", binding.CryptoSuite, binding.Algorithm)
}

func sameBinding(a, b Binding) bool {
	return a == b
}

func validatePluginID(value string) error {
	if len(value) == 0 || len(value) > 64 {
		return errors.New("signer plugin plugin_id must contain 1 to 64 characters")
	}
	for index, r := range value {
		valid := r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-'
		if !valid || index == 0 && !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return fmt.Errorf("signer plugin plugin_id %q must match [a-z0-9][a-z0-9._-]*", value)
		}
	}
	return nil
}

func validProviderKind(provider string) bool {
	switch provider {
	case ProviderPKCS11, ProviderSDF, ProviderRemote:
		return true
	default:
		return false
	}
}

func validateAlgorithmCapability(capability AlgorithmCapability) error {
	switch capability.CryptoSuite {
	case SuiteINTLV1:
		if capability.Algorithm != AlgorithmEd25519 ||
			capability.PublicKeyEncoding != Ed25519PublicKeyEncoding ||
			capability.SignatureEncoding != Ed25519SignatureEncoding ||
			capability.SM2UserID != "" {
			return errors.New("signer plugin INTL_V1 capability does not match the immutable suite profile")
		}
	case SuiteCNSMV1:
		if capability.Algorithm != AlgorithmSM2SM3 ||
			capability.PublicKeyEncoding != SM2PublicKeyEncoding ||
			capability.SignatureEncoding != SM2SignatureEncoding ||
			capability.SM2UserID != SM2DefaultUserID {
			return errors.New("signer plugin CN_SM_V1 capability does not match the immutable suite profile")
		}
	default:
		return fmt.Errorf("signer plugin crypto_suite %q is unsupported by protocol v1", capability.CryptoSuite)
	}
	return nil
}

func validateKeyReference(provider string, reference KeyReference) error {
	present := 0
	for _, ok := range []bool{reference.PKCS11 != nil, reference.SDF != nil, reference.Remote != nil} {
		if ok {
			present++
		}
	}
	if present != 1 {
		return errors.New("signer plugin key reference must contain exactly one provider reference")
	}
	switch provider {
	case ProviderPKCS11:
		if reference.PKCS11 == nil {
			return errors.New("signer plugin pkcs11 binding requires a pkcs11 reference")
		}
		return validatePKCS11URI(reference.PKCS11.URI)
	case ProviderSDF:
		if reference.SDF == nil {
			return errors.New("signer plugin sdf binding requires an sdf reference")
		}
		if !validIdentifier(reference.SDF.DeviceRef, maxReferenceBytes) || reference.SDF.KeyIndex == 0 ||
			!validOptionalIdentifier(reference.SDF.CredentialRef, maxReferenceBytes) {
			return errors.New("signer plugin sdf reference is incomplete or malformed")
		}
		return nil
	case ProviderRemote:
		if reference.Remote == nil {
			return errors.New("signer plugin remote binding requires a remote reference")
		}
		return validateRemoteReference(*reference.Remote)
	default:
		return fmt.Errorf("signer plugin provider_kind %q is unsupported", provider)
	}
}

func validatePKCS11URI(raw string) error {
	if !validIdentifier(raw, maxReferenceBytes) {
		return errors.New("signer plugin pkcs11 URI is empty or malformed")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "pkcs11" || u.Opaque == "" || u.RawQuery != "" || u.Fragment != "" || u.String() != raw {
		return errors.New("signer plugin pkcs11 URI is malformed")
	}
	seen := make(map[string]struct{})
	items := strings.Split(u.Opaque, ";")
	attributeNames := make([]string, 0, len(items))
	for _, item := range items {
		parts := strings.SplitN(item, "=", 2)
		if len(parts) != 2 || parts[1] == "" || !validPKCS11AttributeName(parts[0]) {
			return errors.New("signer plugin pkcs11 URI contains a malformed attribute")
		}
		if _, exists := seen[parts[0]]; exists {
			return errors.New("signer plugin pkcs11 URI contains a duplicate attribute")
		}
		seen[parts[0]] = struct{}{}
		attributeNames = append(attributeNames, parts[0])
		if parts[0] == "pin-value" {
			return errors.New("signer plugin pkcs11 URI must not contain pin-value")
		}
	}
	sortedNames := append([]string(nil), attributeNames...)
	sort.Strings(sortedNames)
	for index := range attributeNames {
		if attributeNames[index] != sortedNames[index] {
			return errors.New("signer plugin pkcs11 URI attributes must be sorted by name")
		}
	}
	if _, hasObject := seen["object"]; !hasObject {
		if _, hasID := seen["id"]; !hasID {
			return errors.New("signer plugin pkcs11 URI must identify object or id")
		}
	}
	if _, hasType := seen["type"]; hasType {
		for _, item := range items {
			if item == "type=private" {
				return nil
			}
		}
		return errors.New("signer plugin pkcs11 URI type must be private")
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

func validateRemoteReference(reference RemoteKeyReference) error {
	if !validIdentifier(reference.Endpoint, maxReferenceBytes) ||
		!validIdentifier(reference.Handle, maxReferenceBytes) ||
		!validIdentifier(reference.CredentialRef, maxReferenceBytes) {
		return errors.New("signer plugin remote endpoint, handle, and credential_ref are required and bounded")
	}
	u, err := url.Parse(reference.Endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.String() != reference.Endpoint {
		return errors.New("signer plugin remote endpoint must be an HTTPS origin without credentials, query, or fragment")
	}
	return nil
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

func validOptionalIdentifier(value string, maxBytes int) bool {
	return value == "" || validIdentifier(value, maxBytes)
}

func validatePublicKey(binding Binding, publicKey []byte) error {
	switch binding.CryptoSuite {
	case SuiteINTLV1:
		if len(publicKey) != 32 {
			return fmt.Errorf("signer plugin returned Ed25519 public key size %d", len(publicKey))
		}
	case SuiteCNSMV1:
		if len(publicKey) != 65 || publicKey[0] != 0x04 {
			return errors.New("signer plugin returned a malformed SM2 uncompressed public key")
		}
	default:
		return fmt.Errorf("signer plugin crypto_suite %q is unsupported", binding.CryptoSuite)
	}
	return nil
}

func validateSignature(binding Binding, signature []byte) error {
	switch binding.CryptoSuite {
	case SuiteINTLV1:
		if len(signature) != 64 {
			return fmt.Errorf("signer plugin returned Ed25519 signature size %d", len(signature))
		}
	case SuiteCNSMV1:
		if err := validateCanonicalDERSignature(signature); err != nil {
			return err
		}
	default:
		return fmt.Errorf("signer plugin crypto_suite %q is unsupported", binding.CryptoSuite)
	}
	return nil
}

type derSignature struct {
	R *big.Int
	S *big.Int
}

func validateCanonicalDERSignature(signature []byte) error {
	if len(signature) < 8 || len(signature) > 72 {
		return fmt.Errorf("signer plugin returned SM2 DER signature size %d", len(signature))
	}
	var parsed derSignature
	rest, err := asn1.Unmarshal(signature, &parsed)
	if err != nil || len(rest) != 0 || parsed.R == nil || parsed.S == nil || parsed.R.Sign() <= 0 || parsed.S.Sign() <= 0 {
		return errors.New("signer plugin returned a malformed SM2 DER signature")
	}
	canonical, err := asn1.Marshal(parsed)
	if err != nil || !bytes.Equal(canonical, signature) {
		return errors.New("signer plugin returned a non-canonical SM2 DER signature")
	}
	return nil
}
