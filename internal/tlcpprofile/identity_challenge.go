package tlcpprofile

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/wowtrust/trustdb/v2/internal/model"
	"github.com/wowtrust/trustdb/v2/internal/trustcrypto"
)

const (
	ActiveIdentityChallengePath   = "/.well-known/trustdb/tlcp-active-identities"
	ActiveIdentityChallengeSchema = "trustdb.tlcp-active-identity-challenge.v1"

	activeIdentityChallengeNonceBytes = 32
	maxActiveIdentityChallengeBytes   = 256 << 10
	activeIdentityChallengeDomain     = "trustdb.tlcp-active-identity-challenge.v1\x00"
)

// ActiveIdentityChallenge proves that the running TrustDB process currently
// owns the proof signer and has authenticated the registry identity named by
// the strict gateway profile. The caller supplies a fresh nonce on every
// readiness invocation, so a saved response cannot be replayed.
type ActiveIdentityChallenge struct {
	SchemaVersion          string          `json:"schema_version"`
	NonceBase64URL         string          `json:"nonce_base64url"`
	IdentityManifestSHA256 string          `json:"identity_manifest_sha256"`
	ProofSigner            PublicIdentity  `json:"proof_signer"`
	RegistrySigner         *PublicIdentity `json:"registry_signer,omitempty"`
	Signature              model.Signature `json:"signature"`
}

type activeIdentityChallengePayload struct {
	SchemaVersion          string          `json:"schema_version"`
	NonceBase64URL         string          `json:"nonce_base64url"`
	IdentityManifestSHA256 string          `json:"identity_manifest_sha256"`
	ProofSigner            PublicIdentity  `json:"proof_signer"`
	RegistrySigner         *PublicIdentity `json:"registry_signer,omitempty"`
}

// ActiveIdentityChallengeService is mounted only by a TrustDB serve process
// that completed the strict TLCP identity boundary. It exposes no private
// material and accepts requests only from the shared loopback namespace.
type ActiveIdentityChallengeService struct {
	manifest       TrustDBIdentityManifest
	manifestSHA256 string
	signer         trustcrypto.Signer
	proofPublic    trustcrypto.PublicKeyDescriptor
}

func NewActiveIdentityChallengeService(
	manifest TrustDBIdentityManifest,
	signer trustcrypto.Signer,
) (*ActiveIdentityChallengeService, error) {
	proofDescriptor, _, err := validatePublicIdentity(
		identityRoleProofSigner,
		manifest.ProofSigner,
	)
	if err != nil {
		return nil, fmt.Errorf("active proof signer: %w", err)
	}
	if manifest.RegistrySigner != nil {
		if _, _, err := validatePublicIdentity(
			identityRoleRegistrySigner,
			*manifest.RegistrySigner,
		); err != nil {
			return nil, fmt.Errorf("active registry signer: %w", err)
		}
	}
	if signer == nil {
		return nil, errors.New("active TrustDB proof signer is required")
	}
	activePublic, err := signer.PublicKey(context.Background())
	if err != nil {
		return nil, fmt.Errorf("resolve active TrustDB proof signer: %w", err)
	}
	expectedPublic, err := proofPublicKeyDescriptor(proofDescriptor)
	if err != nil {
		return nil, err
	}
	if !equalTrustDBPublicKey(activePublic, expectedPublic) {
		return nil, errors.New(
			"active TrustDB proof signer does not match the challenge manifest",
		)
	}
	manifestData, err := encodeTrustDBIdentityManifest(manifest)
	if err != nil {
		return nil, err
	}
	return &ActiveIdentityChallengeService{
		manifest:       manifest,
		manifestSHA256: digestBytes(manifestData),
		signer:         signer,
		proofPublic:    expectedPublic,
	}, nil
}

func (service *ActiveIdentityChallengeService) Mount(next http.Handler) http.Handler {
	if next == nil {
		next = http.NotFoundHandler()
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != ActiveIdentityChallengePath {
			next.ServeHTTP(writer, request)
			return
		}
		service.serveHTTP(writer, request)
	})
}

func (service *ActiveIdentityChallengeService) serveHTTP(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method != http.MethodGet {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !loopbackRemoteAddress(request.RemoteAddr) {
		http.Error(writer, "forbidden", http.StatusForbidden)
		return
	}
	nonce, err := parseChallengeNonce(request.URL)
	if err != nil {
		http.Error(writer, "invalid nonce", http.StatusBadRequest)
		return
	}
	payload := activeIdentityChallengePayload{
		SchemaVersion:          ActiveIdentityChallengeSchema,
		NonceBase64URL:         base64.RawURLEncoding.EncodeToString(nonce),
		IdentityManifestSHA256: service.manifestSHA256,
		ProofSigner:            service.manifest.ProofSigner,
		RegistrySigner:         service.manifest.RegistrySigner,
	}
	payloadData, err := json.Marshal(payload)
	if err != nil {
		http.Error(writer, "encode challenge", http.StatusInternalServerError)
		return
	}
	signature, err := trustcrypto.Sign(
		request.Context(),
		service.proofPublic.Suite,
		service.signer,
		append([]byte(activeIdentityChallengeDomain), payloadData...),
	)
	if err != nil {
		http.Error(writer, "sign challenge", http.StatusServiceUnavailable)
		return
	}
	response := ActiveIdentityChallenge{
		SchemaVersion:          payload.SchemaVersion,
		NonceBase64URL:         payload.NonceBase64URL,
		IdentityManifestSHA256: payload.IdentityManifestSHA256,
		ProofSigner:            payload.ProofSigner,
		RegistrySigner:         payload.RegistrySigner,
		Signature:              signature,
	}
	data, err := encodeActiveIdentityChallenge(response)
	if err != nil {
		http.Error(writer, "encode challenge", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(data)
}

// VerifyActiveIdentityChallenge performs a fresh online proof-of-possession
// against the actual loopback TrustDB upstream named by the profile.
func VerifyActiveIdentityChallenge(
	ctx context.Context,
	profilePath string,
	profile Profile,
) error {
	profileData, err := readBoundedRegularFile(profilePath, MaxProfileBytes)
	if err != nil {
		return fmt.Errorf("read active TLCP profile: %w", err)
	}
	currentProfile, err := Decode(profileData)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(currentProfile, profile) {
		return errors.New(
			"TLCP profile changed before the active TrustDB identity challenge",
		)
	}
	manifest, _, manifestSHA256, err := loadTrustDBIdentityManifest(
		profile.TrustDBIdentityManifestFile,
	)
	if err != nil {
		return err
	}
	nonce := make([]byte, activeIdentityChallengeNonceBytes)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generate TrustDB identity challenge nonce: %w", err)
	}
	nonceText := base64.RawURLEncoding.EncodeToString(nonce)
	query := url.Values{"nonce": []string{nonceText}}.Encode()
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		"http://trustdb.invalid"+ActiveIdentityChallengePath+"?"+query,
		nil,
	)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	transport := &http.Transport{
		Proxy:                 nil,
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: 5 * time.Second,
		DialContext: func(
			dialContext context.Context,
			network string,
			_ string,
		) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(
				dialContext,
				network,
				profile.Network.TrustDBHTTPUpstream,
			)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("TrustDB identity challenge redirects are forbidden")
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("request active TrustDB identity challenge: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return fmt.Errorf(
			"active TrustDB identity challenge returned HTTP %d",
			response.StatusCode,
		)
	}
	data, err := io.ReadAll(io.LimitReader(
		response.Body,
		maxActiveIdentityChallengeBytes+1,
	))
	if err != nil {
		return fmt.Errorf("read active TrustDB identity challenge: %w", err)
	}
	if len(data) > maxActiveIdentityChallengeBytes {
		return fmt.Errorf(
			"active TrustDB identity challenge exceeds %d bytes",
			maxActiveIdentityChallengeBytes,
		)
	}
	var challenge ActiveIdentityChallenge
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&challenge); err != nil {
		return fmt.Errorf("decode active TrustDB identity challenge: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("active TrustDB identity challenge contains trailing data")
	}
	canonical, err := encodeActiveIdentityChallenge(challenge)
	if err != nil {
		return err
	}
	if !bytes.Equal(canonical, data) {
		return errors.New("active TrustDB identity challenge is not canonical")
	}
	if challenge.SchemaVersion != ActiveIdentityChallengeSchema ||
		challenge.NonceBase64URL != nonceText ||
		challenge.IdentityManifestSHA256 != manifestSHA256 ||
		challenge.ProofSigner != manifest.ProofSigner ||
		!equalOptionalPublicIdentity(
			challenge.RegistrySigner,
			manifest.RegistrySigner,
		) {
		return errors.New(
			"running TrustDB identities do not exactly match the active TLCP identity manifest",
		)
	}
	proofDescriptor, _, err := validatePublicIdentity(
		identityRoleProofSigner,
		challenge.ProofSigner,
	)
	if err != nil {
		return err
	}
	proofPublic, err := proofPublicKeyDescriptor(proofDescriptor)
	if err != nil {
		return err
	}
	payload := activeIdentityChallengePayload{
		SchemaVersion:          challenge.SchemaVersion,
		NonceBase64URL:         challenge.NonceBase64URL,
		IdentityManifestSHA256: challenge.IdentityManifestSHA256,
		ProofSigner:            challenge.ProofSigner,
		RegistrySigner:         challenge.RegistrySigner,
	}
	payloadData, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if err := trustcrypto.VerifySignatureForSuite(
		ctx,
		proofPublic.Suite,
		proofPublic,
		append([]byte(activeIdentityChallengeDomain), payloadData...),
		challenge.Signature,
	); err != nil {
		return fmt.Errorf("verify active TrustDB proof signer challenge: %w", err)
	}
	return nil
}

func parseChallengeNonce(requestURL *url.URL) ([]byte, error) {
	query := requestURL.Query()
	if len(query) != 1 || len(query["nonce"]) != 1 {
		return nil, errors.New("exactly one nonce is required")
	}
	text := query["nonce"][0]
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(text)
	if err != nil || len(nonce) != activeIdentityChallengeNonceBytes ||
		base64.RawURLEncoding.EncodeToString(nonce) != text {
		return nil, errors.New("nonce must be canonical base64url")
	}
	return nonce, nil
}

func loopbackRemoteAddress(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return false
	}
	address, err := netip.ParseAddr(strings.TrimSpace(host))
	return err == nil && address.Unmap().IsLoopback()
}

func encodeActiveIdentityChallenge(
	challenge ActiveIdentityChallenge,
) ([]byte, error) {
	data, err := json.MarshalIndent(challenge, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode active TrustDB identity challenge: %w", err)
	}
	return append(data, '\n'), nil
}

func equalOptionalPublicIdentity(left, right *PublicIdentity) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func proofPublicKeyDescriptor(
	descriptor proofKeyDescriptor,
) (trustcrypto.PublicKeyDescriptor, error) {
	return trustcrypto.PublicKeyDescriptor{
		Suite:     descriptor.CryptoSuite,
		KeyID:     descriptor.KeyID,
		Algorithm: descriptor.Algorithm,
		Encoding:  descriptor.PublicKey.Encoding,
		Bytes:     append([]byte(nil), descriptor.PublicKey.Bytes...),
	}, nil
}

func equalTrustDBPublicKey(
	left trustcrypto.PublicKeyDescriptor,
	right trustcrypto.PublicKeyDescriptor,
) bool {
	return left.Suite == right.Suite &&
		left.KeyID == right.KeyID &&
		left.Algorithm == right.Algorithm &&
		left.Encoding == right.Encoding &&
		bytes.Equal(left.Bytes, right.Bytes)
}
