package adminweb

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
)

const (
	oidcIssuerHeader  = "X-TrustDB-OIDC-Issuer"
	oidcSubjectHeader = "X-TrustDB-OIDC-Subject"
	oidcMFAHeader     = "X-TrustDB-OIDC-MFA"
)

// MTLSGatewayOIDCVerifier trusts OIDC identity headers only when they arrive
// through a mutually authenticated gateway certificate whose SPKI digest is
// explicitly pinned. The gateway remains responsible for JWT signature,
// issuer, audience, expiry, nonce, and MFA validation.
type MTLSGatewayOIDCVerifier struct {
	pins [][]byte
}

func NewMTLSGatewayOIDCVerifier(pins []string) (*MTLSGatewayOIDCVerifier, error) {
	verifier := &MTLSGatewayOIDCVerifier{pins: make([][]byte, 0, len(pins))}
	for _, pin := range pins {
		decoded, err := hex.DecodeString(strings.TrimSpace(pin))
		if err != nil || len(decoded) != sha256.Size {
			return nil, errors.New("adminweb: OIDC gateway pin must be SHA-256 hex")
		}
		verifier.pins = append(verifier.pins, decoded)
	}
	if len(verifier.pins) == 0 {
		return nil, errors.New("adminweb: at least one OIDC gateway pin is required")
	}
	return verifier, nil
}

func (v *MTLSGatewayOIDCVerifier) VerifyOIDC(request *http.Request) (OIDCIdentity, error) {
	if request == nil || request.TLS == nil || len(request.TLS.PeerCertificates) == 0 {
		return OIDCIdentity{}, errors.New("adminweb: OIDC gateway requires mTLS")
	}
	digest := sha256.Sum256(request.TLS.PeerCertificates[0].RawSubjectPublicKeyInfo)
	matched := 0
	for _, pin := range v.pins {
		if len(pin) == len(digest) {
			matched |= subtle.ConstantTimeCompare(pin, digest[:])
		}
	}
	if matched != 1 {
		return OIDCIdentity{}, errors.New("adminweb: OIDC gateway certificate is not pinned")
	}
	issuer := strings.TrimSpace(request.Header.Get(oidcIssuerHeader))
	subject := strings.TrimSpace(request.Header.Get(oidcSubjectHeader))
	if issuer == "" || len(issuer) > 2048 || subject == "" || len(subject) > 512 {
		return OIDCIdentity{}, errors.New("adminweb: OIDC gateway identity headers are invalid")
	}
	mfaText := strings.TrimSpace(request.Header.Get(oidcMFAHeader))
	if mfaText != "" && mfaText != "true" && mfaText != "false" {
		return OIDCIdentity{}, errors.New("adminweb: OIDC MFA header must be true or false")
	}
	return OIDCIdentity{Issuer: issuer, Subject: subject, MFA: mfaText == "true"}, nil
}
