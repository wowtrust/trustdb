package adminweb

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/wowtrust/trustdb/v2/internal/adminauth"
)

const sessionCookieName = "trustdb_admin_session"
const sessionVersion = "v2"

type sessionPayload struct {
	Exp             int64               `json:"exp"`
	Iat             int64               `json:"iat"`
	JTI             string              `json:"jti"`
	Principal       adminauth.Principal `json:"principal"`
	EmergencyReason string              `json:"emergency_reason,omitempty"`
}

func issueSessionToken(secret []byte, principal adminauth.Principal, emergencyReason string, ttl time.Duration) (string, error) {
	return issueSessionTokenAt(secret, principal, emergencyReason, ttl, time.Now())
}

func issueSessionTokenAt(secret []byte, principal adminauth.Principal, emergencyReason string, ttl time.Duration, now time.Time) (string, error) {
	if len(secret) < 32 {
		return "", errors.New("session secret too short")
	}
	if principal.AccountID == "" || principal.Username == "" || principal.PolicyDigest == "" {
		return "", errors.New("session principal is incomplete")
	}
	if principal.Emergency && strings.TrimSpace(emergencyReason) == "" {
		return "", errors.New("emergency session requires a reason")
	}
	jtiBytes := make([]byte, 18)
	if _, err := rand.Read(jtiBytes); err != nil {
		return "", err
	}
	pl, err := json.Marshal(sessionPayload{
		Exp: now.Add(ttl).Unix(), Iat: now.Unix(), JTI: base64.RawURLEncoding.EncodeToString(jtiBytes),
		Principal: principal, EmergencyReason: strings.TrimSpace(emergencyReason),
	})
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(pl)
	sig := mac.Sum(nil)
	return sessionVersion + "." + base64.RawURLEncoding.EncodeToString(pl) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func verifySessionToken(secret []byte, token string) (principal adminauth.Principal, emergencyReason string, ok bool) {
	return verifySessionTokenAt(secret, token, time.Now())
}

func verifySessionTokenAt(secret []byte, token string, now time.Time) (principal adminauth.Principal, emergencyReason string, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != sessionVersion {
		return adminauth.Principal{}, "", false
	}
	pl, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return adminauth.Principal{}, "", false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return adminauth.Principal{}, "", false
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(pl)
	want := mac.Sum(nil)
	if len(sig) != len(want) || subtle.ConstantTimeCompare(sig, want) != 1 {
		return adminauth.Principal{}, "", false
	}
	var p sessionPayload
	if err := json.Unmarshal(pl, &p); err != nil || p.Principal.AccountID == "" || p.Principal.Username == "" || p.JTI == "" {
		return adminauth.Principal{}, "", false
	}
	if p.Iat > now.Unix()+60 || now.Unix() >= p.Exp || p.Exp <= p.Iat {
		return adminauth.Principal{}, "", false
	}
	if p.Principal.Emergency && strings.TrimSpace(p.EmergencyReason) == "" {
		return adminauth.Principal{}, "", false
	}
	return p.Principal, p.EmergencyReason, true
}

func sessionTTL(cfgTTL string) time.Duration {
	d, err := time.ParseDuration(strings.TrimSpace(cfgTTL))
	if err != nil || d <= 0 {
		return 8 * time.Hour
	}
	return d
}

func cookiePath(basePath string) string {
	bp := strings.TrimSuffix(strings.TrimSpace(basePath), "/")
	if bp == "" {
		return "/admin"
	}
	return bp
}

func buildSessionCookie(basePath, token string, secure bool, ttl time.Duration) string {
	maxAge := int(ttl.Seconds())
	if maxAge < 60 {
		maxAge = 60
	}
	// HttpOnly; SameSite=Strict; Path=<base>
	p := cookiePath(basePath)
	return fmt.Sprintf("%s=%s; Path=%s; Max-Age=%d; HttpOnly; SameSite=Strict%s",
		sessionCookieName, token, p, maxAge, func() string {
			if secure {
				return "; Secure"
			}
			return ""
		}())
}

func clearSessionCookie(basePath string, secure bool) string {
	p := cookiePath(basePath)
	return fmt.Sprintf("%s=; Path=%s; Max-Age=0; HttpOnly; SameSite=Strict%s",
		sessionCookieName, p, func() string {
			if secure {
				return "; Secure"
			}
			return ""
		}())
}
