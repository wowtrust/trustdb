package adminweb

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const sessionCookieName = "trustdb_admin_session"
const sessionVersion = "v1"

type sessionPayload struct {
	Exp  int64  `json:"exp"`
	User string `json:"user"`
}

func issueSessionToken(secret []byte, user string, ttl time.Duration) (string, error) {
	return issueSessionTokenAt(secret, user, ttl, time.Now())
}

func issueSessionTokenAt(secret []byte, user string, ttl time.Duration, now time.Time) (string, error) {
	if len(secret) < 32 {
		return "", errors.New("session secret too short")
	}
	exp := now.Add(ttl).Unix()
	pl, err := json.Marshal(sessionPayload{Exp: exp, User: user})
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(pl)
	sig := mac.Sum(nil)
	return sessionVersion + "." + base64.RawURLEncoding.EncodeToString(pl) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func verifySessionToken(secret []byte, token string) (user string, ok bool) {
	return verifySessionTokenAt(secret, token, time.Now())
}

func verifySessionTokenAt(secret []byte, token string, now time.Time) (user string, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != sessionVersion {
		return "", false
	}
	pl, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", false
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(pl)
	want := mac.Sum(nil)
	if len(sig) != len(want) || subtle.ConstantTimeCompare(sig, want) != 1 {
		return "", false
	}
	var p sessionPayload
	if err := json.Unmarshal(pl, &p); err != nil || p.User == "" {
		return "", false
	}
	if now.Unix() >= p.Exp {
		return "", false
	}
	return p.User, true
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
	// HttpOnly; SameSite=Lax; Path=<base>
	p := cookiePath(basePath)
	return fmt.Sprintf("%s=%s; Path=%s; Max-Age=%d; HttpOnly; SameSite=Lax%s",
		sessionCookieName, token, p, maxAge, func() string {
			if secure {
				return "; Secure"
			}
			return ""
		}())
}

func clearSessionCookie(basePath string, secure bool) string {
	p := cookiePath(basePath)
	return fmt.Sprintf("%s=; Path=%s; Max-Age=0; HttpOnly; SameSite=Lax%s",
		sessionCookieName, p, func() string {
			if secure {
				return "; Secure"
			}
			return ""
		}())
}
