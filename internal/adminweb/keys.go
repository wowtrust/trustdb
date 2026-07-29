package adminweb

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/wowtrust/trustdb/v2/internal/keydescriptor"
	"github.com/wowtrust/trustdb/v2/internal/keystore"
	"github.com/wowtrust/trustdb/v2/internal/model"
)

const (
	maxKeyLifecycleBodyBytes int64 = 4 << 20
	maxRevocationClockSkew         = 5 * time.Second
)

type registerKeyBody struct {
	TenantID   string                   `json:"tenant_id"`
	ClientID   string                   `json:"client_id"`
	Descriptor keydescriptor.Descriptor `json:"descriptor"`
	ValidFrom  time.Time                `json:"valid_from"`
	ValidUntil *time.Time               `json:"valid_until,omitempty"`
}

type revokeKeyBody struct {
	RevokedAt time.Time `json:"revoked_at"`
	Reason    string    `json:"reason,omitempty"`
}

func (h *handler) postKey(w http.ResponseWriter, r *http.Request) {
	if h.opts.KeyRegistry == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "writable key registry is unavailable"})
		return
	}
	var body registerKeyBody
	if err := decodeJSONBodyLimit(r.Body, &body, maxKeyLifecycleBodyBytes); err != nil {
		writeKeyBodyError(w, err)
		return
	}
	body.TenantID = strings.TrimSpace(body.TenantID)
	body.ClientID = strings.TrimSpace(body.ClientID)
	if body.TenantID == "" || body.ClientID == "" || body.ValidFrom.IsZero() {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "tenant_id, client_id, descriptor, and valid_from are required"})
		return
	}
	if body.Descriptor.Kind != keydescriptor.KindVerifier || body.Descriptor.Provider != keydescriptor.ProviderPublic {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "descriptor must be a public verifier descriptor"})
		return
	}
	var validUntil time.Time
	if body.ValidUntil != nil {
		validUntil = body.ValidUntil.UTC()
	}
	event, err := h.opts.KeyRegistry.RegisterClientKey(
		body.TenantID,
		body.ClientID,
		body.Descriptor,
		body.ValidFrom.UTC(),
		validUntil,
	)
	if err != nil {
		writeKeyLifecycleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, keyEventEnvelope(event))
}

func (h *handler) getKey(w http.ResponseWriter, r *http.Request) {
	if h.opts.KeyRegistry == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "key registry is unavailable"})
		return
	}
	at := h.opts.Now().UTC()
	if raw := strings.TrimSpace(r.URL.Query().Get("at")); raw != "" {
		parsed, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "at must be RFC3339"})
			return
		}
		at = parsed.UTC()
	}
	key, err := h.opts.KeyRegistry.LookupClientKeyAt(
		strings.TrimSpace(r.PathValue("tenant_id")),
		strings.TrimSpace(r.PathValue("client_id")),
		strings.TrimSpace(r.PathValue("key_id")),
		at,
	)
	if err != nil {
		writeKeyLifecycleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "key": key, "at": at})
}

func (h *handler) postKeyRevoke(w http.ResponseWriter, r *http.Request) {
	if h.opts.KeyRegistry == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "writable key registry is unavailable"})
		return
	}
	var body revokeKeyBody
	if err := decodeJSONBodyLimit(r.Body, &body, maxKeyLifecycleBodyBytes); err != nil {
		writeKeyBodyError(w, err)
		return
	}
	if body.RevokedAt.IsZero() {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "revoked_at is required"})
		return
	}
	tenantID := strings.TrimSpace(r.PathValue("tenant_id"))
	clientID := strings.TrimSpace(r.PathValue("client_id"))
	keyID := strings.TrimSpace(r.PathValue("key_id"))
	reason := strings.TrimSpace(body.Reason)
	if existing, ok := h.opts.KeyRegistry.RevocationEvent(tenantID, clientID, keyID); ok {
		if identicalRevocation(existing, body.RevokedAt.UTC(), reason) {
			writeJSON(w, http.StatusOK, keyEventEnvelope(existing))
			return
		}
	}
	if body.RevokedAt.Before(h.opts.Now().UTC().Add(-maxRevocationClockSkew)) {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "new online revocation cannot take effect more than 5 seconds in the past",
		})
		return
	}
	event, err := h.opts.KeyRegistry.RevokeClientKey(
		tenantID,
		clientID,
		keyID,
		body.RevokedAt.UTC(),
		reason,
	)
	if err != nil {
		writeKeyLifecycleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, keyEventEnvelope(event))
}

func identicalRevocation(event model.KeyEvent, revokedAt time.Time, reason string) bool {
	return event.Type == model.KeyEventRevoke &&
		event.RevokedAtUnixN == revokedAt.UTC().UnixNano() &&
		event.Reason == reason
}

func keyEventEnvelope(event model.KeyEvent) map[string]any {
	return map[string]any{
		"ok":           true,
		"sequence":     event.Sequence,
		"event_type":   event.Type,
		"event_hash":   base64.RawURLEncoding.EncodeToString(event.EventHash),
		"tenant_id":    event.TenantID,
		"client_id":    event.ClientID,
		"key_id":       event.KeyID,
		"crypto_suite": event.CryptoSuite,
	}
}

func writeKeyBodyError(w http.ResponseWriter, err error) {
	if errors.Is(err, errRequestBodyTooLarge) {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"ok": false, "error": "request too large"})
		return
	}
	var syntaxError *json.SyntaxError
	if errors.As(err, &syntaxError) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid json"})
		return
	}
	writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid key lifecycle request"})
}

func writeKeyLifecycleError(w http.ResponseWriter, err error) {
	message := err.Error()
	switch {
	case errors.Is(err, keystore.ErrConflictingKeyID):
		writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": message})
	case strings.Contains(message, "key not found"), strings.Contains(message, "missing key"):
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": message})
	case strings.Contains(message, "registry signer is required"):
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "writable key registry is unavailable"})
	case strings.Contains(message, "key status is"), strings.Contains(message, "already retired"), strings.Contains(message, "already marked compromised"):
		writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": message})
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": message})
	}
}
