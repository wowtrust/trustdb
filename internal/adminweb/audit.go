package adminweb

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"

	"github.com/wowtrust/trustdb/v2/internal/adminauth"
	"github.com/wowtrust/trustdb/v2/internal/securityaudit"
)

type requestIDContextKey struct{}

func (h *handler) requestID(w http.ResponseWriter, r *http.Request) (string, *http.Request) {
	if existing, ok := r.Context().Value(requestIDContextKey{}).(string); ok && existing != "" {
		return existing, r
	}
	requestID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if !validRequestID(requestID) {
		var value [16]byte
		if _, err := rand.Read(value[:]); err == nil {
			requestID = hex.EncodeToString(value[:])
		} else {
			requestID = "generated-request"
		}
	}
	w.Header().Set("X-Request-ID", requestID)
	ctx := context.WithValue(r.Context(), requestIDContextKey{}, requestID)
	return requestID, r.WithContext(ctx)
}

func validRequestID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._:-", r) {
			continue
		}
		return false
	}
	return true
}

func (h *handler) recordAudit(ctx context.Context, draft securityaudit.Draft) error {
	if h.opts.Auditor == nil {
		return nil
	}
	_, err := h.opts.Auditor.Record(ctx, draft)
	return err
}

func (h *handler) recordHTTPAudit(r *http.Request, principal adminauth.Principal, action, result string, extra map[string]string) error {
	requestID, _ := r.Context().Value(requestIDContextKey{}).(string)
	actor := principal.AccountID
	if actor == "" {
		actor = "anonymous"
	}
	contextValues := map[string]string{
		"method": r.Method, "path": r.URL.Path, "source_hash": requestSourceHash(r.RemoteAddr),
	}
	for key, value := range extra {
		contextValues[key] = value
	}
	roles := make([]string, len(principal.Roles))
	for index, role := range principal.Roles {
		roles[index] = string(role)
	}
	return h.recordAudit(r.Context(), securityaudit.Draft{
		Actor: actor, Roles: roles, Action: action, Object: r.URL.Path, Result: result,
		RequestID: requestID, Source: "admin-http", PolicyVersion: principal.PolicyVersion, Context: contextValues,
	})
}

func requestSourceHash(remoteAddr string) string {
	digest := sha256.Sum256([]byte(strings.TrimSpace(remoteAddr)))
	return hex.EncodeToString(digest[:])
}

func emergencyReasonDigest(reason string) string {
	digest := sha256.Sum256([]byte(strings.TrimSpace(reason)))
	return hex.EncodeToString(digest[:])
}

func writeAuditUnavailable(w http.ResponseWriter, loggerError func(error), err error) {
	if loggerError != nil {
		loggerError(err)
	}
	setNoStore(w)
	writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "security audit unavailable"})
}

type auditResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *auditResponseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *auditResponseWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(data)
}

func (w *auditResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *auditResponseWriter) Status() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

func auditResultForStatus(status int) string {
	if status >= 200 && status < 400 {
		return "success"
	}
	return "failure"
}

func statusContext(status int, permission adminauth.Permission, principal adminauth.Principal, emergencyReason string) map[string]string {
	values := map[string]string{
		"status_code": strconv.Itoa(status), "permission": string(permission), "auth_method": string(principal.AuthMethod),
	}
	if principal.Emergency {
		values["emergency"] = "true"
		values["emergency_reason_digest"] = emergencyReasonDigest(emergencyReason)
	}
	return values
}
