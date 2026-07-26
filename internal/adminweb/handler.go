package adminweb

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/spf13/viper"
	"github.com/wowtrust/trustdb/v2/internal/adminauth"
	trustconfig "github.com/wowtrust/trustdb/v2/internal/config"
	"github.com/wowtrust/trustdb/v2/internal/securityaudit"
)

type MFAVerifier interface {
	VerifyMFA(context.Context, adminauth.Principal, string) error
}

type OIDCIdentity struct {
	Issuer  string
	Subject string
	MFA     bool
}

type OIDCVerifier interface {
	VerifyOIDC(*http.Request) (OIDCIdentity, error)
}

// Options configures the admin HTTP subtree.
type Options struct {
	Admin        trustconfig.Admin
	Viper        *viper.Viper
	ConfigPath   string
	EffectiveCfg trustconfig.Config
	Public       http.Handler
	Metrics      http.Handler
	Logger       zerolog.Logger
	Auth         *adminauth.Manager
	PolicyStore  *adminauth.FileStore
	MFAVerifier  MFAVerifier
	OIDCVerifier OIDCVerifier
	Auditor      securityaudit.Recorder
	Now          func() time.Time
}

type handler struct {
	opts     Options
	guard    *loginGuard
	policyMu sync.RWMutex
	configMu sync.Mutex
}

// New returns the admin subtree handler (paths relative to admin base, e.g. /api/...).
func New(opts Options) (http.Handler, error) {
	if !opts.Admin.Enabled {
		return nil, errors.New("adminweb.New called with admin disabled")
	}
	webDir := strings.TrimSpace(opts.Admin.WebDir)
	st, err := os.Stat(filepath.Join(webDir, "index.html"))
	if err != nil || st.IsDir() {
		return nil, fmt.Errorf("admin.web_dir must contain index.html: %w", err)
	}
	if opts.Viper == nil {
		return nil, errors.New("adminweb.Options.Viper is required")
	}
	if opts.Public == nil {
		return nil, errors.New("adminweb.Options.Public is required")
	}
	if opts.Metrics == nil {
		return nil, errors.New("adminweb.Options.Metrics is required")
	}
	if opts.Auth == nil || opts.PolicyStore == nil {
		return nil, errors.New("adminweb.Options.Auth and PolicyStore are required")
	}
	if opts.EffectiveCfg.Audit.Required && opts.Auditor == nil {
		return nil, errors.New("adminweb.Options.Auditor is required by audit policy")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	_, managerDigest := opts.Auth.Snapshot()
	_, storedDigest, err := opts.PolicyStore.Load(opts.Now())
	if err != nil {
		return nil, fmt.Errorf("load admin policy store: %w", err)
	}
	if managerDigest != storedDigest {
		return nil, errors.New("adminweb: authorization manager and policy store do not match")
	}
	h := &handler{opts: opts, guard: newLoginGuard(opts.Admin.LoginMaxFailures, loginLockout(opts.Admin.LoginLockout))}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/session", h.getSession)
	mux.HandleFunc("POST /api/session", h.postSession)
	mux.HandleFunc("DELETE /api/session", h.deleteSession)
	mux.Handle("GET /api/metrics", h.withPermission(adminauth.PermissionSystemRead, http.HandlerFunc(h.getMetricsJSON)))
	mux.Handle("GET /api/config", h.withPermission(adminauth.PermissionSystemRead, http.HandlerFunc(h.getConfig)))
	mux.Handle("GET /api/config/raw", h.withPermission(adminauth.PermissionSystemRead, http.HandlerFunc(h.getConfigRaw)))
	mux.Handle("PUT /api/config", h.withPermission(adminauth.PermissionSystemConfigure, http.HandlerFunc(h.putConfig)))
	mux.Handle("GET /api/overlays", h.withPermission(adminauth.PermissionSystemRead, http.HandlerFunc(h.getOverlays)))
	mux.Handle("GET /api/security/policy", h.withPermission(adminauth.PermissionSecurityPolicyRead, http.HandlerFunc(h.getPolicy)))
	mux.Handle("PUT /api/security/policy", h.withExclusivePermission(adminauth.PermissionSecurityPolicyWrite, http.HandlerFunc(h.putPolicy)))

	proxy := http.StripPrefix("/api/proxy", getOnlyHandler{h: opts.Public})
	mux.Handle("/api/proxy/", h.withPermission(adminauth.PermissionSystemRead, proxy))

	mux.Handle("/", spaFileServer(webDir))
	return mux, nil
}

type getOnlyHandler struct{ h http.Handler }

func (g getOnlyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	g.h.ServeHTTP(w, r)
}

func (h *handler) getSession(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	if principal, _, err := h.authenticatedPrincipal(r); err == nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "principal": principal})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": false})
}

type loginBody struct {
	Username        string `json:"username"`
	Password        string `json:"password"`
	MFACode         string `json:"mfa_code,omitempty"`
	EmergencyReason string `json:"emergency_reason,omitempty"`
}

const (
	maxLoginBodyBytes  int64 = 1 << 20
	maxConfigBodyBytes int64 = 4 << 20
)

var errRequestBodyTooLarge = errors.New("request body too large")

func (h *handler) postSession(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	_, r = h.requestID(w, r)
	auditLogin := func(principal adminauth.Principal, result, reason string) bool {
		if err := h.recordHTTPAudit(r, principal, "admin.login", result, map[string]string{"auth_method": "local-password", "reason": reason}); err != nil {
			writeAuditUnavailable(w, func(err error) { h.opts.Logger.Error().Err(err).Msg("security audit login write failed") }, err)
			return false
		}
		return true
	}
	var body loginBody
	if err := decodeJSONBodyLimit(r.Body, &body, maxLoginBodyBytes); err != nil {
		if !auditLogin(adminauth.Principal{}, "failure", "invalid-request") {
			return
		}
		if errors.Is(err, errRequestBodyTooLarge) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"ok": false, "error": "request too large"})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid json"})
		return
	}
	now := h.opts.Now()
	username := strings.TrimSpace(body.Username)
	if !h.guard.Allow(username, now) {
		if !auditLogin(adminauth.Principal{AccountID: username}, "denied", "locked") {
			return
		}
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"ok": false, "error": "login temporarily locked"})
		return
	}
	principal, err := h.opts.Auth.AuthenticateLocal(username, body.Password, now)
	if err != nil {
		h.guard.Failure(username, now)
		if !auditLogin(adminauth.Principal{AccountID: username}, "denied", "invalid-credentials") {
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "unauthorized"})
		return
	}
	if principal.MFARequired {
		if h.opts.MFAVerifier == nil || h.opts.MFAVerifier.VerifyMFA(r.Context(), principal, strings.TrimSpace(body.MFACode)) != nil {
			h.guard.Failure(username, now)
			if !auditLogin(principal, "denied", "mfa-failed") {
				return
			}
			writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "multi-factor authentication required"})
			return
		}
	}
	reason := strings.TrimSpace(body.EmergencyReason)
	if principal.Emergency && !validEmergencyReason(reason) {
		h.guard.Failure(username, now)
		if !auditLogin(principal, "denied", "emergency-reason-invalid") {
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "emergency access requires a 12..512 character reason"})
		return
	}
	h.guard.Success(username)
	ttl := sessionTTL(h.opts.Admin.SessionTTL)
	if !auditLogin(principal, "success", "authenticated") {
		return
	}
	token, err := issueSessionTokenAt([]byte(h.opts.Admin.SessionSecret), principal, reason, ttl, now)
	if err != nil {
		_ = h.recordHTTPAudit(r, principal, "admin.session.issue", "failure", map[string]string{"auth_method": string(principal.AuthMethod)})
		h.opts.Logger.Error().Err(err).Msg("admin session issue failed")
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "internal"})
		return
	}
	w.Header().Set("Set-Cookie", buildSessionCookie(h.opts.Admin.BasePath, token, h.opts.Admin.CookieSecure, ttl))
	h.opts.Logger.Info().Str("actor", principal.AccountID).Str("auth_method", string(principal.AuthMethod)).Bool("emergency", principal.Emergency).Msg("admin session issued")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "principal": principal})
}

func (h *handler) deleteSession(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	_, r = h.requestID(w, r)
	principal, _, _ := h.authenticatedPrincipal(r)
	if err := h.recordHTTPAudit(r, principal, "admin.logout", "success", nil); err != nil {
		writeAuditUnavailable(w, func(err error) { h.opts.Logger.Error().Err(err).Msg("security audit logout write failed") }, err)
		return
	}
	w.Header().Set("Set-Cookie", clearSessionCookie(h.opts.Admin.BasePath, h.opts.Admin.CookieSecure))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

type actorContextKey struct{}

func (h *handler) authenticatedPrincipal(r *http.Request) (adminauth.Principal, string, error) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil && cookie.Value != "" {
		principal, reason, ok := verifySessionToken([]byte(h.opts.Admin.SessionSecret), cookie.Value)
		if !ok {
			return adminauth.Principal{}, "", adminauth.ErrUnauthenticated
		}
		current, err := h.opts.Auth.ValidatePrincipal(principal, h.opts.Now())
		return current, reason, err
	}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		principal, err := h.opts.Auth.AuthenticateMTLS(r.TLS.PeerCertificates[0], h.opts.Now())
		if err == nil && !principal.MFARequired {
			reason := strings.TrimSpace(r.Header.Get("X-TrustDB-Emergency-Reason"))
			if principal.Emergency && !validEmergencyReason(reason) {
				return adminauth.Principal{}, "", adminauth.ErrUnauthenticated
			}
			return principal, reason, nil
		}
	}
	if h.opts.OIDCVerifier != nil {
		identity, err := h.opts.OIDCVerifier.VerifyOIDC(r)
		if err == nil {
			principal, authErr := h.opts.Auth.AuthenticateOIDC(identity.Issuer, identity.Subject, h.opts.Now())
			if authErr == nil && (!principal.MFARequired || identity.MFA) {
				reason := strings.TrimSpace(r.Header.Get("X-TrustDB-Emergency-Reason"))
				if !principal.Emergency || validEmergencyReason(reason) {
					return principal, reason, nil
				}
			}
		}
	}
	return adminauth.Principal{}, "", adminauth.ErrUnauthenticated
}

func (h *handler) withPermission(permission adminauth.Permission, next http.Handler) http.Handler {
	return h.withPermissionLock(permission, next, false)
}

func (h *handler) withExclusivePermission(permission adminauth.Permission, next http.Handler) http.Handler {
	return h.withPermissionLock(permission, next, true)
}

func (h *handler) withPermissionLock(permission adminauth.Permission, next http.Handler, exclusive bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		_, r = h.requestID(w, r)
		if exclusive {
			h.policyMu.Lock()
			defer h.policyMu.Unlock()
		} else {
			h.policyMu.RLock()
			defer h.policyMu.RUnlock()
		}
		principal, emergencyReason, err := h.authenticatedPrincipal(r)
		if err != nil {
			if auditErr := h.recordHTTPAudit(r, adminauth.Principal{}, "admin.authentication", "denied", map[string]string{"permission": string(permission)}); auditErr != nil {
				writeAuditUnavailable(w, func(err error) { h.opts.Logger.Error().Err(err).Msg("security audit write failed") }, auditErr)
				return
			}
			writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "unauthorized"})
			return
		}
		authorized, err := h.opts.Auth.Authorize(principal, permission, h.opts.Now())
		if err != nil {
			if auditErr := h.recordHTTPAudit(r, principal, "admin.authorization", "denied", statusContext(http.StatusForbidden, permission, principal, emergencyReason)); auditErr != nil {
				writeAuditUnavailable(w, func(err error) { h.opts.Logger.Error().Err(err).Msg("security audit write failed") }, auditErr)
				return
			}
			h.opts.Logger.Warn().Str("actor", principal.AccountID).Str("permission", string(permission)).Msg("admin authorization denied")
			writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "forbidden"})
			return
		}
		principal = authorized
		if auditErr := h.recordHTTPAudit(r, principal, "admin.authorization", "authorized", statusContext(http.StatusOK, permission, principal, emergencyReason)); auditErr != nil {
			writeAuditUnavailable(w, func(err error) { h.opts.Logger.Error().Err(err).Msg("security audit write failed") }, auditErr)
			return
		}
		event := h.opts.Logger.Info().Str("actor", principal.AccountID).Str("permission", string(permission)).Str("method", r.Method).Str("path", r.URL.Path).Str("auth_method", string(principal.AuthMethod)).Bool("emergency", principal.Emergency)
		if principal.Emergency {
			event = event.Str("emergency_reason_digest", emergencyReasonDigest(emergencyReason))
		}
		event.Msg("admin request authorized")
		ctx := context.WithValue(r.Context(), actorContextKey{}, principal)
		ctx = context.WithValue(ctx, emergencyReasonContextKey{}, emergencyReason)
		r = r.WithContext(ctx)
		captured := &auditResponseWriter{ResponseWriter: w}
		next.ServeHTTP(captured, r)
		if auditErr := h.recordHTTPAudit(r.WithContext(context.WithoutCancel(r.Context())), principal, "admin.request", auditResultForStatus(captured.Status()), statusContext(captured.Status(), permission, principal, emergencyReason)); auditErr != nil {
			h.opts.Logger.Error().Err(auditErr).Msg("security audit outcome write failed")
		}
	})
}

func setNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

type emergencyReasonContextKey struct{}

func actorFromContext(ctx context.Context) adminauth.Principal {
	principal, _ := ctx.Value(actorContextKey{}).(adminauth.Principal)
	return principal
}

func validEmergencyReason(reason string) bool {
	length := len(strings.TrimSpace(reason))
	return length >= 12 && length <= 512
}

func (h *handler) getMetricsJSON(w http.ResponseWriter, r *http.Request) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(r.Context(), http.MethodGet, "/metrics", nil)
	h.opts.Metrics.ServeHTTP(rr, req)
	if rr.Code < 200 || rr.Code >= 300 {
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": "metrics unavailable"})
		return
	}
	metrics := ParseMetricsText(rr.Body.String())
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "metrics": metrics})
}

func (h *handler) getConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"config":      h.opts.EffectiveCfg.Redacted(),
		"config_path": h.opts.ConfigPath,
		"notes": []string{
			"Most fields require restarting trustdb serve to take effect.",
			"Use GET /admin/api/config/raw to fetch the on-disk YAML when --config is set.",
		},
	})
}

func (h *handler) getPolicy(w http.ResponseWriter, r *http.Request) {
	policy, digest := h.opts.Auth.Snapshot()
	w.Header().Set("ETag", `"`+digest+`"`)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "policy": policy, "digest": digest,
		"warning": "password_hash values are credential verifiers; handle this response as sensitive",
	})
}

func (h *handler) putPolicy(w http.ResponseWriter, r *http.Request) {
	expected := strings.Trim(strings.TrimSpace(r.Header.Get("If-Match")), `"`)
	if expected == "" {
		writeJSON(w, http.StatusPreconditionRequired, map[string]any{"ok": false, "error": "If-Match policy digest is required"})
		return
	}
	body, err := readBodyLimit(r.Body, adminauth.MaxPolicyBytes)
	if err != nil {
		if errors.Is(err, errRequestBodyTooLarge) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"ok": false, "error": "policy too large"})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "read body"})
		return
	}
	next, err := adminauth.ParsePolicy(body, h.opts.Now())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	actor := actorFromContext(r.Context())
	digest, err := h.opts.PolicyStore.ReplaceOnline(actor, expected, next, h.opts.Now())
	if err != nil {
		switch {
		case errors.Is(err, adminauth.ErrPolicyConflict):
			writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": "policy changed; reload and retry"})
		case errors.Is(err, adminauth.ErrPermissionDenied):
			writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "forbidden"})
		default:
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		}
		return
	}
	if err := h.opts.Auth.Replace(next, h.opts.Now()); err != nil {
		h.opts.Logger.Error().Err(err).Msg("persisted admin policy could not be activated")
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "policy persisted but activation failed; restart required"})
		return
	}
	h.opts.Logger.Info().Str("actor", actor.AccountID).Uint64("policy_version", next.Version).Str("policy_digest", digest).Msg("admin policy replaced")
	if err := h.recordHTTPAudit(r, actor, "security.policy.update", "success", map[string]string{"policy_digest": digest, "new_policy_version": fmt.Sprint(next.Version)}); err != nil {
		writeAuditUnavailable(w, func(err error) { h.opts.Logger.Error().Err(err).Msg("security audit policy result write failed") }, err)
		return
	}
	w.Header().Set("ETag", `"`+digest+`"`)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": next.Version, "digest": digest})
}

func (h *handler) getConfigRaw(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(h.opts.ConfigPath) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "no --config path; raw file API disabled"})
		return
	}
	b, err := readConfigFile(h.opts.ConfigPath)
	if err != nil {
		if errors.Is(err, errRequestBodyTooLarge) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"ok": false, "error": "config file too large"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/x-yaml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

func (h *handler) putConfig(w http.ResponseWriter, r *http.Request) {
	h.configMu.Lock()
	defer h.configMu.Unlock()

	if strings.TrimSpace(h.opts.ConfigPath) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "no --config path; cannot write"})
		return
	}
	body, err := readBodyLimit(r.Body, maxConfigBodyBytes)
	if err != nil {
		if errors.Is(err, errRequestBodyTooLarge) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"ok": false, "error": "request too large"})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "read body"})
		return
	}
	v2 := viper.New()
	v2.SetConfigType("yaml")
	if err := v2.ReadConfig(bytes.NewReader(body)); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": fmt.Sprintf("yaml: %v", err)})
		return
	}
	previous, err := readConfigFile(h.opts.ConfigPath)
	switch {
	case errors.Is(err, errRequestBodyTooLarge):
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"ok": false, "error": "existing config file too large"})
		return
	case err != nil && !os.IsNotExist(err):
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": fmt.Sprintf("read existing config: %v", err)})
		return
	}
	protectedChanged, err := protectedConfigChanged(previous, v2)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": fmt.Sprintf("read existing admin config: %v", err)})
		return
	}
	if protectedChanged {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok": false, "error": "admin authorization, security audit, and deployment policy settings cannot be changed through the generic config endpoint",
		})
		return
	}
	cfg := trustconfig.FromViper(v2)
	if err := cfg.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	backup := ""
	if len(previous) > 0 {
		backup, err = writeConfigBackup(h.opts.ConfigPath, previous)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": fmt.Sprintf("backup: %v", err)})
			return
		}
	}
	if err := writeConfigAtomic(h.opts.ConfigPath, body); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	actor := actorFromContext(r.Context())
	h.opts.Logger.Info().Str("actor", actor.AccountID).Str("path", h.opts.ConfigPath).Str("backup", backup).Msg("admin wrote config file")
	if err := h.recordHTTPAudit(r, actor, "system.configuration.update", "success", map[string]string{"config_path": h.opts.ConfigPath, "backup_path": backup}); err != nil {
		writeAuditUnavailable(w, func(err error) { h.opts.Logger.Error().Err(err).Msg("security audit config result write failed") }, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "backup": backup})
}

func protectedConfigChanged(previous []byte, next *viper.Viper) (bool, error) {
	var currentAdmin, currentAudit, currentDeploymentPolicy, currentRunProfile any
	if len(previous) > 0 {
		current := viper.New()
		current.SetConfigType("yaml")
		if err := current.ReadConfig(bytes.NewReader(previous)); err != nil {
			return false, err
		}
		currentAdmin = current.AllSettings()["admin"]
		currentAudit = current.AllSettings()["audit"]
		currentDeploymentPolicy = current.AllSettings()["deployment_policy"]
		currentRunProfile = current.AllSettings()["run_profile"]
	}
	nextSettings := next.AllSettings()
	auditChanged := !reflect.DeepEqual(currentAudit, nextSettings["audit"])
	if currentAudit == nil && !auditSectionEnabled(nextSettings["audit"]) {
		auditChanged = false
	}
	deploymentPolicyChanged := !reflect.DeepEqual(
		currentDeploymentPolicy,
		nextSettings["deployment_policy"],
	)
	if currentDeploymentPolicy == nil &&
		defaultDeploymentPolicy(trustconfig.FromViper(next).DeploymentPolicy) {
		deploymentPolicyChanged = false
	}
	return !reflect.DeepEqual(currentAdmin, nextSettings["admin"]) ||
		auditChanged ||
		deploymentPolicyChanged ||
		!reflect.DeepEqual(currentRunProfile, nextSettings["run_profile"]), nil
}

func defaultDeploymentPolicy(policy trustconfig.DeploymentPolicy) bool {
	return strings.EqualFold(
		strings.TrimSpace(policy.EgressMode),
		trustconfig.EgressUnrestricted,
	) &&
		len(policy.AllowedEndpoints) == 0 &&
		len(policy.DNSAllowlist) == 0 &&
		!policy.TelemetryEnabled &&
		!policy.UpdateChecksEnabled &&
		len(policy.Exceptions) == 0
}

func auditSectionEnabled(value any) bool {
	section, ok := value.(map[string]any)
	if !ok {
		return false
	}
	enabled, _ := section["enabled"].(bool)
	required, _ := section["required"].(bool)
	return enabled || required
}

func readConfigFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readBodyLimit(f, maxConfigBodyBytes)
}

func writeConfigBackup(configPath string, data []byte) (string, error) {
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, filepath.Base(configPath)+".bak.*")
	if err != nil {
		return "", err
	}
	path := f.Name()
	cleanup := true
	defer func() {
		_ = f.Close()
		if cleanup {
			_ = os.Remove(path)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	cleanup = false
	return path, nil
}

func writeConfigAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := f.Name()
	cleanup := true
	defer func() {
		_ = f.Close()
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := renameReplace(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func renameReplace(src, dst string) error {
	if err := rejectDirectoryTarget(dst); err != nil {
		return err
	}
	if err := os.Rename(src, dst); err != nil {
		if os.IsExist(err) {
			if removeErr := os.Remove(dst); removeErr == nil {
				return os.Rename(src, dst)
			}
		}
		return err
	}
	return nil
}

func rejectDirectoryTarget(path string) error {
	info, err := os.Stat(path)
	if err == nil {
		if info.IsDir() {
			return fmt.Errorf("%s is a directory", path)
		}
		return nil
	}
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func (h *handler) getOverlays(w http.ResponseWriter, r *http.Request) {
	v := h.opts.Viper
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"overlays": map[string]any{
			"server": map[string]any{
				"grpc_listen": strings.TrimSpace(v.GetString("server.grpc_listen")),
			},
			"metastore":      strings.TrimSpace(v.GetString("metastore")),
			"metastore_path": strings.TrimSpace(v.GetString("metastore_path")),
			"anchor": map[string]any{
				"sink": strings.TrimSpace(v.GetString("anchor.sink")),
				"path": strings.TrimSpace(v.GetString("anchor.path")),
			},
		},
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeJSONBodyLimit(r io.Reader, v any, maxBytes int64) error {
	body, err := readBodyLimit(r, maxBytes)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return errors.New("trailing json data")
	} else if err != io.EOF {
		return err
	}
	return nil
}

func readBodyLimit(r io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, errors.New("max bytes must be positive")
	}
	body, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, errRequestBodyTooLarge
	}
	return body, nil
}

type spaHandler struct {
	root string
}

func spaFileServer(root string) http.Handler {
	return spaHandler{root: root}
}

func (h spaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name, ok := spaRelativePath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	root, err := os.OpenRoot(h.root)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer root.Close()
	if name != "" {
		served, exists := serveRootFile(w, r, root, name)
		if served {
			return
		}
		if exists {
			http.NotFound(w, r)
			return
		}
	}
	if served, _ := serveRootFile(w, r, root, "index.html"); served {
		return
	}
	http.NotFound(w, r)
}

func spaRelativePath(urlPath string) (string, bool) {
	if strings.Contains(urlPath, `\`) {
		return "", false
	}
	clean := path.Clean(strings.TrimPrefix(urlPath, "/"))
	if clean == "." {
		return "", true
	}
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false
	}
	return filepath.FromSlash(clean), true
}

func serveRootFile(w http.ResponseWriter, r *http.Request, root *os.Root, name string) (served, exists bool) {
	f, err := root.Open(name)
	if err != nil {
		_, statErr := root.Lstat(name)
		return false, statErr == nil
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		return false, true
	}
	http.ServeContent(w, r, filepath.Base(name), st.ModTime(), f)
	return true, true
}
