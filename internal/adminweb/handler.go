package adminweb

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog"
	trustconfig "github.com/ryan-wong-coder/trustdb/internal/config"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
)

// Options configures the admin HTTP subtree.
type Options struct {
	Admin        trustconfig.Admin
	Viper        *viper.Viper
	ConfigPath   string
	EffectiveCfg trustconfig.Config
	Public       http.Handler
	Metrics      http.Handler
	Logger       zerolog.Logger
}

type handler struct {
	opts Options
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
	h := &handler{opts: opts}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/session", h.getSession)
	mux.HandleFunc("POST /api/session", h.postSession)
	mux.HandleFunc("DELETE /api/session", h.deleteSession)
	mux.Handle("GET /api/metrics", h.withAuth(http.HandlerFunc(h.getMetricsJSON)))
	mux.Handle("GET /api/config", h.withAuth(http.HandlerFunc(h.getConfig)))
	mux.Handle("GET /api/config/raw", h.withAuth(http.HandlerFunc(h.getConfigRaw)))
	mux.Handle("PUT /api/config", h.withAuth(http.HandlerFunc(h.putConfig)))
	mux.Handle("GET /api/overlays", h.withAuth(http.HandlerFunc(h.getOverlays)))

	proxy := http.StripPrefix("/api/proxy", getOnlyHandler{h: opts.Public})
	mux.Handle("/api/proxy/", h.withAuth(proxy))

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
	if u, ok := h.authedUser(r); ok {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "username": u})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": false})
}

type loginBody struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

const (
	maxLoginBodyBytes  int64 = 1 << 20
	maxConfigBodyBytes int64 = 4 << 20
)

var errRequestBodyTooLarge = errors.New("request body too large")

func (h *handler) postSession(w http.ResponseWriter, r *http.Request) {
	var body loginBody
	if err := decodeJSONBodyLimit(r.Body, &body, maxLoginBodyBytes); err != nil {
		if errors.Is(err, errRequestBodyTooLarge) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"ok": false, "error": "request too large"})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid json"})
		return
	}
	wantUser := strings.TrimSpace(h.opts.Admin.Username)
	if subtleStringEq(wantUser, strings.TrimSpace(body.Username)) != 1 {
		// still run bcrypt to reduce user enumeration timing a little
		_ = bcrypt.CompareHashAndPassword([]byte(h.opts.Admin.PasswordHash), []byte("invalid"))
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "unauthorized"})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(h.opts.Admin.PasswordHash), []byte(body.Password)); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "unauthorized"})
		return
	}
	ttl := sessionTTL(h.opts.Admin.SessionTTL)
	token, err := issueSessionToken([]byte(h.opts.Admin.SessionSecret), wantUser, ttl)
	if err != nil {
		h.opts.Logger.Error().Err(err).Msg("admin session issue failed")
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "internal"})
		return
	}
	w.Header().Set("Set-Cookie", buildSessionCookie(h.opts.Admin.BasePath, token, h.opts.Admin.CookieSecure, ttl))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func subtleStringEq(a, b string) int {
	if len(a) != len(b) {
		return 0
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	if v == 0 {
		return 1
	}
	return 0
}

func (h *handler) deleteSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Set-Cookie", clearSessionCookie(h.opts.Admin.BasePath, h.opts.Admin.CookieSecure))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *handler) authedUser(r *http.Request) (string, bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return "", false
	}
	return verifySessionToken([]byte(h.opts.Admin.SessionSecret), c.Value)
}

func (h *handler) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := h.authedUser(r); !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
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
	cfg := trustconfig.FromViper(v2)
	if err := cfg.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	backup := ""
	prev, err := readConfigFile(h.opts.ConfigPath)
	switch {
	case err == nil && len(prev) > 0:
		backup, err = writeConfigBackup(h.opts.ConfigPath, prev)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": fmt.Sprintf("backup: %v", err)})
			return
		}
	case errors.Is(err, errRequestBodyTooLarge):
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"ok": false, "error": "existing config file too large"})
		return
	case err != nil && !os.IsNotExist(err):
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": fmt.Sprintf("read existing config: %v", err)})
		return
	}
	if err := writeConfigAtomic(h.opts.ConfigPath, body); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	h.opts.Logger.Info().Str("path", h.opts.ConfigPath).Str("backup", backup).Msg("admin wrote config file")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "backup": backup})
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
