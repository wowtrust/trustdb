package statusnotify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/wowtrust/trustdb/internal/model"
)

const SchemaNotificationRoutes = "trustdb.status-notification-routes.v1"

type routeBinding struct {
	TenantID string                          `json:"tenant_id"`
	ClientID string                          `json:"client_id"`
	Route    model.UpstreamNotificationRoute `json:"route"`
}

type persistedRoutes struct {
	SchemaVersion string         `json:"schema_version"`
	Routes        []routeBinding `json:"routes"`
}

// RouteStore keeps administrator-controlled delivery destinations separate
// from the signed Key Registry V2 evidence format. A route is scoped to an
// upstream identity, so every key for the same tenant/client uses the same
// webhook and NATS queue group.
type RouteStore struct {
	mu     sync.RWMutex
	path   string
	routes map[string]model.UpstreamNotificationRoute
}

// RouteStorePath derives the operator-only sidecar path for a key registry.
func RouteStorePath(registryPath string) string {
	registryPath = strings.TrimSpace(registryPath)
	if registryPath == "" {
		return ""
	}
	return registryPath + ".status-routes.json"
}

func OpenRouteStore(path string) (*RouteStore, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("statusnotify: route store path is required")
	}
	store := &RouteStore{
		path:   path,
		routes: make(map[string]model.UpstreamNotificationRoute),
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("statusnotify: read route store: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var persisted persistedRoutes
	if err := decoder.Decode(&persisted); err != nil {
		return nil, fmt.Errorf("statusnotify: decode route store: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, fmt.Errorf("statusnotify: decode route store: %w", err)
	}
	if persisted.SchemaVersion != SchemaNotificationRoutes {
		return nil, fmt.Errorf("statusnotify: route store schema must be %s", SchemaNotificationRoutes)
	}
	for _, binding := range persisted.Routes {
		tenantID, clientID, route, err := normalizeRouteBinding(binding.TenantID, binding.ClientID, binding.Route)
		if err != nil {
			return nil, err
		}
		key := routeIdentity(tenantID, clientID)
		if _, exists := store.routes[key]; exists {
			return nil, fmt.Errorf("statusnotify: duplicate route for %s/%s", tenantID, clientID)
		}
		store.routes[key] = route
	}
	return store, nil
}

// Configure adds one immutable route for an upstream. Repeating the exact
// configuration is idempotent; changing an existing upstream route is
// rejected so a key rotation cannot silently redirect notifications.
func (s *RouteStore) Configure(tenantID, clientID string, route model.UpstreamNotificationRoute) error {
	tenantID, clientID, route, err := normalizeRouteBinding(tenantID, clientID, route)
	if err != nil {
		return err
	}
	if route.Empty() {
		return errors.New("statusnotify: at least one webhook or NATS route is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	key := routeIdentity(tenantID, clientID)
	if existing, found := s.routes[key]; found {
		if existing == route {
			return nil
		}
		return fmt.Errorf("statusnotify: notification route already configured for %s/%s", tenantID, clientID)
	}
	s.routes[key] = route
	if err := s.persistLocked(); err != nil {
		delete(s.routes, key)
		return err
	}
	return nil
}

func (s *RouteStore) Lookup(tenantID, clientID string) (model.UpstreamNotificationRoute, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	route, found := s.routes[routeIdentity(strings.TrimSpace(tenantID), strings.TrimSpace(clientID))]
	return route, found
}

func (s *RouteStore) Path() string {
	return s.path
}

func (s *RouteStore) persistLocked() error {
	bindings := make([]routeBinding, 0, len(s.routes))
	for identity, route := range s.routes {
		tenantID, clientID, _ := strings.Cut(identity, "\x00")
		bindings = append(bindings, routeBinding{TenantID: tenantID, ClientID: clientID, Route: route})
	}
	sort.Slice(bindings, func(i, j int) bool {
		if bindings[i].TenantID != bindings[j].TenantID {
			return bindings[i].TenantID < bindings[j].TenantID
		}
		return bindings[i].ClientID < bindings[j].ClientID
	})
	data, err := json.MarshalIndent(persistedRoutes{SchemaVersion: SchemaNotificationRoutes, Routes: bindings}, "", "  ")
	if err != nil {
		return fmt.Errorf("statusnotify: encode route store: %w", err)
	}
	data = append(data, '\n')
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("statusnotify: create route store directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(s.path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("statusnotify: create route store temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	closed := false
	defer func() {
		if !closed {
			_ = tmp.Close()
		}
		_ = os.Remove(tmpPath)
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("statusnotify: protect route store temporary file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("statusnotify: write route store: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("statusnotify: sync route store: %w", err)
	}
	if err := tmp.Close(); err != nil {
		closed = true
		return fmt.Errorf("statusnotify: close route store: %w", err)
	}
	closed = true
	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("statusnotify: replace route store: %w", err)
	}
	return nil
}

func normalizeRouteBinding(tenantID, clientID string, route model.UpstreamNotificationRoute) (string, string, model.UpstreamNotificationRoute, error) {
	tenantID = strings.TrimSpace(tenantID)
	clientID = strings.TrimSpace(clientID)
	if tenantID == "" || clientID == "" || strings.ContainsRune(tenantID, '\x00') || strings.ContainsRune(clientID, '\x00') {
		return "", "", model.UpstreamNotificationRoute{}, errors.New("statusnotify: tenant_id and client_id are required")
	}
	route.WebhookURL = strings.TrimSpace(route.WebhookURL)
	route.NATSSubject = strings.TrimSpace(route.NATSSubject)
	route.NATSQueueGroup = strings.TrimSpace(route.NATSQueueGroup)
	if route.WebhookURL != "" {
		parsed, err := url.Parse(route.WebhookURL)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return "", "", model.UpstreamNotificationRoute{}, errors.New("statusnotify: webhook URL must be an absolute http(s) URL")
		}
		if parsed.User != nil {
			return "", "", model.UpstreamNotificationRoute{}, errors.New("statusnotify: webhook URL must not contain credentials")
		}
	}
	if (route.NATSSubject == "") != (route.NATSQueueGroup == "") {
		return "", "", model.UpstreamNotificationRoute{}, errors.New("statusnotify: NATS subject and queue group must be configured together")
	}
	if route.NATSSubject != "" && !validNATSName(route.NATSSubject) {
		return "", "", model.UpstreamNotificationRoute{}, errors.New("statusnotify: NATS subject must be concrete and contain no wildcards, whitespace, or empty tokens")
	}
	if route.NATSQueueGroup != "" && !validNATSName(route.NATSQueueGroup) {
		return "", "", model.UpstreamNotificationRoute{}, errors.New("statusnotify: NATS queue group must contain no wildcards, whitespace, or empty tokens")
	}
	return tenantID, clientID, route, nil
}

func validNATSName(value string) bool {
	if value == "" || strings.ContainsAny(value, "*>") || strings.IndexFunc(value, unicode.IsSpace) >= 0 {
		return false
	}
	for _, token := range strings.Split(value, ".") {
		if token == "" {
			return false
		}
	}
	return true
}

func routeIdentity(tenantID, clientID string) string {
	return tenantID + "\x00" + clientID
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}
	return errors.New("unexpected trailing JSON value")
}

// StoredRouteResolver combines the signed key registry used for request
// authentication with the separate operator-controlled route sidecar.
type StoredRouteResolver struct {
	keys   ClientKeyResolver
	routes *RouteStore
}

type ClientKeyResolver interface {
	LookupClientKeyAt(tenantID, clientID, keyID string, at time.Time) (model.ClientKey, error)
}

func NewStoredRouteResolver(keys ClientKeyResolver, routes *RouteStore) (*StoredRouteResolver, error) {
	if keys == nil {
		return nil, errors.New("statusnotify: client key resolver is required")
	}
	if routes == nil {
		return nil, errors.New("statusnotify: route store is required")
	}
	return &StoredRouteResolver{keys: keys, routes: routes}, nil
}

func (r *StoredRouteResolver) LookupNotificationRoute(tenantID, clientID, _ string) (model.UpstreamNotificationRoute, bool) {
	return r.routes.Lookup(tenantID, clientID)
}

func (r *StoredRouteResolver) LookupClientKeyAt(tenantID, clientID, keyID string, at time.Time) (model.ClientKey, error) {
	return r.keys.LookupClientKeyAt(tenantID, clientID, keyID, at)
}
