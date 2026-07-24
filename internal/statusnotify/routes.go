package statusnotify

import (
	"bytes"
	"context"
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

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
)

const SchemaNotificationRoutes = "trustdb.status-notification-routes.v1"

type routeBinding struct {
	TenantID string                          `cbor:"tenant_id" json:"tenant_id"`
	ClientID string                          `cbor:"client_id" json:"client_id"`
	Route    model.UpstreamNotificationRoute `cbor:"route" json:"route"`
}

type routeSnapshot struct {
	SchemaVersion string         `cbor:"schema_version" json:"schema_version"`
	CryptoSuite   cryptosuite.ID `cbor:"crypto_suite" json:"crypto_suite"`
	RegistryKeyID string         `cbor:"registry_key_id" json:"registry_key_id"`
	Routes        []routeBinding `cbor:"routes" json:"routes"`
}

type persistedRoutes struct {
	SchemaVersion     string          `json:"schema_version"`
	CryptoSuite       cryptosuite.ID  `json:"crypto_suite"`
	RegistryKeyID     string          `json:"registry_key_id"`
	Routes            []routeBinding  `json:"routes"`
	RegistrySignature model.Signature `json:"registry_signature"`
}

func (p persistedRoutes) snapshot() routeSnapshot {
	return routeSnapshot{
		SchemaVersion: p.SchemaVersion,
		CryptoSuite:   p.CryptoSuite,
		RegistryKeyID: p.RegistryKeyID,
		Routes:        append([]routeBinding(nil), p.Routes...),
	}
}

// RouteStore keeps administrator-controlled delivery destinations separate
// from the Key Registry V2 event format. The registry signer signs the entire
// sidecar snapshot, and serve verifies it with the same external registry
// trust root before accepting any route.
type RouteStore struct {
	mu          sync.RWMutex
	path        string
	signer      trustcrypto.Signer
	registryPub trustcrypto.PublicKeyDescriptor
	routes      map[string]model.UpstreamNotificationRoute
}

// RouteStorePath derives the signed sidecar path for a key registry.
func RouteStorePath(registryPath string) string {
	registryPath = strings.TrimSpace(registryPath)
	if registryPath == "" {
		return ""
	}
	return registryPath + ".status-routes.json"
}

// OpenRouteStore opens a route snapshot under the registry trust root. A
// signer is required only for Configure; read-only serve processes pass nil.
// Existing sidecars always require a valid registry signature.
func OpenRouteStore(path string, signer trustcrypto.Signer, trustedRegistryPub trustcrypto.PublicKeyDescriptor) (*RouteStore, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("statusnotify: route store path is required")
	}
	registryPub, err := resolveRouteTrustRoot(signer, trustedRegistryPub)
	if err != nil {
		return nil, err
	}
	store := &RouteStore{
		path:        path,
		signer:      signer,
		registryPub: registryPub,
		routes:      make(map[string]model.UpstreamNotificationRoute),
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
	if err := verifyRouteSnapshot(persisted, registryPub); err != nil {
		return nil, err
	}
	previousIdentity := ""
	for _, binding := range persisted.Routes {
		tenantID, clientID, route, err := normalizeRouteBinding(binding.TenantID, binding.ClientID, binding.Route)
		if err != nil {
			return nil, err
		}
		if tenantID != binding.TenantID || clientID != binding.ClientID || route != binding.Route {
			return nil, errors.New("statusnotify: signed route store contains non-canonical values")
		}
		key := routeIdentity(tenantID, clientID)
		if previousIdentity != "" && key <= previousIdentity {
			return nil, errors.New("statusnotify: signed route store routes must be unique and sorted")
		}
		previousIdentity = key
		store.routes[key] = route
	}
	return store, nil
}

// Configure adds one immutable route for an upstream. Repeating the exact
// configuration is idempotent; changing an existing upstream route is
// rejected so a key rotation cannot silently redirect notifications.
func (s *RouteStore) Configure(tenantID, clientID string, route model.UpstreamNotificationRoute) error {
	if s.signer == nil {
		return errors.New("statusnotify: registry signer is required to configure notification routes")
	}
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
	snapshot := routeSnapshot{
		SchemaVersion: SchemaNotificationRoutes,
		CryptoSuite:   s.registryPub.Suite,
		RegistryKeyID: s.registryPub.KeyID,
		Routes:        bindings,
	}
	signature, err := signRouteSnapshot(snapshot, s.signer, s.registryPub)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(persistedRoutes{
		SchemaVersion:     snapshot.SchemaVersion,
		CryptoSuite:       snapshot.CryptoSuite,
		RegistryKeyID:     snapshot.RegistryKeyID,
		Routes:            snapshot.Routes,
		RegistrySignature: signature,
	}, "", "  ")
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

func resolveRouteTrustRoot(signer trustcrypto.Signer, trusted trustcrypto.PublicKeyDescriptor) (trustcrypto.PublicKeyDescriptor, error) {
	if signer != nil {
		signerPub, err := signer.PublicKey(context.Background())
		if err != nil {
			return trustcrypto.PublicKeyDescriptor{}, fmt.Errorf("statusnotify: read registry signer public key: %w", err)
		}
		if len(trusted.Bytes) == 0 {
			trusted = signerPub
		} else if !sameRoutePublicKey(trusted, signerPub) {
			return trustcrypto.PublicKeyDescriptor{}, errors.New("statusnotify: registry signer does not match trusted registry public key")
		}
	}
	if len(trusted.Bytes) == 0 || strings.TrimSpace(trusted.KeyID) == "" {
		return trustcrypto.PublicKeyDescriptor{}, errors.New("statusnotify: trusted registry public key is required")
	}
	if err := trustcrypto.ValidatePublicKeyForSuite(trusted.Suite, trusted); err != nil {
		return trustcrypto.PublicKeyDescriptor{}, fmt.Errorf("statusnotify: invalid trusted registry public key: %w", err)
	}
	return trusted.Clone(), nil
}

func sameRoutePublicKey(a, b trustcrypto.PublicKeyDescriptor) bool {
	return a.Suite == b.Suite && a.KeyID == b.KeyID && a.Algorithm == b.Algorithm && a.Encoding == b.Encoding && bytes.Equal(a.Bytes, b.Bytes)
}

func signRouteSnapshot(snapshot routeSnapshot, signer trustcrypto.Signer, registryPub trustcrypto.PublicKeyDescriptor) (model.Signature, error) {
	input, err := routeSnapshotSignatureInput(snapshot)
	if err != nil {
		return model.Signature{}, err
	}
	signature, err := signer.Sign(context.Background(), input)
	if err != nil {
		return model.Signature{}, fmt.Errorf("statusnotify: sign route store: %w", err)
	}
	if err := trustcrypto.VerifySignatureForSuite(context.Background(), snapshot.CryptoSuite, registryPub, input, signature); err != nil {
		return model.Signature{}, fmt.Errorf("statusnotify: registry signer returned unverifiable route signature: %w", err)
	}
	return signature, nil
}

func verifyRouteSnapshot(persisted persistedRoutes, registryPub trustcrypto.PublicKeyDescriptor) error {
	if persisted.SchemaVersion != SchemaNotificationRoutes {
		return fmt.Errorf("statusnotify: route store schema must be %s", SchemaNotificationRoutes)
	}
	if persisted.CryptoSuite != registryPub.Suite || persisted.RegistryKeyID != registryPub.KeyID {
		return errors.New("statusnotify: route store registry trust root does not match configured registry")
	}
	input, err := routeSnapshotSignatureInput(persisted.snapshot())
	if err != nil {
		return err
	}
	if err := trustcrypto.VerifySignatureForSuite(context.Background(), persisted.CryptoSuite, registryPub, input, persisted.RegistrySignature); err != nil {
		return fmt.Errorf("statusnotify: verify route store registry signature: %w", err)
	}
	return nil
}

func routeSnapshotSignatureInput(snapshot routeSnapshot) ([]byte, error) {
	payload, err := cborx.Marshal(snapshot)
	if err != nil {
		return nil, fmt.Errorf("statusnotify: encode route signature payload: %w", err)
	}
	input, err := trustcrypto.SignatureInputForSuite(snapshot.CryptoSuite, trustcrypto.SignaturePurposeStatusNotificationRoutes, payload)
	if err != nil {
		return nil, fmt.Errorf("statusnotify: build route signature input: %w", err)
	}
	return input, nil
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
// authentication with the independently signed route sidecar.
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
