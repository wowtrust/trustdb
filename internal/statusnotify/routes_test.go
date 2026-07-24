package statusnotify

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/model"
)

type storedRouteKeyResolver struct {
	key model.ClientKey
	err error
}

func (r storedRouteKeyResolver) LookupClientKeyAt(tenantID, clientID, keyID string, _ time.Time) (model.ClientKey, error) {
	if r.err != nil {
		return model.ClientKey{}, r.err
	}
	key := r.key
	key.TenantID = tenantID
	key.ClientID = clientID
	key.KeyID = keyID
	return key, nil
}

func TestRouteStorePersistsOneRoutePerUpstream(t *testing.T) {
	t.Parallel()
	path := RouteStorePath(filepath.Join(t.TempDir(), "keys.tdkeys"))
	store, err := OpenRouteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	route := model.UpstreamNotificationRoute{
		WebhookURL:     "https://upstream.example/trustdb/status-refresh",
		NATSSubject:    "trustdb.status.upstream-a",
		NATSQueueGroup: "trustdb-status-upstream-a",
	}
	if err := store.Configure(" tenant-a ", " upstream-a ", route); err != nil {
		t.Fatal(err)
	}
	if err := store.Configure("tenant-a", "upstream-a", route); err != nil {
		t.Fatalf("idempotent Configure() error = %v", err)
	}
	if err := store.Configure("tenant-a", "upstream-a", model.UpstreamNotificationRoute{WebhookURL: "https://other.example/status"}); err == nil {
		t.Fatal("conflicting Configure() error = nil")
	}

	reopened, err := OpenRouteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewStoredRouteResolver(storedRouteKeyResolver{}, reopened)
	if err != nil {
		t.Fatal(err)
	}
	got, found := resolver.LookupNotificationRoute("tenant-a", "upstream-a", "rotated-key")
	if !found || got != route {
		t.Fatalf("LookupNotificationRoute() = %+v, %v", got, found)
	}
	key, err := resolver.LookupClientKeyAt("tenant-a", "upstream-a", "rotated-key", time.Now())
	if err != nil || key.KeyID != "rotated-key" {
		t.Fatalf("LookupClientKeyAt() = %+v, %v", key, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("route store permissions = %o, want no group/other access", info.Mode().Perm())
	}
}

func TestRouteStoreRejectsUnsafeDestinations(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		route model.UpstreamNotificationRoute
		want  string
	}{
		{name: "relative webhook", route: model.UpstreamNotificationRoute{WebhookURL: "/status"}, want: "absolute http(s)"},
		{name: "webhook credentials", route: model.UpstreamNotificationRoute{WebhookURL: "https://user:pass@example.com/status"}, want: "credentials"},
		{name: "subject without group", route: model.UpstreamNotificationRoute{NATSSubject: "trustdb.status.upstream"}, want: "configured together"},
		{name: "group without subject", route: model.UpstreamNotificationRoute{NATSQueueGroup: "upstream-workers"}, want: "configured together"},
		{name: "wildcard subject", route: model.UpstreamNotificationRoute{NATSSubject: "trustdb.status.*", NATSQueueGroup: "upstream-workers"}, want: "concrete"},
		{name: "empty subject token", route: model.UpstreamNotificationRoute{NATSSubject: "trustdb..status", NATSQueueGroup: "upstream-workers"}, want: "empty tokens"},
		{name: "queue whitespace", route: model.UpstreamNotificationRoute{NATSSubject: "trustdb.status.upstream", NATSQueueGroup: "upstream workers"}, want: "queue group"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, err := OpenRouteStore(filepath.Join(t.TempDir(), "routes.json"))
			if err != nil {
				t.Fatal(err)
			}
			err = store.Configure("tenant", "client", test.route)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Configure() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestOpenRouteStoreRejectsUnknownOrTrailingJSON(t *testing.T) {
	t.Parallel()
	tests := []string{
		`{"schema_version":"trustdb.status-notification-routes.v1","routes":[],"unknown":true}`,
		`{"schema_version":"trustdb.status-notification-routes.v1","routes":[]} {}`,
		`{"schema_version":"trustdb.status-notification-routes.v0","routes":[]}`,
	}
	for i, body := range tests {
		path := filepath.Join(t.TempDir(), "routes.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenRouteStore(path); err == nil {
			t.Fatalf("OpenRouteStore(case %d) error = nil", i)
		}
	}
}

func TestNewStoredRouteResolverRequiresDependencies(t *testing.T) {
	t.Parallel()
	store, err := OpenRouteStore(filepath.Join(t.TempDir(), "routes.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewStoredRouteResolver(nil, store); err == nil {
		t.Fatal("nil keys error = nil")
	}
	if _, err := NewStoredRouteResolver(storedRouteKeyResolver{err: errors.New("unavailable")}, nil); err == nil {
		t.Fatal("nil routes error = nil")
	}
}
