package statusnotify

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
)

type routeResolver struct {
	routes map[string]model.UpstreamNotificationRoute
	keys   map[string]model.ClientKey
}

func (r routeResolver) LookupNotificationRoute(tenantID, clientID, keyID string) (model.UpstreamNotificationRoute, bool) {
	route, found := r.routes[tenantID+"/"+clientID+"/"+keyID]
	return route, found
}

func (r routeResolver) LookupClientKeyAt(tenantID, clientID, keyID string, _ time.Time) (model.ClientKey, error) {
	key, found := r.keys[tenantID+"/"+clientID+"/"+keyID]
	if !found {
		return model.ClientKey{}, errors.New("key not found")
	}
	return key, nil
}

type memoryNATSPublisher struct {
	mu       sync.Mutex
	subjects []string
	bodies   [][]byte
}

func (p *memoryNATSPublisher) PublishStatusRefresh(_ context.Context, subject string, body []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.subjects = append(p.subjects, subject)
	p.bodies = append(p.bodies, append([]byte(nil), body...))
	return nil
}

func testSigner(t *testing.T) (trustcrypto.Signer, ed25519.PublicKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return trustcrypto.MustNewEd25519Signer("server-key", privateKey), publicKey
}

func testResolverAndRequest(t testing.TB, route model.UpstreamNotificationRoute, recordIDs []string, channels Channels) (routeResolver, CreateRequest) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	resolver := routeResolver{
		routes: map[string]model.UpstreamNotificationRoute{"tenant/client/key": route},
		keys: map[string]model.ClientKey{"tenant/client/key": {
			TenantID: "tenant", ClientID: "client", KeyID: "key", Alg: cryptosuite.SignatureEd25519,
			PublicKey: publicKey, Status: model.KeyStatusValid,
		}},
	}
	request := CreateRequest{
		TenantID: "tenant", ClientID: "client", KeyID: "key", RecordIDs: recordIDs, Channels: channels,
		SignedAtUnixN: time.Now().UTC().UnixNano(), Nonce: "0123456789abcdef",
	}
	if err := SignCreateRequest(context.Background(), cryptosuite.INTLV1, trustcrypto.MustNewEd25519Signer("key", privateKey), &request); err != nil {
		t.Fatal(err)
	}
	return resolver, request
}

func TestHubCoalescesWebhookRefreshes(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	received := make(chan model.StatusRefresh, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var notification model.StatusRefresh
		if err := json.NewDecoder(r.Body).Decode(&notification); err != nil {
			t.Errorf("decode webhook: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		calls.Add(1)
		received <- notification
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	signer, _ := testSigner(t)
	resolver, createRequest := testResolverAndRequest(t, model.UpstreamNotificationRoute{WebhookURL: server.URL}, []string{"tr1a", "tr1b"}, Channels{Webhook: true})
	hub, err := New(Config{
		Routes:        resolver,
		Signer:        signer,
		CryptoSuite:   cryptosuite.INTLV1,
		FlushInterval: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()

	subscription, err := hub.Create(context.Background(), createRequest)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1000; i++ {
		hub.Notify([]model.RecordStatus{{RecordID: "tr1a"}})
	}

	select {
	case notification := <-received:
		if notification.SubscriptionID != subscription.ID || !notification.RefreshRequired || notification.Version == 0 || len(notification.ServerSig.Signature) == 0 {
			t.Fatalf("notification = %+v", notification)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for webhook")
	}
	time.Sleep(250 * time.Millisecond)
	if got := calls.Load(); got != 1 {
		t.Fatalf("webhook calls = %d, want one coalesced refresh", got)
	}
}

func TestHubAllowsSSEOnlySubscriptionWithoutOutboundRoute(t *testing.T) {
	t.Parallel()
	signer, _ := testSigner(t)
	resolver, request := testResolverAndRequest(t, model.UpstreamNotificationRoute{}, []string{"tr1sse"}, Channels{})
	resolver.routes = map[string]model.UpstreamNotificationRoute{}
	hub, err := New(Config{Routes: resolver, Signer: signer, CryptoSuite: cryptosuite.INTLV1})
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	if _, err := hub.Create(context.Background(), request); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
}

func TestHubSSEWatchAndNATSPublish(t *testing.T) {
	t.Parallel()

	signer, _ := testSigner(t)
	resolver, createRequest := testResolverAndRequest(t, model.UpstreamNotificationRoute{
		NATSSubject: "trustdb.status.client", NATSQueueGroup: "trustdb-status-client",
	}, []string{"tr1a"}, Channels{NATS: true})
	hub, err := New(Config{
		Routes:        resolver,
		Signer:        signer,
		CryptoSuite:   cryptosuite.INTLV1,
		FlushInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	publisher := &memoryNATSPublisher{}
	hub.SetNATSPublisher(publisher)

	subscription, err := hub.Create(context.Background(), createRequest)
	if err != nil {
		t.Fatal(err)
	}
	events, cancel, err := hub.Watch(subscription.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()

	select {
	case notification := <-events:
		if notification.SubscriptionID != subscription.ID {
			t.Fatalf("SSE notification = %+v", notification)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for SSE refresh")
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		publisher.mu.Lock()
		count := len(publisher.bodies)
		publisher.mu.Unlock()
		if count > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timed out waiting for NATS refresh")
}

func TestHubContinuousChangesDoNotStarveRefresh(t *testing.T) {
	t.Parallel()

	signer, _ := testSigner(t)
	resolver, createRequest := testResolverAndRequest(t, model.UpstreamNotificationRoute{}, []string{"tr1hot"}, Channels{})
	hub, err := New(Config{
		Routes:        resolver,
		Signer:        signer,
		CryptoSuite:   cryptosuite.INTLV1,
		FlushInterval: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	subscription, err := hub.Create(context.Background(), createRequest)
	if err != nil {
		t.Fatal(err)
	}
	events, cancel, err := hub.Watch(subscription.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(2 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				hub.Notify([]model.RecordStatus{{RecordID: "tr1hot"}})
			case <-stop:
				return
			}
		}
	}()
	defer func() {
		close(stop)
		<-done
	}()

	select {
	case <-events:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("continuous changes starved the coalesced refresh")
	}
}

func TestHubExpiryHeapClosesSubscriptionWatchers(t *testing.T) {
	t.Parallel()

	signer, _ := testSigner(t)
	resolver, createRequest := testResolverAndRequest(t, model.UpstreamNotificationRoute{}, []string{"tr1expiry"}, Channels{})
	now := time.Now().UTC()
	hub, err := New(Config{
		Routes: resolver, Signer: signer, CryptoSuite: cryptosuite.INTLV1,
		FlushInterval: time.Hour, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	subscription, err := hub.Create(context.Background(), createRequest)
	if err != nil {
		t.Fatal(err)
	}
	events, cancel, err := hub.Watch(subscription.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()

	now = now.Add(defaultTTL + time.Second)
	hub.flush()
	select {
	case _, ok := <-events:
		if ok {
			t.Fatal("expired watcher remained open")
		}
	case <-time.After(time.Second):
		t.Fatal("expired watcher was not closed")
	}
}

func TestHubRejectsTamperedSubscriptionRequest(t *testing.T) {
	t.Parallel()

	signer, _ := testSigner(t)
	resolver, request := testResolverAndRequest(t, model.UpstreamNotificationRoute{}, []string{"tr1a"}, Channels{})
	hub, err := New(Config{Routes: resolver, Signer: signer, CryptoSuite: cryptosuite.INTLV1, FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	request.RecordIDs[0] = "tr1tampered"
	if _, err := hub.Create(context.Background(), request); err == nil {
		t.Fatal("tampered subscription request was accepted")
	}
}

func BenchmarkHubNotifySelectiveRecord(b *testing.B) {
	_, privateKey, _ := ed25519.GenerateKey(nil)
	resolver, createRequest := testResolverAndRequest(b, model.UpstreamNotificationRoute{}, []string{"tr1hot"}, Channels{})
	hub, err := New(Config{
		Routes:        resolver,
		Signer:        trustcrypto.MustNewEd25519Signer("server-key", privateKey),
		FlushInterval: time.Hour,
	})
	if err != nil {
		b.Fatal(err)
	}
	defer hub.Close()
	if _, err := hub.Create(context.Background(), createRequest); err != nil {
		b.Fatal(err)
	}
	status := []model.RecordStatus{{RecordID: "tr1hot"}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hub.Notify(status)
	}
}
