package statusnotify

import (
	"bytes"
	"container/heap"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

const (
	defaultFlushInterval        = 50 * time.Millisecond
	defaultTTL                  = 24 * time.Hour
	maxTTL                      = 7 * 24 * time.Hour
	maxRecordIDs                = 1000
	maxSubscriptions            = 10000
	maxSubscriptionsPerUpstream = 64
	defaultWorkers              = 8
	defaultQueueSize            = 4096
	defaultWebhookTimeout       = 5 * time.Second
)

type RouteResolver interface {
	LookupNotificationRoute(tenantID, clientID, keyID string) (model.UpstreamNotificationRoute, bool)
	LookupClientKeyAt(tenantID, clientID, keyID string, at time.Time) (model.ClientKey, error)
}

type NATSPublisher interface {
	PublishStatusRefresh(context.Context, string, []byte) error
}

type Config struct {
	StatePath     string
	Routes        RouteResolver
	Signer        trustcrypto.Signer
	CryptoSuite   cryptosuite.ID
	HTTPClient    *http.Client
	FlushInterval time.Duration
	Workers       int
	QueueSize     int
	Clock         func() time.Time
}

type Channels struct {
	Webhook bool `cbor:"webhook" json:"webhook"`
	NATS    bool `cbor:"nats" json:"nats"`
}

type CreateRequest struct {
	TenantID      string          `cbor:"tenant_id" json:"tenant_id"`
	ClientID      string          `cbor:"client_id" json:"client_id"`
	KeyID         string          `cbor:"key_id" json:"key_id"`
	RecordIDs     []string        `cbor:"record_ids" json:"record_ids"`
	Channels      Channels        `cbor:"channels" json:"channels"`
	TTLSeconds    int64           `cbor:"ttl_seconds,omitempty" json:"ttl_seconds,omitempty"`
	SignedAtUnixN int64           `cbor:"signed_at_unix_nano" json:"signed_at_unix_nano"`
	Nonce         string          `cbor:"nonce" json:"nonce"`
	Signature     model.Signature `cbor:"signature" json:"signature"`
}

type Subscription struct {
	ID             string   `json:"subscription_id"`
	TenantID       string   `json:"tenant_id"`
	ClientID       string   `json:"client_id"`
	KeyID          string   `json:"key_id"`
	RecordIDs      []string `json:"record_ids"`
	Channels       Channels `json:"channels"`
	CreatedAtUnixN int64    `json:"created_at_unix_nano"`
	ExpiresAtUnixN int64    `json:"expires_at_unix_nano"`
	Version        uint64   `json:"version"`
}

type state struct {
	subscription Subscription
	dirty        bool
	nextAttempt  time.Time
	attempts     int
	nextWatcher  uint64
	watchers     map[uint64]chan model.StatusRefresh
}

type deliveryJob struct {
	subscription Subscription
	route        model.UpstreamNotificationRoute
}

type persistedState struct {
	Subscriptions []Subscription `json:"subscriptions"`
}

type subscriptionExpiry struct {
	id             string
	expiresAtUnixN int64
}

type subscriptionExpiryHeap []subscriptionExpiry

func (h subscriptionExpiryHeap) Len() int           { return len(h) }
func (h subscriptionExpiryHeap) Less(i, j int) bool { return h[i].expiresAtUnixN < h[j].expiresAtUnixN }
func (h subscriptionExpiryHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *subscriptionExpiryHeap) Push(value any)    { *h = append(*h, value.(subscriptionExpiry)) }
func (h *subscriptionExpiryHeap) Pop() any {
	old := *h
	last := old[len(old)-1]
	*h = old[:len(old)-1]
	return last
}

// Hub keeps only the latest invalidation bit per selective subscription. A
// slow or disconnected receiver can therefore increase notification latency
// but can never create an event-per-status unbounded queue.
type Hub struct {
	mu             sync.RWMutex
	byID           map[string]*state
	byRecord       map[string]map[string]struct{}
	dirty          map[string]struct{}
	expiries       subscriptionExpiryHeap
	upstreamCounts map[string]int
	cfg            Config
	jobs           chan deliveryJob
	stop           chan struct{}
	done           chan struct{}
	natsMu         sync.RWMutex
	nats           NATSPublisher
	stopOnce       sync.Once
	workers        sync.WaitGroup
}

func New(cfg Config) (*Hub, error) {
	if cfg.Routes == nil {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "status notification route resolver is required")
	}
	if cfg.Signer == nil {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "status notification signer is required")
	}
	if cfg.CryptoSuite == "" {
		cfg.CryptoSuite = cryptosuite.INTLV1
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = defaultFlushInterval
	}
	if cfg.Workers <= 0 {
		cfg.Workers = defaultWorkers
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = defaultQueueSize
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: defaultWebhookTimeout}
	}
	h := &Hub{
		byID:           make(map[string]*state),
		byRecord:       make(map[string]map[string]struct{}),
		dirty:          make(map[string]struct{}),
		upstreamCounts: make(map[string]int),
		cfg:            cfg,
		jobs:           make(chan deliveryJob, cfg.QueueSize),
		stop:           make(chan struct{}),
		done:           make(chan struct{}),
	}
	if err := h.load(); err != nil {
		return nil, err
	}
	for i := 0; i < cfg.Workers; i++ {
		h.workers.Add(1)
		go h.deliveryWorker()
	}
	go h.run()
	return h, nil
}

func (h *Hub) SetNATSPublisher(publisher NATSPublisher) {
	h.natsMu.Lock()
	h.nats = publisher
	h.natsMu.Unlock()
}

// ValidateCreateRequest authenticates and bounds a subscription request
// without mutating hub state. HTTP handlers call it before record ownership
// lookups so an unsigned request cannot amplify proofstore reads.
func (h *Hub) ValidateCreateRequest(request CreateRequest) error {
	request.TenantID = strings.TrimSpace(request.TenantID)
	request.ClientID = strings.TrimSpace(request.ClientID)
	request.KeyID = strings.TrimSpace(request.KeyID)
	if request.TenantID == "" || request.ClientID == "" || request.KeyID == "" {
		return trusterr.New(trusterr.CodeInvalidArgument, "tenant_id, client_id, and key_id are required")
	}
	clientKey, err := h.cfg.Routes.LookupClientKeyAt(request.TenantID, request.ClientID, request.KeyID, h.cfg.Clock().UTC())
	if err != nil {
		return trusterr.Wrap(trusterr.CodeFailedPrecondition, "upstream key is not currently valid", err)
	}
	if err := VerifyCreateRequest(request, clientKey, h.cfg.Clock().UTC()); err != nil {
		return err
	}
	if _, err := normalizeRecordIDs(request.RecordIDs); err != nil {
		return err
	}
	route, _ := h.cfg.Routes.LookupNotificationRoute(request.TenantID, request.ClientID, request.KeyID)
	if request.Channels.Webhook && route.WebhookURL == "" {
		return trusterr.New(trusterr.CodeFailedPrecondition, "upstream key has no configured webhook route")
	}
	if request.Channels.NATS && (route.NATSSubject == "" || route.NATSQueueGroup == "") {
		return trusterr.New(trusterr.CodeFailedPrecondition, "upstream key has no configured NATS subject and queue group")
	}
	if request.Channels.NATS {
		h.natsMu.RLock()
		available := h.nats != nil
		h.natsMu.RUnlock()
		if !available {
			return trusterr.New(trusterr.CodeFailedPrecondition, "NATS status notifications are not enabled on this server")
		}
	}
	if request.TTLSeconds < 0 {
		return trusterr.New(trusterr.CodeInvalidArgument, "subscription ttl_seconds must not be negative")
	}
	if request.TTLSeconds > int64(maxTTL/time.Second) {
		return trusterr.New(trusterr.CodeInvalidArgument, "subscription ttl exceeds 7 days")
	}
	return nil
}

func (h *Hub) Create(_ context.Context, request CreateRequest) (Subscription, error) {
	if err := h.ValidateCreateRequest(request); err != nil {
		return Subscription{}, err
	}
	request.TenantID = strings.TrimSpace(request.TenantID)
	request.ClientID = strings.TrimSpace(request.ClientID)
	request.KeyID = strings.TrimSpace(request.KeyID)
	if request.TenantID == "" || request.ClientID == "" || request.KeyID == "" {
		return Subscription{}, trusterr.New(trusterr.CodeInvalidArgument, "tenant_id, client_id, and key_id are required")
	}
	clientKey, err := h.cfg.Routes.LookupClientKeyAt(request.TenantID, request.ClientID, request.KeyID, h.cfg.Clock().UTC())
	if err != nil {
		return Subscription{}, trusterr.Wrap(trusterr.CodeFailedPrecondition, "upstream key is not currently valid", err)
	}
	if err := VerifyCreateRequest(request, clientKey, h.cfg.Clock().UTC()); err != nil {
		return Subscription{}, err
	}
	recordIDs, err := normalizeRecordIDs(request.RecordIDs)
	if err != nil {
		return Subscription{}, err
	}
	route, _ := h.cfg.Routes.LookupNotificationRoute(request.TenantID, request.ClientID, request.KeyID)
	if request.Channels.Webhook && route.WebhookURL == "" {
		return Subscription{}, trusterr.New(trusterr.CodeFailedPrecondition, "upstream key has no configured webhook route")
	}
	if request.Channels.NATS && (route.NATSSubject == "" || route.NATSQueueGroup == "") {
		return Subscription{}, trusterr.New(trusterr.CodeFailedPrecondition, "upstream key has no configured NATS subject and queue group")
	}
	if request.Channels.NATS {
		h.natsMu.RLock()
		available := h.nats != nil
		h.natsMu.RUnlock()
		if !available {
			return Subscription{}, trusterr.New(trusterr.CodeFailedPrecondition, "NATS status notifications are not enabled on this server")
		}
	}
	ttl := defaultTTL
	if request.TTLSeconds > 0 {
		ttl = time.Duration(request.TTLSeconds) * time.Second
	}
	id, err := subscriptionID(request)
	if err != nil {
		return Subscription{}, trusterr.Wrap(trusterr.CodeInternal, "derive subscription id", err)
	}
	now := h.cfg.Clock().UTC()
	subscription := Subscription{
		ID:             id,
		TenantID:       request.TenantID,
		ClientID:       request.ClientID,
		KeyID:          request.KeyID,
		RecordIDs:      recordIDs,
		Channels:       request.Channels,
		CreatedAtUnixN: now.UnixNano(),
		ExpiresAtUnixN: now.Add(ttl).UnixNano(),
	}
	h.mu.Lock()
	if existing := h.byID[subscription.ID]; existing != nil {
		result := cloneSubscription(existing.subscription)
		h.mu.Unlock()
		return result, nil
	}
	if len(h.byID) >= maxSubscriptions {
		h.mu.Unlock()
		return Subscription{}, trusterr.New(trusterr.CodeResourceExhausted, "status subscription capacity is exhausted")
	}
	if h.upstreamCounts[upstreamIdentity(subscription.TenantID, subscription.ClientID)] >= maxSubscriptionsPerUpstream {
		h.mu.Unlock()
		return Subscription{}, trusterr.New(trusterr.CodeResourceExhausted, "upstream status subscription limit is exhausted")
	}
	h.addLocked(subscription, true)
	if err := h.persistLocked(); err != nil {
		h.removeLocked(subscription.ID)
		h.mu.Unlock()
		return Subscription{}, err
	}
	h.mu.Unlock()
	return cloneSubscription(subscription), nil
}

func (h *Hub) Get(id string) (Subscription, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	item, ok := h.byID[id]
	if !ok || item.subscription.ExpiresAtUnixN <= h.cfg.Clock().UTC().UnixNano() {
		return Subscription{}, false
	}
	return cloneSubscription(item.subscription), true
}

func (h *Hub) Delete(_ context.Context, id string) error {
	h.mu.Lock()
	if _, found := h.byID[id]; !found {
		h.mu.Unlock()
		return trusterr.New(trusterr.CodeNotFound, "status subscription not found")
	}
	h.removeLocked(id)
	err := h.persistLocked()
	h.mu.Unlock()
	return err
}

// Notify is intentionally bounded by the number of subscriptions for the
// changed record. It performs no signing, encoding, disk IO, or network IO.
func (h *Hub) Notify(statuses []model.RecordStatus) {
	if len(statuses) == 0 {
		return
	}
	h.mu.Lock()
	for i := range statuses {
		for id := range h.byRecord[statuses[i].RecordID] {
			if item := h.byID[id]; item != nil {
				h.markDirtyLocked(id, item)
			}
		}
	}
	h.mu.Unlock()
}

func (h *Hub) Watch(id string) (<-chan model.StatusRefresh, func(), error) {
	h.mu.Lock()
	item := h.byID[id]
	if item == nil || item.subscription.ExpiresAtUnixN <= h.cfg.Clock().UTC().UnixNano() {
		h.mu.Unlock()
		return nil, nil, trusterr.New(trusterr.CodeNotFound, "status subscription not found")
	}
	item.nextWatcher++
	watcherID := item.nextWatcher
	ch := make(chan model.StatusRefresh, 1)
	item.watchers[watcherID] = ch
	h.markDirtyLocked(id, item)
	h.mu.Unlock()
	var once sync.Once
	cancel := func() {
		once.Do(func() {
			h.mu.Lock()
			if current := h.byID[id]; current != nil {
				delete(current.watchers, watcherID)
			}
			h.mu.Unlock()
		})
	}
	return ch, cancel, nil
}

func (h *Hub) Close() error {
	h.stopOnce.Do(func() { close(h.stop) })
	<-h.done
	return nil
}

func (h *Hub) run() {
	defer close(h.done)
	// Use a fixed cadence instead of debounce. Under continuous high write
	// traffic, resetting a debounce timer on every change can postpone a
	// refresh forever; a ticker keeps coalescing while bounding notification
	// latency to roughly one flush interval plus delivery time.
	ticker := time.NewTicker(h.cfg.FlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-h.stop:
			h.mu.Lock()
			for _, item := range h.byID {
				for watcherID, watcher := range item.watchers {
					delete(item.watchers, watcherID)
					close(watcher)
				}
			}
			h.mu.Unlock()
			close(h.jobs)
			h.workers.Wait()
			return
		case <-ticker.C:
			h.flush()
		}
	}
}

func (h *Hub) flush() {
	now := h.cfg.Clock().UTC()
	nowUnixN := now.UnixNano()
	jobs := make([]deliveryJob, 0)
	h.mu.Lock()
	removed := false
	for h.expiries.Len() > 0 && h.expiries[0].expiresAtUnixN <= nowUnixN {
		expiry := heap.Pop(&h.expiries).(subscriptionExpiry)
		item := h.byID[expiry.id]
		if item != nil && item.subscription.ExpiresAtUnixN == expiry.expiresAtUnixN {
			h.removeLocked(expiry.id)
			removed = true
		}
	}
	for id := range h.dirty {
		item := h.byID[id]
		if item == nil || !item.dirty {
			delete(h.dirty, id)
			continue
		}
		if now.Before(item.nextAttempt) {
			continue
		}
		if _, err := h.cfg.Routes.LookupClientKeyAt(item.subscription.TenantID, item.subscription.ClientID, item.subscription.KeyID, now); err != nil {
			h.removeLocked(id)
			removed = true
			continue
		}
		item.dirty = false
		delete(h.dirty, id)
		item.subscription.Version = uint64(nowUnixN)
		route, _ := h.cfg.Routes.LookupNotificationRoute(item.subscription.TenantID, item.subscription.ClientID, item.subscription.KeyID)
		jobs = append(jobs, deliveryJob{subscription: cloneSubscription(item.subscription), route: route})
	}
	if removed {
		_ = h.persistLocked()
	}
	h.mu.Unlock()
	for _, job := range jobs {
		select {
		case h.jobs <- job:
		case <-h.stop:
			return
		default:
			h.retry(job.subscription.ID)
		}
	}
}

func (h *Hub) deliveryWorker() {
	defer h.workers.Done()
	for job := range h.jobs {
		if err := h.deliver(job); err != nil {
			h.retry(job.subscription.ID)
		} else {
			h.delivered(job.subscription.ID)
		}
	}
}

func (h *Hub) deliver(job deliveryJob) error {
	notification := model.StatusRefresh{
		SchemaVersion:   model.SchemaStatusRefresh,
		SubscriptionID:  job.subscription.ID,
		TenantID:        job.subscription.TenantID,
		ClientID:        job.subscription.ClientID,
		Version:         job.subscription.Version,
		RefreshRequired: true,
		EmittedAtUnixN:  h.cfg.Clock().UTC().UnixNano(),
	}
	if err := signRefresh(context.Background(), h.cfg.CryptoSuite, h.cfg.Signer, &notification); err != nil {
		return err
	}

	h.mu.RLock()
	if item := h.byID[job.subscription.ID]; item != nil {
		for _, watcher := range item.watchers {
			select {
			case watcher <- notification:
			default:
			}
		}
	}
	h.mu.RUnlock()

	var deliveryErr error
	if job.subscription.Channels.Webhook {
		body, err := json.Marshal(notification)
		if err != nil {
			deliveryErr = errors.Join(deliveryErr, err)
		} else if err := h.postWebhook(job.route.WebhookURL, job.subscription.ID, body); err != nil {
			deliveryErr = errors.Join(deliveryErr, err)
		}
	}
	if job.subscription.Channels.NATS {
		body, err := cborx.Marshal(notification)
		if err != nil {
			deliveryErr = errors.Join(deliveryErr, err)
		} else {
			h.natsMu.RLock()
			publisher := h.nats
			h.natsMu.RUnlock()
			if publisher == nil {
				deliveryErr = errors.Join(deliveryErr, errors.New("NATS status publisher is unavailable"))
			} else {
				publishCtx, cancel := context.WithTimeout(context.Background(), defaultWebhookTimeout)
				err := publisher.PublishStatusRefresh(publishCtx, job.route.NATSSubject, body)
				cancel()
				if err != nil {
					deliveryErr = errors.Join(deliveryErr, err)
				}
			}
		}
	}
	return deliveryErr
}

func (h *Hub) postWebhook(rawURL, subscriptionID string, body []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultWebhookTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-TrustDB-Schema-Version", model.SchemaStatusRefresh)
	request.Header.Set("X-TrustDB-Subscription-ID", subscriptionID)
	response, err := h.cfg.HTTPClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("status webhook returned HTTP %d", response.StatusCode)
	}
	return nil
}

func (h *Hub) retry(id string) {
	h.mu.Lock()
	if item := h.byID[id]; item != nil {
		h.markDirtyLocked(id, item)
		item.attempts++
		delay := 100 * time.Millisecond
		for i := 1; i < item.attempts && delay < time.Minute; i++ {
			delay *= 2
		}
		if delay > time.Minute {
			delay = time.Minute
		}
		item.nextAttempt = h.cfg.Clock().UTC().Add(delay)
	}
	h.mu.Unlock()
}

func (h *Hub) delivered(id string) {
	h.mu.Lock()
	if item := h.byID[id]; item != nil {
		item.attempts = 0
		item.nextAttempt = time.Time{}
	}
	h.mu.Unlock()
}

func (h *Hub) addLocked(subscription Subscription, dirty bool) {
	item := &state{subscription: cloneSubscription(subscription), watchers: make(map[uint64]chan model.StatusRefresh)}
	h.byID[subscription.ID] = item
	h.upstreamCounts[upstreamIdentity(subscription.TenantID, subscription.ClientID)]++
	heap.Push(&h.expiries, subscriptionExpiry{id: subscription.ID, expiresAtUnixN: subscription.ExpiresAtUnixN})
	if dirty {
		h.markDirtyLocked(subscription.ID, item)
	}
	for _, recordID := range subscription.RecordIDs {
		ids := h.byRecord[recordID]
		if ids == nil {
			ids = make(map[string]struct{})
			h.byRecord[recordID] = ids
		}
		ids[subscription.ID] = struct{}{}
	}
}

func (h *Hub) removeLocked(id string) {
	item := h.byID[id]
	if item == nil {
		return
	}
	delete(h.byID, id)
	delete(h.dirty, id)
	upstream := upstreamIdentity(item.subscription.TenantID, item.subscription.ClientID)
	if h.upstreamCounts[upstream] <= 1 {
		delete(h.upstreamCounts, upstream)
	} else {
		h.upstreamCounts[upstream]--
	}
	for watcherID, watcher := range item.watchers {
		delete(item.watchers, watcherID)
		close(watcher)
	}
	for _, recordID := range item.subscription.RecordIDs {
		delete(h.byRecord[recordID], id)
		if len(h.byRecord[recordID]) == 0 {
			delete(h.byRecord, recordID)
		}
	}
}

func (h *Hub) markDirtyLocked(id string, item *state) {
	item.dirty = true
	h.dirty[id] = struct{}{}
}

func upstreamIdentity(tenantID, clientID string) string {
	return tenantID + "\x00" + clientID
}

func (h *Hub) load() error {
	if strings.TrimSpace(h.cfg.StatePath) == "" {
		return nil
	}
	data, err := os.ReadFile(h.cfg.StatePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "read status subscriptions", err)
	}
	var persisted persistedState
	if err := json.Unmarshal(data, &persisted); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "decode status subscriptions", err)
	}
	now := h.cfg.Clock().UTC().UnixNano()
	for _, subscription := range persisted.Subscriptions {
		if subscription.ExpiresAtUnixN > now {
			h.addLocked(subscription, true)
		}
	}
	return nil
}

func (h *Hub) persistLocked() error {
	if strings.TrimSpace(h.cfg.StatePath) == "" {
		return nil
	}
	items := make([]Subscription, 0, len(h.byID))
	for _, item := range h.byID {
		items = append(items, cloneSubscription(item.subscription))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	data, err := json.Marshal(persistedState{Subscriptions: items})
	if err != nil {
		return trusterr.Wrap(trusterr.CodeInternal, "encode status subscriptions", err)
	}
	if err := os.MkdirAll(filepath.Dir(h.cfg.StatePath), 0o700); err != nil {
		return trusterr.Wrap(trusterr.CodeInternal, "create status subscription directory", err)
	}
	tmp := h.cfg.StatePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return trusterr.Wrap(trusterr.CodeInternal, "write status subscriptions", err)
	}
	if err := os.Rename(tmp, h.cfg.StatePath); err != nil {
		return trusterr.Wrap(trusterr.CodeInternal, "replace status subscriptions", err)
	}
	return nil
}

func signRefresh(ctx context.Context, suiteID cryptosuite.ID, signer trustcrypto.Signer, notification *model.StatusRefresh) error {
	payload := *notification
	payload.ServerSig = model.Signature{}
	encoded, err := cborx.Marshal(payload)
	if err != nil {
		return err
	}
	input, err := trustcrypto.SignatureInputForSuite(suiteID, trustcrypto.SignaturePurposeStatusRefresh, encoded)
	if err != nil {
		return err
	}
	signature, err := trustcrypto.Sign(ctx, suiteID, signer, input)
	if err != nil {
		return err
	}
	notification.ServerSig = signature
	return nil
}

func normalizeRecordIDs(recordIDs []string) ([]string, error) {
	if len(recordIDs) == 0 {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "record_ids must not be empty")
	}
	if len(recordIDs) > maxRecordIDs {
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "record_ids exceeds 1000 items")
	}
	seen := make(map[string]struct{}, len(recordIDs))
	out := make([]string, 0, len(recordIDs))
	for _, raw := range recordIDs {
		id := strings.TrimSpace(raw)
		if id == "" {
			return nil, trusterr.New(trusterr.CodeInvalidArgument, "record_id must not be empty")
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out, nil
}

func SignCreateRequest(ctx context.Context, suiteID cryptosuite.ID, signer trustcrypto.Signer, request *CreateRequest) error {
	if request == nil {
		return trusterr.New(trusterr.CodeInvalidArgument, "status subscription request is required")
	}
	payload := *request
	payload.Signature = model.Signature{}
	encoded, err := cborx.Marshal(payload)
	if err != nil {
		return err
	}
	input, err := trustcrypto.SignatureInputForSuite(suiteID, trustcrypto.SignaturePurposeStatusSubscription, encoded)
	if err != nil {
		return err
	}
	request.Signature, err = trustcrypto.Sign(ctx, suiteID, signer, input)
	return err
}

func VerifyCreateRequest(request CreateRequest, clientKey model.ClientKey, now time.Time) error {
	if clientKey.TenantID != request.TenantID || clientKey.ClientID != request.ClientID || clientKey.KeyID != request.KeyID {
		return trusterr.New(trusterr.CodeInvalidArgument, "status subscription identity does not match the registered key")
	}
	if request.SignedAtUnixN <= 0 || len(request.Nonce) < 16 || len(request.Nonce) > 128 {
		return trusterr.New(trusterr.CodeInvalidArgument, "status subscription requires signed_at_unix_nano and a 16-128 byte nonce")
	}
	signedAt := time.Unix(0, request.SignedAtUnixN).UTC()
	if signedAt.Before(now.Add(-5*time.Minute)) || signedAt.After(now.Add(5*time.Minute)) {
		return trusterr.New(trusterr.CodeInvalidArgument, "status subscription signature timestamp is outside the 5 minute window")
	}
	if request.Signature.KeyID != request.KeyID || request.Signature.KeyID != clientKey.KeyID {
		return trusterr.New(trusterr.CodeInvalidArgument, "status subscription signature key_id does not match the registered key")
	}
	suite, err := cryptosuite.RequireAvailable(cryptosuite.INTLV1)
	if err != nil {
		return err
	}
	payload := request
	payload.Signature = model.Signature{}
	encoded, err := cborx.Marshal(payload)
	if err != nil {
		return err
	}
	input, err := trustcrypto.SignatureInputForSuite(suite.ID, trustcrypto.SignaturePurposeStatusSubscription, encoded)
	if err != nil {
		return err
	}
	descriptor := trustcrypto.PublicKeyDescriptor{
		Suite: suite.ID, KeyID: clientKey.KeyID, Algorithm: clientKey.Alg,
		Encoding: suite.Signature.PublicKeyEncoding, Bytes: append([]byte(nil), clientKey.PublicKey...),
	}
	if err := trustcrypto.VerifySignatureForSuite(context.Background(), suite.ID, descriptor, input, request.Signature); err != nil {
		return trusterr.Wrap(trusterr.CodeInvalidArgument, "verify status subscription signature", err)
	}
	return nil
}

func subscriptionID(request CreateRequest) (string, error) {
	encoded, err := cborx.Marshal(request)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return "tss1" + base64.RawURLEncoding.EncodeToString(digest[:18]), nil
}

func cloneSubscription(subscription Subscription) Subscription {
	subscription.RecordIDs = append([]string(nil), subscription.RecordIDs...)
	return subscription
}
