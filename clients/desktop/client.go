package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/sdk"
)

type serverClient struct {
	sdk       *sdk.Client
	transport string
}

func newServerClient(transport, endpoint string) (*serverClient, error) {
	return newServerClientWithTLS(transport, endpoint, sdk.TLSConfig{})
}

func newServerClientWithTLS(transport, endpoint string, tlsConfig sdk.TLSConfig) (*serverClient, error) {
	transport = normalizeServerTransport(transport)
	endpoint = strings.TrimSpace(endpoint)
	var (
		client *sdk.Client
		err    error
	)
	switch transport {
	case serverTransportHTTP:
		if strings.EqualFold(parsedScheme(endpoint), "https") {
			client, err = sdk.NewClient(endpoint, sdk.WithTLSConfig(tlsConfig))
		} else {
			client, err = sdk.NewClient(endpoint)
		}
	case serverTransportGRPC:
		target, targetErr := normalizeGRPCTarget(endpoint)
		if targetErr != nil {
			return nil, targetErr
		}
		if hasTLSInputs(tlsConfig) || !isLoopbackDesktopTarget(target) {
			client, err = sdk.NewGRPCClient(target, sdk.WithGRPCTLSConfig(tlsConfig))
		} else {
			client, err = sdk.NewGRPCClient(target, sdk.WithGRPCLocalPlaintext())
		}
	default:
		return nil, fmt.Errorf("unsupported server transport: %s", transport)
	}
	if err != nil {
		return nil, err
	}
	return &serverClient{sdk: client, transport: transport}, nil
}

func parsedScheme(endpoint string) string {
	u, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil {
		return ""
	}
	return u.Scheme
}

func hasTLSInputs(config sdk.TLSConfig) bool {
	return strings.TrimSpace(config.CAFile) != "" || strings.TrimSpace(config.CertFile) != "" || strings.TrimSpace(config.KeyFile) != "" || strings.TrimSpace(config.ServerName) != "" || len(config.CAPinsSHA256) > 0
}

func isLoopbackDesktopTarget(target string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(target))
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func tlsConfigFromSettings(settings Settings) sdk.TLSConfig {
	pins := strings.FieldsFunc(settings.ServerCAPinsSHA256, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' })
	return sdk.TLSConfig{
		CAFile:         strings.TrimSpace(settings.ServerCAFile),
		CAPinsSHA256:   pins,
		CertFile:       strings.TrimSpace(settings.ClientTLSCertFile),
		KeyFile:        strings.TrimSpace(settings.ClientTLSKeyFile),
		ServerName:     strings.TrimSpace(settings.ServerName),
		ReloadInterval: strings.TrimSpace(settings.TLSReloadInterval),
	}
}

func normalizeServerTransport(transport string) string {
	switch strings.ToLower(strings.TrimSpace(transport)) {
	case "", serverTransportHTTP:
		return serverTransportHTTP
	case serverTransportGRPC:
		return serverTransportGRPC
	default:
		return strings.ToLower(strings.TrimSpace(transport))
	}
}

func validServerTransport(transport string) bool {
	switch normalizeServerTransport(transport) {
	case serverTransportHTTP, serverTransportGRPC:
		return true
	default:
		return false
	}
}

func normalizeGRPCTarget(endpoint string) (string, error) {
	trimmed := strings.TrimSpace(endpoint)
	if trimmed == "" {
		return "", errors.New("grpc server target is empty")
	}
	if !strings.Contains(trimmed, "://") {
		return strings.TrimRight(trimmed, "/"), nil
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("parse grpc target: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "grpc":
		if u.Host == "" {
			return "", fmt.Errorf("grpc target must include host: %s", trimmed)
		}
		if path := strings.Trim(u.Path, "/"); path != "" {
			return "", fmt.Errorf("grpc target must be host:port, got path %q", u.Path)
		}
		return u.Host, nil
	default:
		// Keep advanced gRPC resolver targets such as dns:///host untouched.
		return trimmed, nil
	}
}

func (c *serverClient) close() {
	if c == nil || c.sdk == nil {
		return
	}
	_ = c.sdk.Close()
}

type ServerError = sdk.Error

type HealthStatus struct {
	OK                bool   `json:"ok"`
	ServerURL         string `json:"server_url"`
	Transport         string `json:"transport"`
	RTTMillis         int64  `json:"rtt_millis"`
	Error             string `json:"error,omitempty"`
	StatusCode        int    `json:"status_code,omitempty"`
	TransportSecurity string `json:"transport_security,omitempty"`
	TLSVersion        string `json:"tls_version,omitempty"`
	PeerAuthenticated bool   `json:"peer_authenticated,omitempty"`
	PeerSubject       string `json:"peer_subject,omitempty"`
}

func (c *serverClient) health(ctx context.Context) HealthStatus {
	status := c.sdk.CheckHealth(ctx)
	return HealthStatus{
		OK:                status.OK,
		ServerURL:         status.ServerURL,
		Transport:         c.transport,
		RTTMillis:         status.RTTMillis,
		Error:             status.Error,
		StatusCode:        status.StatusCode,
		TransportSecurity: status.TransportSecurity,
		TLSVersion:        status.TLSVersion,
		PeerAuthenticated: status.PeerAuthenticated,
		PeerSubject:       status.PeerSubject,
	}
}

// submitClaimResult mirrors the server's submit response so the UI can inspect
// batch_enqueued / idempotent flags without making a second call.
type submitClaimResult = sdk.SubmitResult

func (c *serverClient) submitSignedClaim(ctx context.Context, signed model.SignedClaim) (submitClaimResult, error) {
	return c.sdk.SubmitSignedClaim(ctx, signed)
}

func (c *serverClient) getProof(ctx context.Context, recordID string) (model.ProofBundle, error) {
	return c.sdk.GetProofBundle(ctx, recordID)
}

func (c *serverClient) getRecordIndex(ctx context.Context, recordID string) (model.RecordIndex, error) {
	return c.sdk.GetRecord(ctx, recordID)
}

func (c *serverClient) listRecordIndexes(ctx context.Context, opts RecordPageOptions) (RecordPage, error) {
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	direction := strings.TrimSpace(opts.Direction)
	if direction == "" {
		direction = sdk.RecordListDirectionDesc
	}

	query := strings.TrimSpace(opts.Query)
	contentHash := ""
	if query != "" {
		if looksLikeRecordID(query) {
			idx, err := c.getRecordIndex(ctx, query)
			if err != nil {
				var se *ServerError
				if errors.As(err, &se) && se.StatusCode == http.StatusNotFound {
					return RecordPage{Items: nil, Limit: limit, Offset: opts.Offset, Source: "server", TotalExact: true}, nil
				}
				return RecordPage{}, err
			}
			return RecordPage{
				Items:      []LocalRecord{localRecordFromIndex(idx)},
				Total:      1,
				Limit:      limit,
				Offset:     opts.Offset,
				Source:     "server",
				TotalExact: true,
			}, nil
		}
		if strings.HasPrefix(query, "batch-") && opts.BatchID == "" {
			opts.BatchID = query
			query = ""
		}
		if looksLikeSHA256Hex(query) {
			contentHash = strings.TrimPrefix(strings.ToLower(query), "sha256:")
			query = ""
		}
	}

	page, err := c.sdk.ListRecords(ctx, sdk.ListRecordsOptions{
		Limit:          limit,
		Direction:      direction,
		Cursor:         opts.Cursor,
		BatchID:        opts.BatchID,
		TenantID:       opts.TenantID,
		ClientID:       opts.ClientID,
		ProofLevel:     opts.Level,
		Query:          query,
		ContentHashHex: contentHash,
	})
	if err != nil {
		return RecordPage{}, err
	}
	items := make([]LocalRecord, 0, len(page.Records))
	for _, idx := range page.Records {
		items = append(items, localRecordFromIndex(idx))
	}
	total := opts.Offset + len(items)
	if page.NextCursor != "" {
		total++
	}
	return RecordPage{
		Items:      items,
		Total:      total,
		Limit:      limit,
		Offset:     opts.Offset,
		HasMore:    page.NextCursor != "",
		NextCursor: page.NextCursor,
		Source:     "server",
		TotalExact: page.NextCursor == "",
	}, nil
}

func looksLikeRecordID(query string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(query)), "tr1")
}

func looksLikeSHA256Hex(query string) bool {
	query = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(query)), "sha256:")
	if len(query) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(query)
	return err == nil && len(decoded) == 32
}

func localRecordFromIndex(idx model.RecordIndex) LocalRecord {
	proofLevel := model.RecordIndexProofLevel(idx)
	var committed *model.CommittedReceipt
	if idx.BatchID != "" {
		committed = &model.CommittedReceipt{
			SchemaVersion: model.SchemaCommittedReceipt,
			RecordID:      idx.RecordID,
			Status:        "committed",
			BatchID:       idx.BatchID,
			LeafIndex:     idx.BatchLeafIndex,
			ClosedAtUnixN: idx.BatchClosedAtUnixN,
		}
	}
	submittedAt := time.Unix(0, idx.ReceivedAtUnixN).UTC()
	if idx.ReceivedAtUnixN == 0 && idx.BatchClosedAtUnixN != 0 {
		submittedAt = time.Unix(0, idx.BatchClosedAtUnixN).UTC()
	}
	rec := LocalRecord{
		RecordID:         idx.RecordID,
		FilePath:         idx.StorageURI,
		FileName:         displayNameFromStorageURI(idx),
		ContentHashHex:   hex.EncodeToString(idx.ContentHash),
		ContentLength:    idx.ContentLength,
		MediaType:        idx.MediaType,
		EventType:        idx.EventType,
		Source:           idx.Source,
		TenantID:         idx.TenantID,
		ClientID:         idx.ClientID,
		KeyID:            idx.KeyID,
		ProofLevel:       proofLevel,
		BatchID:          idx.BatchID,
		CommittedReceipt: committed,
	}
	setLocalRecordSubmittedAt(&rec, submittedAt)
	setLocalRecordLastSyncedAt(&rec, time.Now().UTC())
	return rec
}

func displayNameFromStorageURI(idx model.RecordIndex) string {
	if strings.TrimSpace(idx.FileName) != "" {
		return strings.TrimSpace(idx.FileName)
	}
	raw := strings.TrimSpace(idx.StorageURI)
	if raw == "" {
		if idx.RecordID != "" {
			return idx.RecordID
		}
		return "remote-record"
	}
	withoutQuery := raw
	if cut := strings.IndexAny(withoutQuery, "?#"); cut >= 0 {
		withoutQuery = withoutQuery[:cut]
	}
	withoutQuery = strings.TrimRight(strings.ReplaceAll(withoutQuery, "\\", "/"), "/")
	if slash := strings.LastIndex(withoutQuery, "/"); slash >= 0 && slash < len(withoutQuery)-1 {
		return withoutQuery[slash+1:]
	}
	if withoutQuery != "" {
		return withoutQuery
	}
	return idx.RecordID
}

type anchorEnvelope struct {
	TreeSize uint64                 `json:"tree_size"`
	Status   string                 `json:"status"`
	Result   *model.STHAnchorResult `json:"result,omitempty"`
}

func (c *serverClient) getGlobalProof(ctx context.Context, batchID string) (model.GlobalLogProof, error) {
	return c.sdk.GetGlobalProof(ctx, batchID)
}

func (c *serverClient) getAnchor(ctx context.Context, treeSize uint64) (anchorEnvelope, error) {
	status, err := c.sdk.GetAnchor(ctx, treeSize)
	if err != nil {
		if sdk.IsUnavailable(err) {
			return anchorEnvelope{TreeSize: treeSize, Status: "unavailable"}, nil
		}
		return anchorEnvelope{}, err
	}
	return anchorEnvelope{TreeSize: status.TreeSize, Status: status.Status, Result: status.Result}, nil
}

func (c *serverClient) listRoots(ctx context.Context, limit int) ([]model.BatchRoot, error) {
	return c.sdk.ListRoots(ctx, limit)
}

func (c *serverClient) latestRoot(ctx context.Context) (model.BatchRoot, error) {
	return c.sdk.LatestRoot(ctx)
}

func (c *serverClient) metricsRaw(ctx context.Context) (string, error) {
	return c.sdk.MetricsRaw(ctx)
}

func (c *serverClient) exportSingleProof(ctx context.Context, recordID string) (model.SingleProof, error) {
	return c.sdk.ExportSingleProof(ctx, recordID)
}
