package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/ryan-wong-coder/trustdb/internal/claim"
	"github.com/ryan-wong-coder/trustdb/internal/model"
	"github.com/ryan-wong-coder/trustdb/internal/trustcrypto"
)

const (
	// DefaultLogEventType is used when a log claim does not set EventType.
	DefaultLogEventType = "log.record"
	// DefaultLogMediaType is used when a log claim does not set MediaType.
	DefaultLogMediaType = "application/json"
)

// LogClaimOptions controls the claim envelope produced for a structured log.
type LogClaimOptions struct {
	ProducedAt     time.Time
	Nonce          []byte
	IdempotencyKey string
	HashAlg        string
	MediaType      string
	StorageURI     string
	EventType      string
	Source         string
	TraceID        string
	Parents        []string
	CustomMetadata map[string]string
}

// LogEntry is one structured log item for batch or stream submission.
type LogEntry struct {
	Body    []byte
	Reader  io.Reader
	Options LogClaimOptions
}

// LogSubmitOptions controls bounded batch log submission.
type LogSubmitOptions struct {
	Claim       LogClaimOptions
	Concurrency int
	StopOnError bool
}

// LogStreamOptions controls backpressure-aware streaming log submission.
type LogStreamOptions struct {
	Claim       LogClaimOptions
	Concurrency int
	QueueSize   int
	StopOnError bool
}

// LogSubmitItemResult is the per-log result returned by batch and stream APIs.
type LogSubmitItemResult struct {
	Index  int
	Result SubmitResult
	Err    error
}

// LogBatchResult summarizes a batch submission and preserves per-entry order.
type LogBatchResult struct {
	Results   []LogSubmitItemResult
	Submitted int
	Failed    int
}

// LogBatchError reports that at least one item in a batch failed.
type LogBatchError struct {
	Submitted int
	Failed    int
}

func (e *LogBatchError) Error() string {
	return fmt.Sprintf("sdk: submit log batch: %d submitted, %d failed", e.Submitted, e.Failed)
}

// NewJSONLogEntry marshals a structured value as one JSON log entry.
func NewJSONLogEntry(v any, opts LogClaimOptions) (LogEntry, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return LogEntry{}, fmt.Errorf("sdk: marshal json log entry: %w", err)
	}
	return LogEntry{Body: body, Options: opts}, nil
}

// BuildSignedLogClaim hashes a log stream and signs it as a TrustDB claim.
func BuildSignedLogClaim(raw io.Reader, id Identity, opts LogClaimOptions) (SignedClaim, error) {
	if raw == nil {
		return SignedClaim{}, errors.New("sdk: log content reader is nil")
	}
	if len(id.PrivateKey) != trustcrypto.Ed25519PrivateKeySize {
		return SignedClaim{}, fmt.Errorf("sdk: invalid ed25519 private key size: %d", len(id.PrivateKey))
	}
	hashAlg := opts.HashAlg
	if hashAlg == "" {
		hashAlg = model.DefaultHashAlg
	}
	contentHash, n, err := trustcrypto.HashReader(hashAlg, raw)
	if err != nil {
		return SignedClaim{}, err
	}
	producedAt := opts.ProducedAt
	if producedAt.IsZero() {
		producedAt = time.Now().UTC()
	}
	nonce := append([]byte(nil), opts.Nonce...)
	if len(nonce) == 0 {
		nonce, err = trustcrypto.NewNonce(16)
		if err != nil {
			return SignedClaim{}, err
		}
	}
	idempotencyKey := opts.IdempotencyKey
	if idempotencyKey == "" {
		idempotencyKey, err = randomIdempotencyKey()
		if err != nil {
			return SignedClaim{}, err
		}
	}
	eventType := opts.EventType
	if eventType == "" {
		eventType = DefaultLogEventType
	}
	mediaType := opts.MediaType
	if mediaType == "" {
		mediaType = DefaultLogMediaType
	}
	metadata := model.Metadata{
		EventType: eventType,
		Source:    opts.Source,
		TraceID:   opts.TraceID,
		Parents:   copyStringSlice(opts.Parents),
		Custom:    copyStringMap(opts.CustomMetadata),
	}
	content := model.Content{
		HashAlg:       hashAlg,
		ContentHash:   contentHash,
		ContentLength: n,
		MediaType:     mediaType,
		StorageURI:    opts.StorageURI,
	}
	c, err := claim.NewFileClaim(
		id.TenantID,
		id.ClientID,
		id.KeyID,
		producedAt,
		nonce,
		idempotencyKey,
		content,
		metadata,
	)
	if err != nil {
		return SignedClaim{}, err
	}
	return claim.Sign(c, id.PrivateKey)
}

// BuildSignedLogClaimBytes hashes an in-memory log payload and signs it.
func BuildSignedLogClaimBytes(raw []byte, id Identity, opts LogClaimOptions) (SignedClaim, error) {
	if raw == nil {
		return SignedClaim{}, errors.New("sdk: log content body is nil")
	}
	return BuildSignedLogClaim(bytes.NewReader(raw), id, opts)
}

// BuildSignedJSONLogClaim marshals a structured value to JSON and signs it.
func BuildSignedJSONLogClaim(v any, id Identity, opts LogClaimOptions) (SignedClaim, error) {
	entry, err := NewJSONLogEntry(v, opts)
	if err != nil {
		return SignedClaim{}, err
	}
	return BuildSignedLogClaimBytes(entry.Body, id, entry.Options)
}

// SubmitLog builds, signs, and submits one streaming log payload.
func (c *Client) SubmitLog(ctx context.Context, raw io.Reader, id Identity, opts LogClaimOptions) (SubmitResult, error) {
	signed, err := BuildSignedLogClaim(raw, id, opts)
	if err != nil {
		return SubmitResult{}, err
	}
	result, err := c.SubmitSignedClaim(ctx, signed)
	if err != nil {
		return SubmitResult{}, err
	}
	result.SignedClaim = signed
	return result, nil
}

// SubmitLogBytes builds, signs, and submits one in-memory log payload.
func (c *Client) SubmitLogBytes(ctx context.Context, raw []byte, id Identity, opts LogClaimOptions) (SubmitResult, error) {
	if raw == nil {
		return SubmitResult{}, errors.New("sdk: log content body is nil")
	}
	return c.SubmitLog(ctx, bytes.NewReader(raw), id, opts)
}

// SubmitJSONLog marshals, signs, and submits one structured JSON log payload.
func (c *Client) SubmitJSONLog(ctx context.Context, v any, id Identity, opts LogClaimOptions) (SubmitResult, error) {
	entry, err := NewJSONLogEntry(v, opts)
	if err != nil {
		return SubmitResult{}, err
	}
	return c.SubmitLogBytes(ctx, entry.Body, id, entry.Options)
}

// SubmitLogBatch submits log entries concurrently and returns per-entry results.
func (c *Client) SubmitLogBatch(ctx context.Context, entries []LogEntry, id Identity, opts LogSubmitOptions) (LogBatchResult, error) {
	result := LogBatchResult{Results: make([]LogSubmitItemResult, len(entries))}
	if len(entries) == 0 {
		return result, nil
	}
	if len(entries) > 1 {
		if err := validateMultiLogDefaults("batch", opts.Claim); err != nil {
			return result, err
		}
	}
	if native, ok := c.transport.(signedClaimBatchTransport); ok {
		return c.submitLogBatchNative(ctx, entries, id, opts, native)
	}
	workerCount := normalizeLogConcurrency(opts.Concurrency)
	if workerCount > len(entries) {
		workerCount = len(entries)
	}
	workCtx := ctx
	if workCtx == nil {
		workCtx = context.Background()
	}
	workCtx, cancel := context.WithCancel(workCtx)
	defer cancel()

	jobs := make(chan int)
	done := make([]bool, len(entries))
	var wg sync.WaitGroup
	wg.Add(workerCount)
	for worker := 0; worker < workerCount; worker++ {
		go func() {
			defer wg.Done()
			for index := range jobs {
				if opts.StopOnError {
					if err := workCtx.Err(); err != nil {
						result.Results[index] = LogSubmitItemResult{Index: index, Err: err}
						done[index] = true
						continue
					}
				}
				submitted, err := c.submitLogEntry(workCtx, entries[index], id, opts.Claim)
				result.Results[index] = LogSubmitItemResult{Index: index, Result: submitted, Err: err}
				done[index] = true
				if err != nil && opts.StopOnError {
					cancel()
				}
			}
		}()
	}

sendLoop:
	for index := range entries {
		select {
		case jobs <- index:
		case <-workCtx.Done():
			break sendLoop
		}
	}
	close(jobs)
	wg.Wait()

	for index := range entries {
		if !done[index] {
			err := workCtx.Err()
			if err == nil {
				err = errors.New("sdk: log batch item was not submitted")
			}
			result.Results[index] = LogSubmitItemResult{Index: index, Err: err}
		}
		if result.Results[index].Err != nil {
			result.Failed++
			continue
		}
		result.Submitted++
	}
	if result.Failed > 0 {
		return result, &LogBatchError{Submitted: result.Submitted, Failed: result.Failed}
	}
	return result, nil
}

func (c *Client) submitLogBatchNative(ctx context.Context, entries []LogEntry, id Identity, opts LogSubmitOptions, transport signedClaimBatchTransport) (LogBatchResult, error) {
	workCtx := ctx
	if workCtx == nil {
		workCtx = context.Background()
	}
	result := LogBatchResult{Results: make([]LogSubmitItemResult, len(entries))}
	signed := make([]SignedClaim, 0, len(entries))
	originalIndexes := make([]int, 0, len(entries))
	done := make([]bool, len(entries))
	for index, entry := range entries {
		if err := workCtx.Err(); err != nil {
			result.Results[index] = LogSubmitItemResult{Index: index, Err: err}
			done[index] = true
			continue
		}
		raw, err := logEntryReader(entry)
		if err != nil {
			result.Results[index] = LogSubmitItemResult{Index: index, Err: err}
			done[index] = true
			continue
		}
		claim, err := BuildSignedLogClaim(raw, id, mergeLogClaimOptions(opts.Claim, entry.Options))
		if err != nil {
			result.Results[index] = LogSubmitItemResult{Index: index, Err: err}
			done[index] = true
			continue
		}
		signed = append(signed, claim)
		originalIndexes = append(originalIndexes, index)
	}
	if len(signed) == 0 {
		countLogBatchResult(&result)
		return result, &LogBatchError{Submitted: result.Submitted, Failed: result.Failed}
	}
	items, err := transport.SubmitSignedClaims(workCtx, signed)
	if err != nil {
		return result, err
	}
	if len(items) != len(signed) {
		return result, fmt.Errorf("sdk: native log batch returned %d results for %d submitted entries", len(items), len(signed))
	}
	for _, item := range items {
		if item.Index < 0 || item.Index >= len(signed) {
			return result, fmt.Errorf("sdk: native log batch returned out-of-range result index %d", item.Index)
		}
		originalIndex := originalIndexes[item.Index]
		result.Results[originalIndex] = LogSubmitItemResult{Index: originalIndex, Result: item.Result, Err: item.Err}
		done[originalIndex] = true
	}
	for index := range entries {
		if !done[index] {
			result.Results[index] = LogSubmitItemResult{Index: index, Err: errors.New("sdk: log batch item was not submitted")}
		}
	}
	if countLogBatchResult(&result) {
		return result, &LogBatchError{Submitted: result.Submitted, Failed: result.Failed}
	}
	return result, nil
}

// SubmitLogStream submits entries from a channel with bounded queueing.
func (c *Client) SubmitLogStream(ctx context.Context, entries <-chan LogEntry, id Identity, opts LogStreamOptions) (<-chan LogSubmitItemResult, error) {
	if entries == nil {
		return nil, errors.New("sdk: log entry stream is nil")
	}
	if err := validateMultiLogDefaults("stream", opts.Claim); err != nil {
		return nil, err
	}
	if native, ok := c.transport.(signedClaimStreamTransport); ok {
		return c.submitLogStreamNative(ctx, entries, id, opts, native)
	}
	workerCount := normalizeLogConcurrency(opts.Concurrency)
	queueSize := opts.QueueSize
	if queueSize <= 0 {
		queueSize = workerCount * 2
	}
	workCtx := ctx
	if workCtx == nil {
		workCtx = context.Background()
	}
	workCtx, cancel := context.WithCancel(workCtx)
	jobs := make(chan indexedLogEntry, queueSize)
	out := make(chan LogSubmitItemResult, queueSize)

	var wg sync.WaitGroup
	wg.Add(workerCount)
	for worker := 0; worker < workerCount; worker++ {
		go func() {
			defer wg.Done()
			for job := range jobs {
				submitted, err := c.submitLogEntry(workCtx, job.entry, id, opts.Claim)
				item := LogSubmitItemResult{Index: job.index, Result: submitted, Err: err}
				select {
				case out <- item:
				case <-workCtx.Done():
					return
				}
				if err != nil && opts.StopOnError {
					cancel()
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		index := 0
		for {
			select {
			case <-workCtx.Done():
				return
			case entry, ok := <-entries:
				if !ok {
					return
				}
				job := indexedLogEntry{index: index, entry: entry}
				index++
				select {
				case jobs <- job:
				case <-workCtx.Done():
					return
				}
			}
		}
	}()

	go func() {
		wg.Wait()
		cancel()
		close(out)
	}()

	return out, nil
}

func (c *Client) submitLogStreamNative(ctx context.Context, entries <-chan LogEntry, id Identity, opts LogStreamOptions, transport signedClaimStreamTransport) (<-chan LogSubmitItemResult, error) {
	workerCount := normalizeLogConcurrency(opts.Concurrency)
	queueSize := opts.QueueSize
	if queueSize <= 0 {
		queueSize = workerCount * 2
	}
	workCtx := ctx
	if workCtx == nil {
		workCtx = context.Background()
	}
	workCtx, cancel := context.WithCancel(workCtx)
	signedIn := make(chan signedClaimStreamItem, queueSize)
	nativeOut, err := transport.SubmitSignedClaimStream(workCtx, signedIn)
	if err != nil {
		cancel()
		return nil, err
	}
	out := make(chan LogSubmitItemResult, queueSize)
	emit := func(item LogSubmitItemResult) bool {
		select {
		case out <- item:
			return true
		case <-workCtx.Done():
			return false
		}
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer close(signedIn)
		index := 0
		for {
			select {
			case <-workCtx.Done():
				return
			case entry, ok := <-entries:
				if !ok {
					return
				}
				itemIndex := index
				index++
				raw, err := logEntryReader(entry)
				if err != nil {
					if !emit(LogSubmitItemResult{Index: itemIndex, Err: err}) {
						return
					}
					if opts.StopOnError {
						cancel()
						return
					}
					continue
				}
				signed, err := BuildSignedLogClaim(raw, id, mergeLogClaimOptions(opts.Claim, entry.Options))
				if err != nil {
					if !emit(LogSubmitItemResult{Index: itemIndex, Err: err}) {
						return
					}
					if opts.StopOnError {
						cancel()
						return
					}
					continue
				}
				select {
				case signedIn <- signedClaimStreamItem{Index: itemIndex, SignedClaim: signed}:
				case <-workCtx.Done():
					return
				}
			}
		}
	}()
	go func() {
		defer wg.Done()
		for item := range nativeOut {
			if !emit(LogSubmitItemResult{Index: item.Index, Result: item.Result, Err: item.Err}) {
				return
			}
			if item.Err != nil && opts.StopOnError {
				cancel()
				return
			}
		}
	}()
	go func() {
		wg.Wait()
		cancel()
		close(out)
	}()
	return out, nil
}

type indexedLogEntry struct {
	index int
	entry LogEntry
}

func (c *Client) submitLogEntry(ctx context.Context, entry LogEntry, id Identity, defaults LogClaimOptions) (SubmitResult, error) {
	if err := ctx.Err(); err != nil {
		return SubmitResult{}, err
	}
	raw, err := logEntryReader(entry)
	if err != nil {
		return SubmitResult{}, err
	}
	opts := mergeLogClaimOptions(defaults, entry.Options)
	return c.SubmitLog(ctx, raw, id, opts)
}

func logEntryReader(entry LogEntry) (io.Reader, error) {
	if entry.Reader != nil && entry.Body != nil {
		return nil, errors.New("sdk: log entry cannot set both Body and Reader")
	}
	if entry.Reader != nil {
		return entry.Reader, nil
	}
	if entry.Body != nil {
		return bytes.NewReader(entry.Body), nil
	}
	return nil, errors.New("sdk: log entry Body or Reader is required")
}

func mergeLogClaimOptions(defaults, override LogClaimOptions) LogClaimOptions {
	out := defaults
	if !override.ProducedAt.IsZero() {
		out.ProducedAt = override.ProducedAt
	}
	if len(override.Nonce) > 0 {
		out.Nonce = append([]byte(nil), override.Nonce...)
	} else {
		out.Nonce = append([]byte(nil), defaults.Nonce...)
	}
	if override.IdempotencyKey != "" {
		out.IdempotencyKey = override.IdempotencyKey
	}
	if override.HashAlg != "" {
		out.HashAlg = override.HashAlg
	}
	if override.MediaType != "" {
		out.MediaType = override.MediaType
	}
	if override.StorageURI != "" {
		out.StorageURI = override.StorageURI
	}
	if override.EventType != "" {
		out.EventType = override.EventType
	}
	if override.Source != "" {
		out.Source = override.Source
	}
	if override.TraceID != "" {
		out.TraceID = override.TraceID
	}
	if len(override.Parents) > 0 {
		out.Parents = copyStringSlice(override.Parents)
	} else {
		out.Parents = copyStringSlice(defaults.Parents)
	}
	out.CustomMetadata = mergeStringMap(defaults.CustomMetadata, override.CustomMetadata)
	return out
}

func validateMultiLogDefaults(scope string, defaults LogClaimOptions) error {
	if defaults.IdempotencyKey != "" {
		return fmt.Errorf("sdk: log %s default idempotency key would be reused; set it per LogEntry or leave it empty", scope)
	}
	if len(defaults.Nonce) > 0 {
		return fmt.Errorf("sdk: log %s default nonce would be reused; set it per LogEntry or leave it empty", scope)
	}
	return nil
}

func normalizeLogConcurrency(concurrency int) int {
	if concurrency <= 0 {
		return defaultHTTPConcurrency
	}
	return concurrency
}

func copyStringSlice(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func mergeStringMap(defaults, override map[string]string) map[string]string {
	out := make(map[string]string, len(defaults)+len(override))
	for k, v := range defaults {
		out[k] = v
	}
	for k, v := range override {
		out[k] = v
	}
	return out
}

func countLogBatchResult(result *LogBatchResult) bool {
	result.Submitted = 0
	result.Failed = 0
	for _, item := range result.Results {
		if item.Err != nil {
			result.Failed++
			continue
		}
		result.Submitted++
	}
	return result.Failed > 0
}
