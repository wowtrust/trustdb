package natsingress

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/wowtrust/trustdb/internal/model"
)

const StatusRefreshContentType = "application/vnd.trustdb.status-refresh+cbor"

// StatusPublisher uses the already-managed NATS ingress connection to emit
// best-effort invalidation hints on the operator-approved subject stored in
// the upstream key registry. Status data itself remains available through the
// pull API, so a missed core-NATS hint is repaired by reconnect refresh.
type StatusPublisher struct {
	conn *nats.Conn
}

func NewStatusPublisher(runtime *Runtime) (*StatusPublisher, error) {
	if runtime == nil || runtime.Conn() == nil {
		return nil, errors.New("NATS status publisher requires an open runtime")
	}
	return &StatusPublisher{conn: runtime.Conn()}, nil
}

func (p *StatusPublisher) PublishStatusRefresh(ctx context.Context, subject string, body []byte) error {
	if p == nil || p.conn == nil || p.conn.IsClosed() {
		return errors.New("NATS status publisher is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	message := nats.NewMsg(subject)
	message.Header.Set(HeaderContentType, StatusRefreshContentType)
	message.Header.Set(HeaderSchemaVersion, model.SchemaStatusRefresh)
	message.Data = body
	if err := p.conn.PublishMsg(message); err != nil {
		return fmt.Errorf("publish NATS status refresh: %w", err)
	}
	flushCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		flushCtx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	if err := p.conn.FlushWithContext(flushCtx); err != nil {
		return fmt.Errorf("flush NATS status refresh: %w", err)
	}
	return nil
}
