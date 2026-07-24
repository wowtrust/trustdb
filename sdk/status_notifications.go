package sdk

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/nats-io/nats.go"
	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
)

const MaxStatusRefreshBytes = 64 << 10

// DecodeAndVerifyStatusRefreshJSON is intended for a configured webhook
// receiver. It validates the TrustDB server signature before returning the
// refresh hint; callers then pull the subscription's current statuses.
func DecodeAndVerifyStatusRefreshJSON(reader io.Reader, serverPublicKey ed25519.PublicKey) (StatusRefresh, error) {
	raw, err := readAllLimit(reader, MaxStatusRefreshBytes)
	if err != nil {
		return StatusRefresh{}, err
	}
	var notification model.StatusRefresh
	if err := json.Unmarshal(raw, &notification); err != nil {
		return StatusRefresh{}, fmt.Errorf("sdk: decode status refresh JSON: %w", err)
	}
	if err := VerifyStatusRefresh(notification, serverPublicKey); err != nil {
		return StatusRefresh{}, err
	}
	return notification, nil
}

func DecodeAndVerifyStatusRefreshCBOR(data []byte, serverPublicKey ed25519.PublicKey) (StatusRefresh, error) {
	if len(data) > MaxStatusRefreshBytes {
		return StatusRefresh{}, fmt.Errorf("sdk: status refresh is too large: %d", len(data))
	}
	var notification model.StatusRefresh
	if err := cborx.UnmarshalLimit(data, &notification, MaxStatusRefreshBytes); err != nil {
		return StatusRefresh{}, fmt.Errorf("sdk: decode status refresh CBOR: %w", err)
	}
	if err := VerifyStatusRefresh(notification, serverPublicKey); err != nil {
		return StatusRefresh{}, err
	}
	return notification, nil
}

func VerifyStatusRefresh(notification StatusRefresh, serverPublicKey ed25519.PublicKey) error {
	if notification.SchemaVersion != model.SchemaStatusRefresh || notification.SubscriptionID == "" ||
		notification.TenantID == "" || notification.ClientID == "" || notification.Version == 0 ||
		!notification.RefreshRequired || notification.EmittedAtUnixN <= 0 {
		return errors.New("sdk: invalid status refresh notification")
	}
	if len(serverPublicKey) != ed25519.PublicKeySize {
		return errors.New("sdk: invalid server public key")
	}
	payload := notification
	payload.ServerSig = model.Signature{}
	encoded, err := cborx.Marshal(payload)
	if err != nil {
		return err
	}
	input, err := trustcrypto.SignatureInputForSuite(cryptosuite.INTLV1, trustcrypto.SignaturePurposeStatusRefresh, encoded)
	if err != nil {
		return err
	}
	descriptor := trustcrypto.MustNewEd25519PublicKey(notification.ServerSig.KeyID, serverPublicKey)
	if err := trustcrypto.VerifySignatureForSuite(context.Background(), cryptosuite.INTLV1, descriptor, input, notification.ServerSig); err != nil {
		return fmt.Errorf("sdk: verify status refresh: %w", err)
	}
	return nil
}

// SubscribeNATSStatusRefresh joins the preconfigured queue group for one
// upstream. Replicas using the same subject and queue group share each refresh
// hint, while a different queue group would receive its own copy. Core NATS
// notifications are wake-up hints, so reconnecting callers should immediately
// pull current subscription statuses.
func SubscribeNATSStatusRefresh(ctx context.Context, conn *nats.Conn, subject, queueGroup string, serverPublicKey ed25519.PublicKey) (<-chan StatusRefresh, <-chan error, error) {
	if conn == nil || conn.IsClosed() {
		return nil, nil, errors.New("sdk: NATS connection is unavailable")
	}
	subject = strings.TrimSpace(subject)
	queueGroup = strings.TrimSpace(queueGroup)
	if subject == "" || queueGroup == "" {
		return nil, nil, errors.New("sdk: NATS status subject and queue group are required")
	}
	if strings.ContainsAny(queueGroup, " \t\r\n") {
		return nil, nil, errors.New("sdk: NATS status queue group must not contain whitespace")
	}
	events := make(chan StatusRefresh, 1)
	errorsCh := make(chan error, 1)
	messages := make(chan *nats.Msg, 64)
	subscription, err := conn.ChanQueueSubscribe(subject, queueGroup, messages)
	if err != nil {
		return nil, nil, fmt.Errorf("sdk: subscribe NATS status refresh: %w", err)
	}
	if err := conn.Flush(); err != nil {
		_ = subscription.Unsubscribe()
		return nil, nil, fmt.Errorf("sdk: flush NATS subscription: %w", err)
	}
	go func() {
		defer subscription.Unsubscribe()
		defer close(events)
		defer close(errorsCh)
		for {
			select {
			case <-ctx.Done():
				return
			case message := <-messages:
				if message == nil {
					return
				}
				notification, decodeErr := DecodeAndVerifyStatusRefreshCBOR(message.Data, serverPublicKey)
				if decodeErr != nil {
					select {
					case errorsCh <- decodeErr:
					default:
					}
					continue
				}
				select {
				case events <- notification:
				default:
					// A queued invalidation already tells the caller to pull current
					// state; dropping another hint is deliberate coalescing.
				}
			}
		}
	}()
	return events, errorsCh, nil
}
