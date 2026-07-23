package natsingress

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/wowtrust/trustdb/internal/config"
)

var ErrOutcomeConflict = errors.New("NATS outcome conflicts with immutable stored outcome")

// JetStreamOutcomeSink stores one immutable result per verified request ID and
// one immutable dead-letter message per computed rejection ID. It is safe to
// retry after a lost publish acknowledgement, including after the stream's
// duplicate window has elapsed.
type JetStreamOutcomeSink struct {
	js                jetstream.JetStream
	resultStream      jetstream.Stream
	deadLetterStream  jetstream.Stream
	ingressStreamName string
	ingressConsumer   string
	ingressSubject    string
	resultStreamName  string
	deadLetterName    string
	resultPattern     string
	deadLetterPattern string
}

func NewJetStreamOutcomeSink(runtime *Runtime, cfg config.NATS) (*JetStreamOutcomeSink, error) {
	if !cfg.Enabled {
		return nil, errors.New("NATS outcome sink requires nats.enabled=true")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if runtime == nil || nilInterface(runtime.JetStream()) || nilInterface(runtime.ResultStream()) || nilInterface(runtime.DeadLetterStream()) {
		return nil, errors.New("NATS outcome sink requires an open runtime with validated outcome streams")
	}
	return &JetStreamOutcomeSink{
		js:                runtime.JetStream(),
		resultStream:      runtime.ResultStream(),
		deadLetterStream:  runtime.DeadLetterStream(),
		ingressStreamName: cfg.Stream,
		ingressConsumer:   cfg.Durable,
		ingressSubject:    cfg.Subject,
		resultStreamName:  cfg.ResultStream,
		deadLetterName:    cfg.DLQStream,
		resultPattern:     cfg.ResultSubject,
		deadLetterPattern: cfg.DLQSubject,
	}, nil
}

func (s *JetStreamOutcomeSink) Store(ctx context.Context, outcome DeliveryOutcome) error {
	if s == nil {
		return errors.New("NATS outcome sink is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := outcome.Validate(); err != nil {
		return err
	}

	if outcome.Result != nil {
		body, err := EncodeResult(*outcome.Result)
		if err != nil {
			return fmt.Errorf("encode NATS ingress result: %w", err)
		}
		return s.storeImmutable(ctx, s.resultStream, s.resultStreamName, s.resultPattern, outcome.Result.MessageID, SchemaResult, body)
	}

	if outcome.Rejection.Subject != s.ingressSubject {
		return fmt.Errorf("NATS rejection subject %q does not match configured ingress subject %q", outcome.Rejection.Subject, s.ingressSubject)
	}
	if outcome.Rejection.Stream != "" && (outcome.Rejection.Stream != s.ingressStreamName || outcome.Rejection.Consumer != s.ingressConsumer) {
		return fmt.Errorf("NATS rejection stream/consumer %q/%q does not match configured ingress %q/%q", outcome.Rejection.Stream, outcome.Rejection.Consumer, s.ingressStreamName, s.ingressConsumer)
	}
	deadLetter, err := NewDeadLetter(*outcome.Rejection)
	if err != nil {
		return fmt.Errorf("build NATS dead-letter message: %w", err)
	}
	body, err := EncodeDeadLetter(deadLetter)
	if err != nil {
		return fmt.Errorf("encode NATS dead-letter message: %w", err)
	}
	return s.storeImmutable(ctx, s.deadLetterStream, s.deadLetterName, s.deadLetterPattern, deadLetter.ID, SchemaDeadLetter, body)
}

func (s *JetStreamOutcomeSink) storeImmutable(ctx context.Context, stream jetstream.Stream, streamName, pattern, id, schema string, body []byte) error {
	subject, err := outcomeSubject(pattern, id)
	if err != nil {
		return err
	}
	message := nats.NewMsg(subject)
	message.Header.Set(HeaderContentType, ContentType)
	message.Header.Set(HeaderSchemaVersion, schema)
	message.Header.Set(HeaderMessageID, id)
	message.Data = body

	ack, publishErr := s.js.PublishMsg(
		ctx,
		message,
		jetstream.WithExpectStream(streamName),
		jetstream.WithExpectLastSequencePerSubject(0),
		jetstream.WithMsgID(id),
	)
	if publishErr == nil && ack != nil && !ack.Duplicate {
		if ack.Stream != streamName {
			return fmt.Errorf("NATS immutable outcome publish acknowledged by stream %q, want %q", ack.Stream, streamName)
		}
		return nil
	}

	existing, lookupErr := stream.GetLastMsgForSubject(ctx, subject)
	if lookupErr == nil {
		if immutableMessageMatches(existing, message) {
			return nil
		}
		return fmt.Errorf("%w: subject=%s", ErrOutcomeConflict, subject)
	}
	if publishErr != nil {
		if errors.Is(lookupErr, jetstream.ErrMsgNotFound) {
			return fmt.Errorf("publish immutable NATS outcome to %s: %w", streamName, publishErr)
		}
		return fmt.Errorf("publish immutable NATS outcome to %s: %w (verify existing outcome: %v)", streamName, publishErr, lookupErr)
	}
	if ack == nil {
		return fmt.Errorf("publish immutable NATS outcome to %s returned no acknowledgement; verify existing outcome: %w", streamName, lookupErr)
	}
	return fmt.Errorf("duplicate NATS outcome acknowledgement for missing subject %s: %w", subject, lookupErr)
}

func outcomeSubject(pattern, id string) (string, error) {
	if !validDigestID(id, messageIDPrefix) && !validDigestID(id, "tnj1") {
		return "", fmt.Errorf("invalid NATS outcome identity %q", id)
	}
	if !strings.HasSuffix(pattern, ".*") {
		return "", fmt.Errorf("invalid NATS outcome subject pattern %q", pattern)
	}
	return strings.TrimSuffix(pattern, "*") + id, nil
}

func immutableMessageMatches(existing *jetstream.RawStreamMsg, wanted *nats.Msg) bool {
	if existing == nil || wanted == nil || existing.Subject != wanted.Subject || !bytes.Equal(existing.Data, wanted.Data) {
		return false
	}
	for _, key := range []string{HeaderContentType, HeaderSchemaVersion, HeaderMessageID} {
		if !slices.Equal(existing.Header.Values(key), wanted.Header.Values(key)) {
			return false
		}
	}
	return true
}
