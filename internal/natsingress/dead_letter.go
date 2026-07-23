package natsingress

import (
	"errors"
	"fmt"
	"strings"

	"github.com/nats-io/nats.go"
	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/formatregistry"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

const SchemaDeadLetter = "trustdb.nats-dead-letter.v1"

// DeadLetter is the complete, deterministic copy of one rejected JetStream
// delivery. Its identity is derived from broker metadata and raw content; a
// malformed caller-provided Nats-Msg-Id is never used as the storage key.
type DeadLetter struct {
	SchemaVersion    string        `cbor:"schema_version" json:"schema_version"`
	FormatGeneration string        `cbor:"format_generation" json:"format_generation"`
	ID               string        `cbor:"id" json:"id"`
	Subject          string        `cbor:"subject" json:"subject"`
	Reply            string        `cbor:"reply" json:"reply"`
	Headers          nats.Header   `cbor:"headers" json:"headers"`
	Data             []byte        `cbor:"data" json:"data"`
	Stream           string        `cbor:"stream" json:"stream"`
	Consumer         string        `cbor:"consumer" json:"consumer"`
	StreamSequence   uint64        `cbor:"stream_sequence" json:"stream_sequence"`
	ConsumerSequence uint64        `cbor:"consumer_sequence" json:"consumer_sequence"`
	NumDelivered     uint64        `cbor:"num_delivered" json:"num_delivered"`
	Code             trusterr.Code `cbor:"code" json:"code"`
	Message          string        `cbor:"message" json:"message"`
}

func NewDeadLetter(rejection Rejection) (DeadLetter, error) {
	deadLetter := DeadLetter{
		SchemaVersion:    SchemaDeadLetter,
		FormatGeneration: formatregistry.NATSV1,
		ID:               rejection.ID,
		Subject:          rejection.Subject,
		Reply:            rejection.Reply,
		Headers:          cloneHeader(rejection.Headers),
		Data:             append([]byte(nil), rejection.Data...),
		Stream:           rejection.Stream,
		Consumer:         rejection.Consumer,
		StreamSequence:   rejection.StreamSequence,
		ConsumerSequence: rejection.ConsumerSequence,
		NumDelivered:     rejection.NumDelivered,
		Code:             rejection.Code,
		Message:          rejection.Message,
	}
	if err := deadLetter.Validate(); err != nil {
		return DeadLetter{}, err
	}
	return deadLetter, nil
}

func EncodeDeadLetter(deadLetter DeadLetter) ([]byte, error) {
	if err := deadLetter.Validate(); err != nil {
		return nil, err
	}
	data, err := cborx.Marshal(deadLetter)
	if err != nil {
		return nil, err
	}
	if len(data) > MaxDeadLetterBytes {
		return nil, fmt.Errorf("NATS dead-letter message too large: %d > %d", len(data), MaxDeadLetterBytes)
	}
	return data, nil
}

func DecodeDeadLetter(data []byte) (DeadLetter, error) {
	var deadLetter DeadLetter
	if err := cborx.UnmarshalLimit(data, &deadLetter, MaxDeadLetterBytes); err != nil {
		return DeadLetter{}, fmt.Errorf("decode NATS dead-letter message: %w", err)
	}
	if err := deadLetter.Validate(); err != nil {
		return DeadLetter{}, err
	}
	return deadLetter, nil
}

func (d DeadLetter) Validate() error {
	if d.SchemaVersion != SchemaDeadLetter {
		return fmt.Errorf("unexpected NATS dead-letter schema: %s", d.SchemaVersion)
	}
	if d.FormatGeneration != formatregistry.NATSV1 {
		return fmt.Errorf("unexpected NATS dead-letter format generation: %s", d.FormatGeneration)
	}
	if strings.TrimSpace(d.Subject) == "" {
		return errors.New("NATS dead-letter subject is required")
	}
	if len(d.Data) > MaxMessageBytes {
		return fmt.Errorf("NATS dead-letter raw data too large: %d > %d", len(d.Data), MaxMessageBytes)
	}
	if err := (Failure{Code: d.Code, Message: d.Message}).validate(); err != nil {
		return fmt.Errorf("invalid NATS dead-letter rejection: %w", err)
	}
	if d.Stream == "" {
		if d.Consumer != "" || d.StreamSequence != 0 || d.ConsumerSequence != 0 || d.NumDelivered != 0 {
			return errors.New("NATS dead-letter has partial JetStream metadata")
		}
	} else if d.Consumer == "" || d.StreamSequence == 0 || d.ConsumerSequence == 0 || d.NumDelivered == 0 {
		return errors.New("NATS dead-letter has incomplete JetStream metadata")
	}
	wantID := rejectionIdentity(d.Stream, d.StreamSequence, d.Subject, d.Reply, d.Headers, d.Data)
	if !validDigestID(d.ID, "tnj1") || d.ID != wantID {
		return fmt.Errorf("NATS dead-letter rejection id mismatch: got %q want %q", d.ID, wantID)
	}
	return nil
}
