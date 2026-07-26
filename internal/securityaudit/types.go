// Package securityaudit implements TrustDB's signed, append-only security
// audit trail. Audit evidence is separate from application logs and business
// proof data: it records privileged control-plane activity and the time state
// observed by the process without changing TrustDB proof semantics.
package securityaudit

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/model"
	"github.com/wowtrust/trustdb/v2/internal/trustcrypto"
)

const (
	EventSchema            = "trustdb.security-audit-event.v1"
	CheckpointSchema       = "trustdb.security-audit-checkpoint.v1"
	ExportSchema           = "trustdb.security-audit-export.v1"
	CheckpointExportSchema = "trustdb.security-audit-checkpoint-export.v1"
	TimeSchema             = "trustdb.time-reference.v1"

	maxRecordBytes  = 256 << 10
	maxContextPairs = 32
	maxRoles        = 16
)

var (
	ErrInvalidEvent       = errors.New("securityaudit: invalid event")
	ErrInvalidCheckpoint  = errors.New("securityaudit: invalid checkpoint")
	ErrInvalidChain       = errors.New("securityaudit: invalid chain")
	ErrRollback           = errors.New("securityaudit: audit rollback or truncation detected")
	ErrCapacity           = errors.New("securityaudit: configured audit capacity exhausted")
	ErrTimeUnsynchronized = errors.New("securityaudit: trusted time requirement is not satisfied")
	ErrUnsafeStorage      = errors.New("securityaudit: unsafe storage")
)

type TimeEvidence struct {
	Source               string `cbor:"source" json:"source"`
	Status               string `cbor:"status" json:"status"`
	Confidence           string `cbor:"confidence" json:"confidence"`
	Synchronized         bool   `cbor:"synchronized" json:"synchronized"`
	OffsetNanos          int64  `cbor:"offset_nanos" json:"offset_nanos"`
	UncertaintyNanos     int64  `cbor:"uncertainty_nanos" json:"uncertainty_nanos"`
	ReferenceSampleUnixN int64  `cbor:"reference_sample_unix_nano" json:"reference_sample_unix_nano"`
	SampleAgeNanos       int64  `cbor:"sample_age_nanos" json:"sample_age_nanos"`
}

type Draft struct {
	Actor         string
	Roles         []string
	Action        string
	Object        string
	Result        string
	RequestID     string
	Source        string
	PolicyVersion uint64
	Context       map[string]string
}

type Event struct {
	SchemaVersion      string            `cbor:"schema_version" json:"schema_version"`
	CryptoSuite        cryptosuite.ID    `cbor:"crypto_suite" json:"crypto_suite"`
	Sequence           uint64            `cbor:"sequence" json:"sequence"`
	EventID            string            `cbor:"event_id" json:"event_id"`
	PreviousHash       []byte            `cbor:"previous_hash" json:"previous_hash"`
	Actor              string            `cbor:"actor" json:"actor"`
	Roles              []string          `cbor:"roles,omitempty" json:"roles,omitempty"`
	Action             string            `cbor:"action" json:"action"`
	Object             string            `cbor:"object" json:"object"`
	Result             string            `cbor:"result" json:"result"`
	RequestID          string            `cbor:"request_id" json:"request_id"`
	Source             string            `cbor:"source" json:"source"`
	PolicyVersion      uint64            `cbor:"policy_version" json:"policy_version"`
	LocalTimeUnixNano  int64             `cbor:"local_time_unix_nano" json:"local_time_unix_nano"`
	Time               TimeEvidence      `cbor:"time" json:"time"`
	RetentionUntilUnix int64             `cbor:"retention_until_unix_nano" json:"retention_until_unix_nano"`
	Context            map[string]string `cbor:"context,omitempty" json:"context,omitempty"`
}

type SignedEvent struct {
	Event     Event           `cbor:"event" json:"event"`
	EventHash []byte          `cbor:"event_hash" json:"event_hash"`
	Signature model.Signature `cbor:"signature" json:"signature"`
}

type Checkpoint struct {
	SchemaVersion string         `cbor:"schema_version" json:"schema_version"`
	CryptoSuite   cryptosuite.ID `cbor:"crypto_suite" json:"crypto_suite"`
	Sequence      uint64         `cbor:"sequence" json:"sequence"`
	EventHash     []byte         `cbor:"event_hash" json:"event_hash"`
	LogBytes      int64          `cbor:"log_bytes" json:"log_bytes"`
	CreatedUnixN  int64          `cbor:"created_unix_nano" json:"created_unix_nano"`
}

type SignedCheckpoint struct {
	Checkpoint Checkpoint      `cbor:"checkpoint" json:"checkpoint"`
	Signature  model.Signature `cbor:"signature" json:"signature"`
}

type CheckpointArtifact struct {
	SchemaVersion string                          `json:"schema_version"`
	PublicKey     trustcrypto.PublicKeyDescriptor `json:"public_key"`
	Checkpoint    SignedCheckpoint                `json:"checkpoint"`
}

type Stats struct {
	Sequence  uint64         `json:"sequence"`
	EventHash []byte         `json:"event_hash"`
	LogBytes  int64          `json:"log_bytes"`
	Suite     cryptosuite.ID `json:"crypto_suite"`
}

type Recorder interface {
	Record(context.Context, Draft) (SignedEvent, error)
}

func sanitizeDraft(d Draft) (Draft, error) {
	d.Actor = cleanValue(d.Actor, 256)
	d.Action = cleanIdentifier(d.Action, 128)
	d.Object = cleanValue(d.Object, 512)
	d.Result = cleanIdentifier(d.Result, 64)
	d.RequestID = cleanValue(d.RequestID, 256)
	d.Source = cleanIdentifier(d.Source, 128)
	if d.Actor == "" || d.Action == "" || d.Object == "" || d.Result == "" || d.Source == "" {
		return Draft{}, fmt.Errorf("%w: actor, action, object, result, and source are required", ErrInvalidEvent)
	}
	if d.RequestID == "" {
		d.RequestID = "none"
	}
	if len(d.Roles) > maxRoles {
		return Draft{}, fmt.Errorf("%w: too many roles", ErrInvalidEvent)
	}
	roles := make([]string, 0, len(d.Roles))
	seenRoles := make(map[string]struct{}, len(d.Roles))
	for _, role := range d.Roles {
		role = cleanIdentifier(role, 128)
		if role == "" {
			return Draft{}, fmt.Errorf("%w: invalid role", ErrInvalidEvent)
		}
		if _, exists := seenRoles[role]; exists {
			continue
		}
		seenRoles[role] = struct{}{}
		roles = append(roles, role)
	}
	sort.Strings(roles)
	if len(roles) == 0 {
		d.Roles = nil
	} else {
		d.Roles = roles
	}
	if len(d.Context) > maxContextPairs {
		return Draft{}, fmt.Errorf("%w: too many context fields", ErrInvalidEvent)
	}
	contextValues := make(map[string]string, len(d.Context))
	for key, value := range d.Context {
		key = cleanIdentifier(strings.ToLower(key), 128)
		if key == "" {
			return Draft{}, fmt.Errorf("%w: invalid context key", ErrInvalidEvent)
		}
		if sensitiveKey(key) {
			contextValues[key] = "<redacted>"
			continue
		}
		contextValues[key] = cleanValue(value, 512)
	}
	if len(contextValues) == 0 {
		d.Context = nil
	} else {
		d.Context = contextValues
	}
	return d, nil
}

func cleanIdentifier(value string, max int) string {
	value = strings.TrimSpace(value)
	if value == "" || !utf8.ValidString(value) || len(value) > max {
		return ""
	}
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("._:/@+-", r) {
			continue
		}
		return ""
	}
	return value
}

func cleanValue(value string, max int) string {
	value = strings.TrimSpace(value)
	if value == "" || !utf8.ValidString(value) || len(value) > max {
		return ""
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return ""
		}
	}
	return value
}

func sensitiveKey(key string) bool {
	for _, fragment := range []string{"password", "secret", "token", "private", "credential", "cookie", "authorization", "payload", "content"} {
		if strings.Contains(key, fragment) {
			return true
		}
	}
	return false
}
