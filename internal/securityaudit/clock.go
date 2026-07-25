package securityaudit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

type Clock interface {
	Sample(context.Context) (time.Time, TimeEvidence, error)
}

type ClockOptions struct {
	ReferencePath       string
	MaxSampleAge        time.Duration
	MaxClockDrift       time.Duration
	RequireSynchronized bool
	Now                 func() time.Time
}

type ReferenceSample struct {
	SchemaVersion     string `json:"schema_version"`
	Source            string `json:"source"`
	SampledAtUnixNano int64  `json:"sampled_at_unix_nano"`
	OffsetNanos       int64  `json:"offset_nanos"`
	UncertaintyNanos  int64  `json:"uncertainty_nanos"`
	Synchronized      bool   `json:"synchronized"`
	Confidence        string `json:"confidence"`
}

type referenceClock struct{ opts ClockOptions }

func NewClock(opts ClockOptions) (Clock, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.MaxSampleAge <= 0 {
		opts.MaxSampleAge = 2 * time.Minute
	}
	if opts.MaxClockDrift <= 0 {
		opts.MaxClockDrift = 5 * time.Second
	}
	if opts.RequireSynchronized && strings.TrimSpace(opts.ReferencePath) == "" {
		return nil, fmt.Errorf("%w: reference path is required", ErrTimeUnsynchronized)
	}
	return &referenceClock{opts: opts}, nil
}

func (c *referenceClock) Sample(ctx context.Context) (time.Time, TimeEvidence, error) {
	if err := ctx.Err(); err != nil {
		return time.Time{}, TimeEvidence{}, err
	}
	now := c.opts.Now().UTC()
	if strings.TrimSpace(c.opts.ReferencePath) == "" {
		evidence := TimeEvidence{Source: "system-clock", Status: "unverified", Confidence: "local", Synchronized: false}
		if c.opts.RequireSynchronized {
			return now, evidence, ErrTimeUnsynchronized
		}
		return now, evidence, nil
	}
	data, err := readProtectedFile(c.opts.ReferencePath, 64<<10)
	if err != nil {
		evidence := TimeEvidence{Source: "configured-reference", Status: "unavailable", Confidence: "none"}
		if c.opts.RequireSynchronized {
			return now, evidence, fmt.Errorf("%w: %v", ErrTimeUnsynchronized, err)
		}
		return now, evidence, nil
	}
	var sample ReferenceSample
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&sample); err != nil {
		return now, TimeEvidence{}, fmt.Errorf("decode trusted time sample: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return now, TimeEvidence{}, errors.New("decode trusted time sample: trailing JSON")
	}
	if err := validateReferenceSample(sample); err != nil {
		return now, TimeEvidence{}, err
	}
	age := now.Sub(time.Unix(0, sample.SampledAtUnixNano).UTC())
	evidence := TimeEvidence{
		Source: sample.Source, Confidence: sample.Confidence, Synchronized: sample.Synchronized,
		OffsetNanos: sample.OffsetNanos, UncertaintyNanos: sample.UncertaintyNanos,
		ReferenceSampleUnixN: sample.SampledAtUnixNano, SampleAgeNanos: age.Nanoseconds(), Status: "synchronized",
	}
	if age < 0 || age > c.opts.MaxSampleAge {
		evidence.Status = "stale"
		evidence.Synchronized = false
	}
	if driftExceeded(sample.OffsetNanos, sample.UncertaintyNanos, c.opts.MaxClockDrift.Nanoseconds()) {
		evidence.Status = "drift-exceeded"
		evidence.Synchronized = false
	}
	if !sample.Synchronized {
		evidence.Status = "unsynchronized"
	}
	if sample.Confidence == "local" {
		evidence.Status = "unverified"
		evidence.Synchronized = false
	}
	if c.opts.RequireSynchronized && !evidence.Synchronized {
		return now, evidence, fmt.Errorf("%w: time status %s", ErrTimeUnsynchronized, evidence.Status)
	}
	return now, evidence, nil
}

func validateReferenceSample(sample ReferenceSample) error {
	if sample.SchemaVersion != TimeSchema {
		return fmt.Errorf("trusted time schema must be %q", TimeSchema)
	}
	if cleanIdentifier(sample.Source, 128) == "" || sample.Source == "system-clock" || sample.Source == "configured-reference" || sample.SampledAtUnixNano <= 0 {
		return errors.New("trusted time source and sampled_at_unix_nano are required")
	}
	if sample.UncertaintyNanos < 0 {
		return errors.New("trusted time uncertainty_nanos must not be negative")
	}
	switch sample.Confidence {
	case "authenticated", "network", "hardware", "local":
	default:
		return errors.New("trusted time confidence is unsupported")
	}
	return nil
}

func WriteReferenceSample(path string, sample ReferenceSample) error {
	if err := validateReferenceSample(sample); err != nil {
		return err
	}
	data, err := json.MarshalIndent(sample, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeProtectedAtomic(path, data)
}

func readProtectedFile(path string, maxBytes int64) ([]byte, error) {
	file, err := openProtectedExisting(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("protected file exceeds %d bytes", maxBytes)
	}
	return data, nil
}

func driftExceeded(offset, uncertainty, limit int64) bool {
	if uncertainty < 0 || limit <= 0 || uncertainty > limit {
		return true
	}
	remaining := limit - uncertainty
	return offset > remaining || offset < -remaining
}
