package anchorsystem

import (
	"context"
	"time"

	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

// StaticProvider describes built-in sinks that do not expose a chain explorer.
// It still gives SDK/Desktop clients a stable system identity and honest trust
// properties instead of forcing them to infer semantics from sink_name.
type StaticProvider struct {
	Descriptor model.AnchorSystem
	Clock      func() time.Time
}

func (p StaticProvider) System(context.Context) (model.AnchorSystem, error) {
	return p.Descriptor, nil
}

func (p StaticProvider) Status(context.Context) (model.AnchorSystemStatus, error) {
	clock := p.Clock
	if clock == nil {
		clock = time.Now
	}
	return model.AnchorSystemStatus{
		SchemaVersion:   model.SchemaAnchorSystemStatus,
		SystemID:        p.Descriptor.SystemID,
		State:           model.AnchorSystemStateHealthy,
		ObservedAtUnixN: clock().UTC().UnixNano(),
		Message:         "provider is configured",
	}, nil
}

func (p StaticProvider) ListResources(context.Context, model.AnchorResourceListOptions) (model.AnchorSystemResourcePage, error) {
	return model.AnchorSystemResourcePage{}, trusterr.New(trusterr.CodeFailedPrecondition, "anchor system does not expose explorer resources")
}

func (p StaticProvider) Resource(context.Context, string, string) (model.AnchorSystemResource, bool, error) {
	return model.AnchorSystemResource{}, false, trusterr.New(trusterr.CodeFailedPrecondition, "anchor system does not expose explorer resources")
}

func BuiltInDescriptor(sinkName string) model.AnchorSystem {
	system := model.AnchorSystem{
		SchemaVersion: model.SchemaAnchorSystem,
		SystemID:      sinkName,
		SinkName:      sinkName,
		Provider:      "trustdb",
		Capabilities:  []string{model.AnchorCapabilityPublish, model.AnchorCapabilityVerify, model.AnchorCapabilityEvidenceRead, model.AnchorCapabilitySystemStatusRead},
	}
	switch sinkName {
	case "ots":
		system.DisplayName = "OpenTimestamps"
		system.Kind = model.AnchorSystemKindTimestampEvidence
		system.Network = "bitcoin"
		system.Assurance = model.AnchorAssurance{IndependentTime: true, PubliclyVerifiable: true, Decentralized: true, Finality: "probabilistic", Custody: "external"}
	case "file":
		system.DisplayName = "Local anchor file"
		system.Kind = model.AnchorSystemKindTimestampEvidence
		system.Assurance = model.AnchorAssurance{Finality: "local_durable_write", Custody: "operator"}
	case "noop":
		system.DisplayName = "No-op development anchor"
		system.Kind = model.AnchorSystemKindTimestampEvidence
		system.Assurance = model.AnchorAssurance{Finality: "none", Custody: "operator"}
	default:
		system.DisplayName = sinkName
		system.Kind = model.AnchorSystemKindTimestampEvidence
		system.Provider = "external-plugin"
		system.Assurance = model.AnchorAssurance{Finality: "provider_defined", Custody: "external"}
	}
	return system
}
