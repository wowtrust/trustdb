package anchorsystem

import (
	"context"
	"testing"

	"github.com/wowtrust/trustdb/internal/model"
)

type resourceProvider struct{ StaticProvider }

func (p resourceProvider) ListResources(_ context.Context, opts model.AnchorResourceListOptions) (model.AnchorSystemResourcePage, error) {
	return model.AnchorSystemResourcePage{Resources: []model.AnchorSystemResource{{
		SchemaVersion: model.SchemaAnchorSystemResource,
		SystemID:      p.Descriptor.SystemID,
		Kind:          opts.Kind,
		ResourceID:    "node-1",
	}}, Limit: opts.Limit}, nil
}

func (p resourceProvider) Resource(_ context.Context, kind, id string) (model.AnchorSystemResource, bool, error) {
	return model.AnchorSystemResource{SchemaVersion: model.SchemaAnchorSystemResource, SystemID: p.Descriptor.SystemID, Kind: kind, ResourceID: id}, true, nil
}

func TestServiceEnforcesCapabilitiesAndBindings(t *testing.T) {
	descriptor := BuiltInDescriptor("chain-a")
	descriptor.Kind = model.AnchorSystemKindEvidenceBlockchain
	descriptor.Capabilities = append(descriptor.Capabilities, model.AnchorCapabilityNodeRead)
	service, err := New(resourceProvider{StaticProvider{Descriptor: descriptor}})
	if err != nil {
		t.Fatal(err)
	}
	page, found, err := service.Resources(context.Background(), descriptor.SystemID, model.AnchorResourceListOptions{Kind: model.AnchorResourceKindNode, Limit: 10})
	if err != nil || !found || len(page.Resources) != 1 || page.Resources[0].ResourceID != "node-1" {
		t.Fatalf("Resources() page=%+v found=%v err=%v", page, found, err)
	}
	if _, _, err := service.Resources(context.Background(), descriptor.SystemID, model.AnchorResourceListOptions{Kind: model.AnchorResourceKindBlock}); err == nil {
		t.Fatal("Resources(block) succeeded without block.read capability")
	}
}

func TestNewRejectsDuplicateSystemIDs(t *testing.T) {
	provider := StaticProvider{Descriptor: BuiltInDescriptor("ots")}
	if _, err := New(provider, provider); err == nil {
		t.Fatal("New() accepted duplicate system IDs")
	}
}

func TestValidateSystemRejectsCapabilitiesOutsideKind(t *testing.T) {
	system := BuiltInDescriptor("ots")
	system.Capabilities = append(system.Capabilities, model.AnchorCapabilityBlockRead)
	if err := ValidateSystem(system); err == nil {
		t.Fatal("ValidateSystem() accepted block.read on timestamp_evidence")
	}
	system = BuiltInDescriptor("chain-a")
	system.Kind = model.AnchorSystemKindEvidenceBlockchain
	system.Capabilities = append(system.Capabilities, model.AnchorCapabilityContractRead)
	if err := ValidateSystem(system); err == nil {
		t.Fatal("ValidateSystem() accepted contract.read on evidence_blockchain")
	}
}
