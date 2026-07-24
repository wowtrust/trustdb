// Package anchorsystem exposes the mutable discovery and explorer plane for
// configured L5 providers. Immutable proof publication and verification stay
// in package anchor so live provider state can never be mistaken for L5 proof.
package anchorsystem

import (
	"context"
	"sort"
	"strings"

	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

const maxPageSize = 1000

type Provider interface {
	System(context.Context) (model.AnchorSystem, error)
	Status(context.Context) (model.AnchorSystemStatus, error)
	ListResources(context.Context, model.AnchorResourceListOptions) (model.AnchorSystemResourcePage, error)
	Resource(context.Context, string, string) (model.AnchorSystemResource, bool, error)
}

type Service struct {
	providers map[string]Provider
	ids       []string
}

func New(providers ...Provider) (*Service, error) {
	service := &Service{providers: make(map[string]Provider, len(providers))}
	for _, provider := range providers {
		if provider == nil {
			return nil, trusterr.New(trusterr.CodeInvalidArgument, "anchor system provider is required")
		}
		system, err := provider.System(context.Background())
		if err != nil {
			return nil, trusterr.Wrap(trusterr.CodeFailedPrecondition, "describe anchor system", err)
		}
		if err := ValidateSystem(system); err != nil {
			return nil, err
		}
		if _, exists := service.providers[system.SystemID]; exists {
			return nil, trusterr.New(trusterr.CodeInvalidArgument, "duplicate anchor system_id: "+system.SystemID)
		}
		service.providers[system.SystemID] = provider
		service.ids = append(service.ids, system.SystemID)
	}
	sort.Strings(service.ids)
	return service, nil
}

func (s *Service) Systems(ctx context.Context) ([]model.AnchorSystem, error) {
	if s == nil {
		return nil, trusterr.New(trusterr.CodeFailedPrecondition, "anchor system service is not configured")
	}
	items := make([]model.AnchorSystem, 0, len(s.ids))
	for _, id := range s.ids {
		system, err := s.providers[id].System(ctx)
		if err != nil {
			return nil, err
		}
		if err := ValidateSystem(system); err != nil {
			return nil, trusterr.Wrap(trusterr.CodeDataLoss, "invalid anchor system descriptor", err)
		}
		items = append(items, system)
	}
	return items, nil
}

func (s *Service) System(ctx context.Context, systemID string) (model.AnchorSystem, bool, error) {
	provider, ok := s.provider(systemID)
	if !ok {
		return model.AnchorSystem{}, false, nil
	}
	system, err := provider.System(ctx)
	if err != nil {
		return model.AnchorSystem{}, false, err
	}
	if err := ValidateSystem(system); err != nil {
		return model.AnchorSystem{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "invalid anchor system descriptor", err)
	}
	return system, true, nil
}

func (s *Service) Status(ctx context.Context, systemID string) (model.AnchorSystemStatus, bool, error) {
	provider, ok := s.provider(systemID)
	if !ok {
		return model.AnchorSystemStatus{}, false, nil
	}
	status, err := provider.Status(ctx)
	if err != nil {
		return model.AnchorSystemStatus{}, false, err
	}
	if status.SchemaVersion != model.SchemaAnchorSystemStatus || status.SystemID != strings.TrimSpace(systemID) || !validState(status.State) {
		return model.AnchorSystemStatus{}, false, trusterr.New(trusterr.CodeDataLoss, "invalid anchor system status")
	}
	return status, true, nil
}

func (s *Service) Resources(ctx context.Context, systemID string, opts model.AnchorResourceListOptions) (model.AnchorSystemResourcePage, bool, error) {
	provider, ok := s.provider(systemID)
	if !ok {
		return model.AnchorSystemResourcePage{}, false, nil
	}
	if !validResourceKind(opts.Kind) {
		return model.AnchorSystemResourcePage{}, true, trusterr.New(trusterr.CodeInvalidArgument, "resource kind must be node, block, transaction, account, or contract")
	}
	if opts.Limit <= 0 {
		opts.Limit = 100
	}
	if opts.Limit > maxPageSize {
		return model.AnchorSystemResourcePage{}, true, trusterr.New(trusterr.CodeInvalidArgument, "limit must be between 1 and 1000")
	}
	system, err := provider.System(ctx)
	if err != nil {
		return model.AnchorSystemResourcePage{}, true, err
	}
	if !HasCapability(system, capabilityForResource(opts.Kind)) {
		return model.AnchorSystemResourcePage{}, true, trusterr.New(trusterr.CodeFailedPrecondition, "anchor system does not expose "+opts.Kind+" resources")
	}
	page, err := provider.ListResources(ctx, opts)
	if err != nil {
		return model.AnchorSystemResourcePage{}, true, err
	}
	if page.Limit == 0 {
		page.Limit = opts.Limit
	}
	if page.Limit < 1 || page.Limit > opts.Limit || len(page.Resources) > page.Limit {
		return model.AnchorSystemResourcePage{}, true, trusterr.New(trusterr.CodeDataLoss, "invalid anchor system resource page")
	}
	for _, resource := range page.Resources {
		if err := validateResource(resource, system.SystemID, opts.Kind); err != nil {
			return model.AnchorSystemResourcePage{}, true, trusterr.Wrap(trusterr.CodeDataLoss, "invalid anchor system resource", err)
		}
	}
	return page, true, nil
}

func (s *Service) Resource(ctx context.Context, systemID, kind, resourceID string) (model.AnchorSystemResource, bool, error) {
	provider, ok := s.provider(systemID)
	if !ok {
		return model.AnchorSystemResource{}, false, nil
	}
	kind = strings.TrimSpace(kind)
	resourceID = strings.TrimSpace(resourceID)
	if !validResourceKind(kind) || resourceID == "" {
		return model.AnchorSystemResource{}, false, trusterr.New(trusterr.CodeInvalidArgument, "resource kind and resource_id are required")
	}
	system, err := provider.System(ctx)
	if err != nil {
		return model.AnchorSystemResource{}, false, err
	}
	if !HasCapability(system, capabilityForResource(kind)) {
		return model.AnchorSystemResource{}, false, trusterr.New(trusterr.CodeFailedPrecondition, "anchor system does not expose "+kind+" resources")
	}
	resource, found, err := provider.Resource(ctx, kind, resourceID)
	if err != nil || !found {
		return model.AnchorSystemResource{}, found, err
	}
	if err := validateResource(resource, system.SystemID, kind); err != nil {
		return model.AnchorSystemResource{}, false, trusterr.Wrap(trusterr.CodeDataLoss, "invalid anchor system resource", err)
	}
	return resource, true, nil
}

func (s *Service) provider(systemID string) (Provider, bool) {
	if s == nil {
		return nil, false
	}
	provider, ok := s.providers[strings.TrimSpace(systemID)]
	return provider, ok
}

func ValidateSystem(system model.AnchorSystem) error {
	if system.SchemaVersion != model.SchemaAnchorSystem {
		return trusterr.New(trusterr.CodeInvalidArgument, "anchor system schema_version is invalid")
	}
	if !validIdentifier(system.SystemID, 128) || !validIdentifier(system.SinkName, 64) || strings.TrimSpace(system.DisplayName) == "" {
		return trusterr.New(trusterr.CodeInvalidArgument, "anchor system identity fields are required")
	}
	switch system.Kind {
	case model.AnchorSystemKindTimestampEvidence, model.AnchorSystemKindEvidenceBlockchain, model.AnchorSystemKindFullBlockchain:
	default:
		return trusterr.New(trusterr.CodeInvalidArgument, "anchor system kind is invalid")
	}
	seen := make(map[string]struct{}, len(system.Capabilities))
	for _, capability := range system.Capabilities {
		capability = strings.TrimSpace(capability)
		if capability == "" {
			return trusterr.New(trusterr.CodeInvalidArgument, "anchor system capability is empty")
		}
		if _, exists := seen[capability]; exists {
			return trusterr.New(trusterr.CodeInvalidArgument, "anchor system capability is duplicated: "+capability)
		}
		seen[capability] = struct{}{}
	}
	if system.Kind == model.AnchorSystemKindTimestampEvidence && hasAny(seen,
		model.AnchorCapabilityNodeRead, model.AnchorCapabilityBlockRead, model.AnchorCapabilityTransactionRead,
		model.AnchorCapabilityAccountRead, model.AnchorCapabilityContractRead, model.AnchorCapabilityDataSync,
		model.AnchorCapabilityBlockProduce, model.AnchorCapabilityTransactionSend, model.AnchorCapabilityContractCall,
		model.AnchorCapabilityContractDeploy) {
		return trusterr.New(trusterr.CodeInvalidArgument, "timestamp evidence systems cannot advertise blockchain capabilities")
	}
	if system.Kind == model.AnchorSystemKindEvidenceBlockchain && hasAny(seen,
		model.AnchorCapabilityAccountRead, model.AnchorCapabilityContractRead, model.AnchorCapabilityTransactionSend,
		model.AnchorCapabilityContractCall, model.AnchorCapabilityContractDeploy) {
		return trusterr.New(trusterr.CodeInvalidArgument, "evidence blockchains cannot advertise account or contract capabilities")
	}
	return nil
}

func hasAny(values map[string]struct{}, wanted ...string) bool {
	for _, item := range wanted {
		if _, ok := values[item]; ok {
			return true
		}
	}
	return false
}

func validIdentifier(value string, maxLength int) bool {
	if len(value) == 0 || len(value) > maxLength {
		return false
	}
	for index, r := range value {
		letter := r >= 'a' && r <= 'z'
		digit := r >= '0' && r <= '9'
		if index == 0 && !letter && !digit || !letter && !digit && r != '.' && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

func HasCapability(system model.AnchorSystem, wanted string) bool {
	for _, capability := range system.Capabilities {
		if capability == wanted {
			return true
		}
	}
	return false
}

func capabilityForResource(kind string) string {
	switch kind {
	case model.AnchorResourceKindNode:
		return model.AnchorCapabilityNodeRead
	case model.AnchorResourceKindBlock:
		return model.AnchorCapabilityBlockRead
	case model.AnchorResourceKindTransaction:
		return model.AnchorCapabilityTransactionRead
	case model.AnchorResourceKindAccount:
		return model.AnchorCapabilityAccountRead
	case model.AnchorResourceKindContract:
		return model.AnchorCapabilityContractRead
	default:
		return ""
	}
}

func validResourceKind(kind string) bool { return capabilityForResource(strings.TrimSpace(kind)) != "" }

func validState(state string) bool {
	switch state {
	case model.AnchorSystemStateHealthy, model.AnchorSystemStateDegraded, model.AnchorSystemStateUnavailable, model.AnchorSystemStateUnknown:
		return true
	default:
		return false
	}
}

func validateResource(resource model.AnchorSystemResource, systemID, kind string) error {
	if resource.SchemaVersion != model.SchemaAnchorSystemResource || resource.SystemID != systemID || resource.Kind != kind || strings.TrimSpace(resource.ResourceID) == "" {
		return trusterr.New(trusterr.CodeInvalidArgument, "anchor resource binding fields are invalid")
	}
	return nil
}
