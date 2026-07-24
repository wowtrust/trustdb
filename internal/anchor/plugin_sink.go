package anchor

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/sdk/anchorplugin"
)

type PluginSinkOptions struct {
	Command      string
	Args         []string
	StartTimeout time.Duration
	RPCTimeout   time.Duration
}

type pluginProcess interface {
	Info() anchorplugin.GetInfoResponse
	Publish(context.Context, anchorplugin.SignedTreeHead) (anchorplugin.AnchorResult, error)
	Verify(context.Context, anchorplugin.SignedTreeHead, anchorplugin.AnchorResult) error
	Close() error
}

type pluginExplorerProcess interface {
	Status(context.Context) (anchorplugin.SystemStatus, error)
	ListResources(context.Context, anchorplugin.ListResourcesRequest) (anchorplugin.ListResourcesResponse, error)
	Resource(context.Context, string, string) (anchorplugin.Resource, bool, error)
}

type pluginProcessFactory func(context.Context, anchorplugin.ProcessConfig) (pluginProcess, error)

// PluginSink adapts a supervised subprocess to the built-in Sink contract.
// A transient RPC failure invalidates the current child so the durable anchor
// worker's next retry starts a fresh process.
type PluginSink struct {
	opts    PluginSinkOptions
	factory pluginProcessFactory

	mu      sync.Mutex
	process pluginProcess
	name    string
	system  model.AnchorSystem
	closed  bool
}

func NewPluginSink(ctx context.Context, opts PluginSinkOptions) (*PluginSink, error) {
	return newPluginSink(ctx, opts, func(ctx context.Context, cfg anchorplugin.ProcessConfig) (pluginProcess, error) {
		return anchorplugin.StartProcess(ctx, cfg)
	})
}

func newPluginSink(ctx context.Context, opts PluginSinkOptions, factory pluginProcessFactory) (*PluginSink, error) {
	if strings.TrimSpace(opts.Command) == "" {
		return nil, fmt.Errorf("anchor plugin command is required")
	}
	sink := &PluginSink{opts: opts, factory: factory}
	process, err := sink.start(ctx)
	if err != nil {
		return nil, err
	}
	sink.process = process
	sink.name = process.Info().SinkName
	sink.system = pluginSystem(process.Info())
	if isBuiltInSinkName(sink.name) {
		_ = process.Close()
		return nil, fmt.Errorf("anchor plugin sink_name %q conflicts with a built-in sink", sink.name)
	}
	return sink, nil
}

func (s *PluginSink) Name() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.name
}

func (s *PluginSink) Publish(ctx context.Context, sth model.SignedTreeHead) (model.STHAnchorResult, error) {
	process, err := s.getProcess(ctx)
	if err != nil {
		return model.STHAnchorResult{}, err
	}
	result, err := process.Publish(ctx, pluginSTH(sth))
	if err != nil {
		if anchorplugin.IsPermanentRPC(err) {
			return model.STHAnchorResult{}, fmt.Errorf("%w: anchor plugin publish: %v", ErrPermanent, err)
		}
		s.invalidate(process)
		return model.STHAnchorResult{}, fmt.Errorf("anchor plugin publish: %w", err)
	}
	if err := process.Verify(ctx, pluginSTH(sth), result); err != nil {
		if anchorplugin.IsPermanentRPC(err) {
			return model.STHAnchorResult{}, fmt.Errorf("%w: anchor plugin verify after publish: %v", ErrPermanent, err)
		}
		s.invalidate(process)
		return model.STHAnchorResult{}, fmt.Errorf("anchor plugin verify after publish: %w", err)
	}
	return model.STHAnchorResult{
		AnchorID:         result.AnchorID,
		Proof:            append([]byte(nil), result.Proof...),
		EvidenceStage:    model.AnchorEvidenceStageOfflineVerified,
		PublishedAtUnixN: result.PublishedAtUnixN,
	}, nil
}

// VerifyAnchor implements verify.AnchorVerifier without importing the verify
// package and therefore keeps the existing anchor -> verify dependency acyclic.
func (s *PluginSink) VerifyAnchor(sth model.SignedTreeHead, result model.STHAnchorResult) error {
	if result.SinkName != s.Name() {
		return fmt.Errorf("anchor plugin %q cannot verify sink %q", s.Name(), result.SinkName)
	}
	process, err := s.getProcess(context.Background())
	if err != nil {
		return err
	}
	err = process.Verify(context.Background(), pluginSTH(sth), anchorplugin.AnchorResult{
		AnchorID:         result.AnchorID,
		Proof:            append([]byte(nil), result.Proof...),
		PublishedAtUnixN: result.PublishedAtUnixN,
	})
	if err != nil {
		if !anchorplugin.IsPermanentRPC(err) {
			s.invalidate(process)
		}
		return fmt.Errorf("anchor plugin verify: %w", err)
	}
	return nil
}

// System implements anchorsystem.Provider without coupling the immutable
// anchor worker to the mutable explorer service. Legacy plugins receive an
// honest timestamp-evidence descriptor with no explorer capabilities.
func (s *PluginSink) System(context.Context) (model.AnchorSystem, error) {
	s.mu.Lock()
	system := s.system
	s.mu.Unlock()
	system.Capabilities = append([]string(nil), system.Capabilities...)
	system.Metadata = cloneStringMap(system.Metadata)
	return system, nil
}

func (s *PluginSink) Status(ctx context.Context) (model.AnchorSystemStatus, error) {
	process, err := s.getProcess(ctx)
	if err != nil {
		return model.AnchorSystemStatus{}, err
	}
	explorer, ok := process.(pluginExplorerProcess)
	if !ok || !pluginHasCapability(process.Info(), anchorplugin.CapabilitySystemStatusRead) {
		return model.AnchorSystemStatus{}, fmt.Errorf("anchor plugin does not expose system status")
	}
	value, err := explorer.Status(ctx)
	if err != nil {
		return model.AnchorSystemStatus{}, fmt.Errorf("anchor plugin status: %w", err)
	}
	return model.AnchorSystemStatus{
		SchemaVersion:   model.SchemaAnchorSystemStatus,
		SystemID:        s.systemID(),
		State:           value.State,
		ObservedAtUnixN: value.ObservedAtUnixN,
		Message:         value.Message,
		Details:         cloneStringMap(value.Details),
	}, nil
}

func (s *PluginSink) ListResources(ctx context.Context, opts model.AnchorResourceListOptions) (model.AnchorSystemResourcePage, error) {
	process, err := s.getProcess(ctx)
	if err != nil {
		return model.AnchorSystemResourcePage{}, err
	}
	explorer, ok := process.(pluginExplorerProcess)
	if !ok {
		return model.AnchorSystemResourcePage{}, fmt.Errorf("anchor plugin does not expose explorer resources")
	}
	response, err := explorer.ListResources(ctx, anchorplugin.ListResourcesRequest{Kind: opts.Kind, Limit: opts.Limit, Cursor: opts.Cursor})
	if err != nil {
		return model.AnchorSystemResourcePage{}, fmt.Errorf("anchor plugin list resources: %w", err)
	}
	systemID := s.systemID()
	items := make([]model.AnchorSystemResource, 0, len(response.Resources))
	for _, resource := range response.Resources {
		items = append(items, pluginResource(systemID, resource))
	}
	return model.AnchorSystemResourcePage{Resources: items, Limit: response.Limit, NextCursor: response.NextCursor}, nil
}

func (s *PluginSink) Resource(ctx context.Context, kind, resourceID string) (model.AnchorSystemResource, bool, error) {
	process, err := s.getProcess(ctx)
	if err != nil {
		return model.AnchorSystemResource{}, false, err
	}
	explorer, ok := process.(pluginExplorerProcess)
	if !ok {
		return model.AnchorSystemResource{}, false, fmt.Errorf("anchor plugin does not expose explorer resources")
	}
	resource, found, err := explorer.Resource(ctx, kind, resourceID)
	if err != nil || !found {
		return model.AnchorSystemResource{}, found, err
	}
	return pluginResource(s.systemID(), resource), true, nil
}

func (s *PluginSink) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	process := s.process
	s.process = nil
	s.mu.Unlock()
	if process != nil {
		return process.Close()
	}
	return nil
}

func (s *PluginSink) getProcess(ctx context.Context) (pluginProcess, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, fmt.Errorf("anchor plugin sink is closed")
	}
	if s.process != nil {
		return s.process, nil
	}
	process, err := s.start(ctx)
	if err != nil {
		return nil, err
	}
	if process.Info().SinkName != s.name {
		_ = process.Close()
		return nil, fmt.Errorf("anchor plugin changed sink_name across restart: got %q want %q", process.Info().SinkName, s.name)
	}
	if got := pluginSystem(process.Info()).SystemID; got != s.system.SystemID {
		_ = process.Close()
		return nil, fmt.Errorf("anchor plugin changed system_id across restart: got %q want %q", got, s.system.SystemID)
	}
	s.process = process
	return process, nil
}

func (s *PluginSink) start(ctx context.Context) (pluginProcess, error) {
	return s.factory(ctx, anchorplugin.ProcessConfig{
		Command:      s.opts.Command,
		Args:         append([]string(nil), s.opts.Args...),
		StartTimeout: s.opts.StartTimeout,
		RPCTimeout:   s.opts.RPCTimeout,
	})
}

func (s *PluginSink) systemID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.system.SystemID
}

func pluginSystem(info anchorplugin.GetInfoResponse) model.AnchorSystem {
	system := model.AnchorSystem{
		SchemaVersion: model.SchemaAnchorSystem,
		SystemID:      info.SinkName,
		SinkName:      info.SinkName,
		DisplayName:   info.SinkName,
		Kind:          model.AnchorSystemKindTimestampEvidence,
		Provider:      "external-plugin",
		Capabilities:  []string{model.AnchorCapabilityPublish, model.AnchorCapabilityVerify, model.AnchorCapabilityEvidenceRead},
		Assurance:     model.AnchorAssurance{Finality: "provider_defined", Custody: "external"},
	}
	if info.System == nil {
		return system
	}
	provided := info.System
	if strings.TrimSpace(provided.SystemID) != "" {
		system.SystemID = strings.TrimSpace(provided.SystemID)
	}
	if strings.TrimSpace(provided.DisplayName) != "" {
		system.DisplayName = strings.TrimSpace(provided.DisplayName)
	}
	if strings.TrimSpace(provided.Kind) != "" {
		system.Kind = strings.TrimSpace(provided.Kind)
	}
	system.Network = strings.TrimSpace(provided.Network)
	if strings.TrimSpace(provided.Provider) != "" {
		system.Provider = strings.TrimSpace(provided.Provider)
	}
	system.Assurance = model.AnchorAssurance{
		IndependentTime:    provided.Assurance.IndependentTime,
		PubliclyVerifiable: provided.Assurance.PubliclyVerifiable,
		Decentralized:      provided.Assurance.Decentralized,
		Finality:           provided.Assurance.Finality,
		Custody:            provided.Assurance.Custody,
	}
	system.Metadata = cloneStringMap(provided.Metadata)
	for _, capability := range provided.Capabilities {
		if capability != anchorplugin.CapabilityPublish && capability != anchorplugin.CapabilityVerify && !containsString(system.Capabilities, capability) {
			system.Capabilities = append(system.Capabilities, capability)
		}
	}
	return system
}

func pluginResource(systemID string, resource anchorplugin.Resource) model.AnchorSystemResource {
	return model.AnchorSystemResource{
		SchemaVersion:  model.SchemaAnchorSystemResource,
		SystemID:       systemID,
		Kind:           resource.Kind,
		ResourceID:     resource.ResourceID,
		ParentID:       resource.ParentID,
		Hash:           resource.Hash,
		Status:         resource.Status,
		Height:         resource.Height,
		TimestampUnixN: resource.TimestampUnixN,
		Summary:        resource.Summary,
		Attributes:     cloneStringMap(resource.Attributes),
	}
}

func pluginHasCapability(info anchorplugin.GetInfoResponse, wanted string) bool {
	for _, capability := range info.Capabilities {
		if capability == wanted {
			return true
		}
	}
	return false
}

func containsString(items []string, wanted string) bool {
	for _, item := range items {
		if item == wanted {
			return true
		}
	}
	return false
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func (s *PluginSink) invalidate(process pluginProcess) {
	s.mu.Lock()
	if s.process == process {
		s.process = nil
	}
	s.mu.Unlock()
	_ = process.Close()
}

func pluginSTH(sth model.SignedTreeHead) anchorplugin.SignedTreeHead {
	return anchorplugin.SignedTreeHead{
		SchemaVersion:  sth.SchemaVersion,
		TreeAlg:        sth.TreeAlg,
		TreeSize:       sth.TreeSize,
		RootHash:       append([]byte(nil), sth.RootHash...),
		TimestampUnixN: sth.TimestampUnixN,
		NodeID:         sth.NodeID,
		LogID:          sth.LogID,
		Signature: anchorplugin.Signature{
			Alg:       sth.Signature.Alg,
			KeyID:     sth.Signature.KeyID,
			Signature: append([]byte(nil), sth.Signature.Signature...),
		},
	}
}

func isBuiltInSinkName(name string) bool {
	switch name {
	case FileSinkName, NoopSinkName, OtsSinkName:
		return true
	default:
		return false
	}
}
