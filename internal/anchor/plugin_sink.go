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
	return model.STHAnchorResult{
		AnchorID:         result.AnchorID,
		Proof:            append([]byte(nil), result.Proof...),
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
