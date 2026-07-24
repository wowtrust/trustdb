package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/wowtrust/trustdb/internal/anchor"
	"github.com/wowtrust/trustdb/internal/anchor/fiscobcos"
	"github.com/wowtrust/trustdb/internal/anchor/fiscobcos/standardsdk"
	trustconfig "github.com/wowtrust/trustdb/internal/config"
	"github.com/wowtrust/trustdb/internal/wal"
	"github.com/wowtrust/trustdb/sdk/signerplugin"
)

// newTestRuntime returns a runtimeConfig minimal enough to drive the
// build helpers without touching the filesystem-rooted PersistentPreRunE
// path. The logger discards everything because none of these tests
// inspect log output.
func newTestRuntime(t *testing.T) *runtimeConfig {
	t.Helper()
	rt := &runtimeConfig{}
	return rt
}

// TestNewOtsSinkFromParams_AcceptsDefaults ensures that an empty
// otsSinkParams yields a usable sink (falls back to the public
// calendar pool and library defaults) — this is the config path
// exercised when the operator simply sets --anchor-sink=ots.
func TestNewOtsSinkFromParams_AcceptsDefaults(t *testing.T) {
	t.Parallel()

	sink, err := newOtsSinkFromParams(otsSinkParams{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sink == nil {
		t.Fatal("expected non-nil sink")
	}
	if got := sink.Name(); got != anchor.OtsSinkName {
		t.Fatalf("unexpected sink name %q, want %q", got, anchor.OtsSinkName)
	}
	if cals := sink.Calendars(); len(cals) == 0 {
		t.Fatalf("expected default calendars to be populated, got 0")
	}
}

// TestNewOtsSinkFromParams_RejectsNegativeMinAccepted guards the
// user-facing flag; accepting a negative value would silently degrade
// the quorum policy to "any single calendar suffices".
func TestNewOtsSinkFromParams_RejectsNegativeMinAccepted(t *testing.T) {
	t.Parallel()

	_, err := newOtsSinkFromParams(otsSinkParams{MinAccepted: -1})
	if err == nil {
		t.Fatal("expected error for negative MinAccepted")
	}
	if !strings.Contains(err.Error(), "anchor-ots-min-accepted") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestNewOtsSinkFromParams_RejectsBadTimeout ensures the shared
// time.ParseDuration error surface propagates through a wrapped
// trusterr so startup fails fast instead of silently using 0s.
func TestNewOtsSinkFromParams_RejectsBadTimeout(t *testing.T) {
	t.Parallel()

	_, err := newOtsSinkFromParams(otsSinkParams{TimeoutText: "not-a-duration"})
	if err == nil {
		t.Fatal("expected error for invalid timeout text")
	}
	if !strings.Contains(err.Error(), "anchor-ots-timeout") {
		t.Fatalf("unexpected error: %v", err)
	}
}

type testFISCOBCOSFactory struct {
	trust         fiscobcos.TrustConfig
	accountSigner standardsdk.AccountSigner
	drivers       []*testFISCOBCOSDriver
}

func (f *testFISCOBCOSFactory) NewDrivers(_ context.Context, config standardsdk.Config) ([]fiscobcos.Driver, error) {
	f.trust = config.TrustConfig
	f.accountSigner = config.AccountSigner
	out := make([]fiscobcos.Driver, 0, len(config.TrustConfig.Endpoints))
	for _, endpoint := range config.TrustConfig.Endpoints {
		driver := &testFISCOBCOSDriver{endpoint: endpoint}
		f.drivers = append(f.drivers, driver)
		out = append(out, driver)
	}
	return out, nil
}

type testFISCOBCOSDriver struct {
	endpoint string
	closed   bool
}

func (d *testFISCOBCOSDriver) Endpoint() string { return d.endpoint }
func (*testFISCOBCOSDriver) ProbeChain(context.Context) (fiscobcos.ChainProbe, error) {
	return fiscobcos.ChainProbe{}, nil
}
func (*testFISCOBCOSDriver) SubmitAnchor(context.Context, fiscobcos.SubmitRequest) (fiscobcos.Submission, error) {
	return fiscobcos.Submission{}, nil
}
func (*testFISCOBCOSDriver) ReadAnchor(context.Context, []byte) (fiscobcos.AnchorRecord, error) {
	return fiscobcos.AnchorRecord{}, nil
}
func (*testFISCOBCOSDriver) GetReceiptWithProof(context.Context, fiscobcos.TransactionSubmission) (fiscobcos.ReceiptWithProof, error) {
	return fiscobcos.ReceiptWithProof{}, nil
}
func (*testFISCOBCOSDriver) GetBlockHeader(context.Context, uint64) (fiscobcos.BlockHeader, error) {
	return fiscobcos.BlockHeader{}, nil
}
func (*testFISCOBCOSDriver) GetConsensusSnapshot(context.Context, uint64) (fiscobcos.ConsensusSnapshot, error) {
	return fiscobcos.ConsensusSnapshot{}, nil
}
func (d *testFISCOBCOSDriver) Close() error { d.closed = true; return nil }

func TestNewFISCOBCOSStandardSinkFromCentralConfig(t *testing.T) {
	t.Parallel()

	trust := testFISCOBCOSTrust(t)
	data, err := fiscobcos.MarshalTrustConfig(trust)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "fisco-bcos-trust.cbor")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	factory := &testFISCOBCOSFactory{}
	sink, signerCloser, err := newFISCOBCOSStandardSinkFromParams(context.Background(), nil, zerolog.Nop(), fiscoBCOSSinkParams{
		TrustConfigFile: path,
		Factory:         factory,
	})
	if err != nil {
		t.Fatalf("newFISCOBCOSStandardSinkFromParams() error = %v", err)
	}
	if sink.Name() != fiscobcos.SinkName || factory.trust.ChainID != trust.ChainID || len(factory.drivers) != 2 {
		t.Fatalf("central config did not reach native driver factory: sink=%q trust=%+v drivers=%d", sink.Name(), factory.trust, len(factory.drivers))
	}
	if signerCloser != nil || factory.accountSigner != nil {
		t.Fatal("software account unexpectedly used an injected signer provider")
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	for _, driver := range factory.drivers {
		if !driver.closed {
			t.Fatal("sink shutdown did not close a native driver")
		}
	}
}

func testFISCOBCOSTrust(t *testing.T) fiscobcos.TrustConfig {
	t.Helper()
	trust, err := fiscobcos.NewTrustConfig(fiscobcos.CryptoModeStandard)
	if err != nil {
		t.Fatal(err)
	}
	trust.ChainID = "chain0"
	trust.GroupID = "group0"
	trust.GenesisHash = bytes.Repeat([]byte{0x01}, 32)
	trust.TrustedCheckpoint = fiscobcos.BlockCheckpoint{BlockNumber: 100, BlockHash: bytes.Repeat([]byte{0x02}, 32)}
	trust.Contract = fiscobcos.ContractBinding{
		Address: bytes.Repeat([]byte{0x03}, 20), CodeHash: bytes.Repeat([]byte{0x04}, 32),
		ProtocolVersion: fiscobcos.TrustDBAnchorV1ProtocolVersion,
		EventSignature:  fiscobcos.TrustDBAnchorV1EventSignature,
	}
	trust.Endpoints = []string{"127.0.0.1:20200", "127.0.0.1:20201"}
	trust.ReadQuorum = 2
	trust.AccountProvider = fiscobcos.AccountProviderConfig{
		Provider: "software", KeyID: "publisher", KeyReference: "/run/trustdb/publisher.key",
		Algorithm: fiscobcos.StandardAccountAlg,
	}
	trust.Certificates = fiscobcos.CertificateConfig{
		TransportMode:               fiscobcos.StandardTransport,
		TrustedCAReferences:         []string{"/etc/trustdb/ca.crt"},
		TrustedCACertificateHashes:  [][]byte{bytes.Repeat([]byte{0x05}, 32)},
		ClientSigningCertificateRef: "/etc/trustdb/sdk.crt",
		ClientSigningKeyRef:         "/run/trustdb/sdk.key",
	}
	for _, id := range []string{"validator-a", "validator-b", "validator-c", "validator-d"} {
		trust.Validators = append(trust.Validators, fiscobcos.ValidatorDescriptor{
			NodeID: id, Algorithm: fiscobcos.StandardAccountAlg,
			PublicKeyEncoding: fiscobcos.StandardKeyEncoding,
			PublicKey:         append([]byte{0x04}, bytes.Repeat([]byte{byte(len(id))}, 64)...),
		})
	}
	return trust
}

type testBCOSAccountSigner struct {
	closed bool
}

func (*testBCOSAccountSigner) PublicKey(context.Context) ([]byte, error) {
	return append([]byte{0x04}, bytes.Repeat([]byte{0x11}, 64)...), nil
}

func (*testBCOSAccountSigner) SignDigest(context.Context, []byte) ([]byte, error) {
	signature := bytes.Repeat([]byte{0x22}, 65)
	signature[64] = 1
	return signature, nil
}

func (s *testBCOSAccountSigner) Close() error { s.closed = true; return nil }

func TestNewFISCOBCOSStandardSinkInjectsNonExportableSigner(t *testing.T) {
	t.Parallel()

	trust := testFISCOBCOSTrust(t)
	trust.AccountProvider = fiscobcos.AccountProviderConfig{
		Provider: "remote", KeyID: "publisher",
		KeyReference: `{"endpoint":"https://signer.example/v1","handle":"bcos-publisher","credential_ref":"vault://bcos-token"}`,
		Algorithm:    fiscobcos.StandardAccountAlg,
	}
	data, err := fiscobcos.MarshalTrustConfig(trust)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "fisco-bcos-trust.cbor")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	factory := &testFISCOBCOSFactory{}
	accountSigner := &testBCOSAccountSigner{}
	builderCalled := false
	builder := func(_ context.Context, account fiscobcos.AccountProviderConfig, _ trustconfig.SignerPlugins, _ io.Writer) (standardsdk.AccountSigner, io.Closer, error) {
		builderCalled = true
		if account.Provider != "remote" || account.KeyID != "publisher" {
			t.Fatalf("builder account = %+v", account)
		}
		return accountSigner, accountSigner, nil
	}
	sink, signerCloser, err := newFISCOBCOSStandardSinkFromParams(context.Background(), nil, zerolog.Nop(), fiscoBCOSSinkParams{
		TrustConfigFile: path,
		Factory:         factory,
		SignerBuilder:   builder,
	})
	if err != nil {
		t.Fatalf("newFISCOBCOSStandardSinkFromParams() error = %v", err)
	}
	if !builderCalled || factory.accountSigner != accountSigner || signerCloser != accountSigner {
		t.Fatal("non-exportable account signer was not passed to the native driver factory")
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	if err := signerCloser.Close(); err != nil {
		t.Fatal(err)
	}
	if !accountSigner.closed {
		t.Fatal("account signer provider was not closed")
	}
}

func TestLoadCanonicalFISCOBCOSTrustConfigRejectsUnsafePath(t *testing.T) {
	t.Parallel()

	trust := testFISCOBCOSTrust(t)
	data, err := fiscobcos.MarshalTrustConfig(trust)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	path := filepath.Join(root, "trust.cbor")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCanonicalFISCOBCOSTrustConfig("relative/trust.cbor"); err == nil {
		t.Fatal("relative TrustConfig path was accepted")
	}
	dirty := root + string(os.PathSeparator) + "nested" + string(os.PathSeparator) + ".." + string(os.PathSeparator) + filepath.Base(path)
	if _, err := loadCanonicalFISCOBCOSTrustConfig(dirty); err == nil {
		t.Fatal("non-clean absolute TrustConfig path was accepted")
	}
	if runtime.GOOS != "windows" {
		link := filepath.Join(root, "trust-link.cbor")
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		if _, err := loadCanonicalFISCOBCOSTrustConfig(link); err == nil {
			t.Fatal("symlinked TrustConfig was accepted")
		}
	}
}

func TestFISCOBCOSPluginKeyBindsProviderAndCanonicalReference(t *testing.T) {
	t.Parallel()

	info := signerplugin.GetInfoResponse{
		ProtocolVersion: signerplugin.ProtocolVersion,
		PluginID:        "remote-bcos-signer",
		ProviderKind:    signerplugin.ProviderRemote,
		Capabilities: []string{
			signerplugin.CapabilityHealth,
			signerplugin.CapabilityPublicKey,
			signerplugin.CapabilitySign,
		},
		Algorithms: []signerplugin.AlgorithmCapability{{
			CryptoSuite:       signerplugin.SuiteFISCOBCOSStandard,
			Algorithm:         signerplugin.AlgorithmSecp256k1,
			PublicKeyEncoding: signerplugin.Secp256k1PublicKeyEncoding,
			SignatureEncoding: signerplugin.Secp256k1SignatureEncoding,
		}},
		MaxConcurrentSigns: 1,
	}
	account := fiscobcos.AccountProviderConfig{
		Provider:     signerplugin.ProviderRemote,
		KeyID:        "publisher",
		KeyReference: `{"endpoint":"https://signer.example/v1","handle":"bcos-publisher","credential_ref":"vault://bcos-token"}`,
		Algorithm:    fiscobcos.StandardAccountAlg,
	}
	key, err := fiscoBCOSPluginKey(account, info)
	if err != nil {
		t.Fatalf("fiscoBCOSPluginKey() error = %v", err)
	}
	if key.Binding.PluginID != info.PluginID || key.Reference.Remote == nil ||
		key.Reference.Remote.Handle != "bcos-publisher" {
		t.Fatalf("plugin key = %+v", key)
	}
	account.KeyReference = `{"handle":"bcos-publisher","endpoint":"https://signer.example/v1","credential_ref":"vault://bcos-token"}`
	if _, err := fiscoBCOSPluginKey(account, info); err == nil {
		t.Fatal("non-canonical provider reference was accepted")
	}
}

func TestServeDurationFlagBounds(t *testing.T) {
	t.Parallel()

	if got, err := parseNonNegativeDurationFlag("read-header-timeout", "0s"); err != nil || got != 0 {
		t.Fatalf("parse zero non-negative duration = %v err=%v, want 0 nil", got, err)
	}
	if _, err := parseNonNegativeDurationFlag("idle-timeout", "-1s"); err == nil || !strings.Contains(err.Error(), "--idle-timeout") {
		t.Fatalf("negative idle-timeout error = %v, want flag error", err)
	}
	if got, err := parsePositiveDurationFlag("batch-max-delay", "5ms"); err != nil || got != 5*time.Millisecond {
		t.Fatalf("parse positive duration = %v err=%v, want 5ms nil", got, err)
	}
	if _, err := parsePositiveDurationFlag("batch-max-delay", "0s"); err == nil || !strings.Contains(err.Error(), "--batch-max-delay") {
		t.Fatalf("zero batch-max-delay error = %v, want flag error", err)
	}
	if got, err := parseWALGroupCommitInterval(wal.FsyncGroup, "10ms"); err != nil || got != 10*time.Millisecond {
		t.Fatalf("parse WAL group interval = %v err=%v, want 10ms nil", got, err)
	}
	for _, value := range []string{"0s", "-1ms"} {
		if _, err := parseWALGroupCommitInterval(wal.FsyncGroup, value); err == nil || !strings.Contains(err.Error(), "--wal-group-commit-interval") {
			t.Fatalf("WAL group interval %q error = %v, want flag error", value, err)
		}
	}
	for _, mode := range []string{wal.FsyncStrict, wal.FsyncBatch} {
		if got, err := parseWALGroupCommitInterval(mode, "0s"); err != nil || got != 10*time.Millisecond {
			t.Fatalf("inactive WAL group interval for %s = %v err=%v, want normalized 10ms nil", mode, got, err)
		}
	}
}

// TestNewOtsSinkFromParams_PropagatesOptions verifies non-default
// options flow into the sink, keeping the flag-to-sink plumbing
// honest if OtsSinkOptions is extended later.
func TestNewOtsSinkFromParams_PropagatesOptions(t *testing.T) {
	t.Parallel()

	sink, err := newOtsSinkFromParams(otsSinkParams{
		Calendars:   []string{"https://example.test/"},
		MinAccepted: 1,
		TimeoutText: "5s",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cals := sink.Calendars()
	if len(cals) != 1 || cals[0] != "https://example.test" {
		t.Fatalf("unexpected calendars %v", cals)
	}
	// Timeout / MinAccepted aren't exposed on OtsSink, so we settle
	// for asserting the constructor accepted them without error. A
	// regression in wiring would have to round-trip through the
	// integration tests in internal/anchor.
	_ = time.Second
}

// TestBuildOtsUpgrader_NilForNonOtsSink documents the central
// conditional in the wire-up: the upgrader is only relevant when
// the configured anchor sink is OpenTimestamps. Returning nil keeps
// serve_cmd's start path simple (`if u != nil { u.Start() }`).
func TestBuildOtsUpgrader_NilForNonOtsSink(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	store := newBoundTestLocalStore(t, filepath.Join(tmp, "ps"))
	defer store.Close()
	rt := newTestRuntime(t)

	for _, kind := range []string{"", "off", "file", "noop", "FILE"} {
		u, err := buildOtsUpgrader(rt, store, nil, kind, otsUpgraderParams{Enabled: true})
		if err != nil {
			t.Fatalf("kind=%q unexpected err: %v", kind, err)
		}
		if u != nil {
			t.Fatalf("kind=%q expected nil upgrader, got %#v", kind, u)
		}
	}
}

// TestBuildOtsUpgrader_DisabledByFlag covers the explicit opt-out
// path: even when the sink is ots, --anchor-ots-upgrade-enabled=false
// must produce a nil upgrader so serve never starts the worker.
func TestBuildOtsUpgrader_DisabledByFlag(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	store := newBoundTestLocalStore(t, filepath.Join(tmp, "ps"))
	defer store.Close()

	u, err := buildOtsUpgrader(newTestRuntime(t), store, nil, "ots", otsUpgraderParams{Enabled: false})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if u != nil {
		t.Fatal("expected nil upgrader when disabled")
	}
}

// TestBuildOtsUpgrader_BuildsWhenEnabled exercises the success path:
// sink=ots + enabled => non-nil upgrader, defaults applied.
func TestBuildOtsUpgrader_BuildsWhenEnabled(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	store := newBoundTestLocalStore(t, filepath.Join(tmp, "ps"))
	defer store.Close()

	u, err := buildOtsUpgrader(newTestRuntime(t), store, nil, "OPENTIMESTAMPS", otsUpgraderParams{
		Enabled:      true,
		IntervalText: "30m",
		BatchSize:    32,
		TimeoutText:  "15s",
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if u == nil {
		t.Fatal("expected non-nil upgrader")
	}
	// Lifecycle smoke: Start/Stop must not panic with the resulting
	// configuration even though we never actually fire a tick.
	u.Stop()
}

// TestBuildOtsUpgrader_RejectsBadDuration ensures invalid duration
// strings fail startup fast instead of silently using zero.
func TestBuildOtsUpgrader_RejectsBadDuration(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	store := newBoundTestLocalStore(t, filepath.Join(tmp, "ps"))
	defer store.Close()

	cases := []struct {
		name   string
		params otsUpgraderParams
		want   string
	}{
		{"interval-bad", otsUpgraderParams{Enabled: true, IntervalText: "weekly"}, "anchor-ots-upgrade-interval"},
		{"interval-zero", otsUpgraderParams{Enabled: true, IntervalText: "0s"}, "anchor-ots-upgrade-interval"},
		{"timeout-bad", otsUpgraderParams{Enabled: true, TimeoutText: "🍩"}, "anchor-ots-upgrade-timeout"},
		{"timeout-zero", otsUpgraderParams{Enabled: true, TimeoutText: "0s"}, "anchor-ots-upgrade-timeout"},
		{"batch-negative", otsUpgraderParams{Enabled: true, BatchSize: -1}, "anchor-ots-upgrade-batch-size"},
		{"batch-too-large", otsUpgraderParams{Enabled: true, BatchSize: anchor.MaxOtsUpgradeBatchSize + 1}, "anchor-ots-upgrade-batch-size"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := buildOtsUpgrader(newTestRuntime(t), store, nil, "ots", tc.params)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q must mention %q", err.Error(), tc.want)
			}
		})
	}
}
