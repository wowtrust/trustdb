//go:build e2e

package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/anchor"
	"github.com/wowtrust/trustdb/internal/app"
	"github.com/wowtrust/trustdb/internal/batch"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/globallog"
	"github.com/wowtrust/trustdb/internal/grpcapi"
	"github.com/wowtrust/trustdb/internal/httpapi"
	"github.com/wowtrust/trustdb/internal/ingest"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/observability"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"github.com/wowtrust/trustdb/internal/wal"
	"github.com/wowtrust/trustdb/sdk"
	"google.golang.org/grpc"
)

func TestHTTPAndGRPCTransportsShareProofSemantics(t *testing.T) {
	env := newTransportE2EEnv(t)

	httpClient, err := sdk.NewClient(env.httpURL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer httpClient.Close()
	grpcClient, err := sdk.NewGRPCClient(env.grpcTarget, sdk.WithGRPCLocalPlaintext())
	if err != nil {
		t.Fatalf("NewGRPCClient: %v", err)
	}
	defer grpcClient.Close()

	if status := httpClient.CheckHealth(context.Background()); !status.OK {
		t.Fatalf("http health = %+v", status)
	}
	if status := grpcClient.CheckHealth(context.Background()); !status.OK {
		t.Fatalf("grpc health = %+v", status)
	}

	tests := []struct {
		name       string
		submitWith *sdk.Client
		proofWith  *sdk.Client
		payload    []byte
	}{
		{
			name:       "http submit grpc proof",
			submitWith: httpClient,
			proofWith:  grpcClient,
			payload:    []byte("http submitted payload, grpc verified proof"),
		},
		{
			name:       "grpc submit http proof",
			submitWith: grpcClient,
			proofWith:  httpClient,
			payload:    []byte("grpc submitted payload, http verified proof"),
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := tt.submitWith.SubmitFile(context.Background(), bytes.NewReader(tt.payload), env.identity, sdk.FileClaimOptions{
				ProducedAt:     time.Unix(int64(1700+i), 0),
				Nonce:          bytes.Repeat([]byte{byte(i + 1)}, 16),
				IdempotencyKey: fmt.Sprintf("transport-e2e-%d", i),
				MediaType:      "text/plain",
				StorageURI:     fmt.Sprintf("file:///transport-e2e-%d.txt", i),
				EventType:      "file.snapshot",
				Source:         "transport-e2e",
			})
			if err != nil {
				t.Fatalf("SubmitFile: %v", err)
			}
			if res.RecordID == "" || !res.BatchEnqueued {
				t.Fatalf("submit result = %+v", res)
			}

			artifacts := waitForProofArtifactsLevel(t, tt.proofWith, res.RecordID, sdk.ProofLevelL4)
			if artifacts.GlobalProof == nil {
				t.Fatalf("proof artifacts missing global proof: %+v", artifacts)
			}
			if artifacts.AnchorResult != nil {
				t.Fatalf("local-only sink unexpectedly produced offline anchor evidence: %+v", artifacts.AnchorResult)
			}
			if artifacts.GlobalProof.BatchID != artifacts.Bundle.CommittedReceipt.BatchID {
				t.Fatalf("global proof batch_id = %q, bundle batch_id = %q",
					artifacts.GlobalProof.BatchID,
					artifacts.Bundle.CommittedReceipt.BatchID,
				)
			}

			verified, err := sdk.VerifyArtifacts(bytes.NewReader(tt.payload), artifacts, sdk.TrustedKeys{
				ClientPublicKey: env.clientPub,
				ServerPublicKey: env.serverPub,
			}, sdk.VerifyOptions{})
			if err != nil {
				t.Fatalf("VerifyArtifacts: %v", err)
			}
			if !verified.Valid || verified.ProofLevel != sdk.ProofLevelL4 || verified.RecordID != res.RecordID {
				t.Fatalf("verify result = %+v", verified)
			}

			record, err := tt.proofWith.GetRecord(context.Background(), res.RecordID)
			if err != nil {
				t.Fatalf("GetRecord opposite transport: %v", err)
			}
			if record.RecordID != res.RecordID || record.BatchID == "" {
				t.Fatalf("record index = %+v", record)
			}
		})
	}
}

type transportE2EEnv struct {
	httpURL    string
	grpcTarget string
	identity   sdk.Identity
	clientPub  sdk.KeyDescriptor
	serverPub  sdk.KeyDescriptor
}

func newTransportE2EEnv(t *testing.T) transportE2EEnv {
	t.Helper()

	clientPub, clientPriv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key client: %v", err)
	}
	serverPub, serverPriv, err := trustcrypto.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key server: %v", err)
	}
	identity, err := sdk.NewINTLV1Identity(
		"tenant-transport",
		"client-transport",
		"client-key",
		clientPriv,
	)
	if err != nil {
		t.Fatalf("NewINTLV1Identity: %v", err)
	}
	clientDescriptor, err := sdk.NewINTLV1PublicKey("client-key", clientPub)
	if err != nil {
		t.Fatalf("NewINTLV1PublicKey client: %v", err)
	}
	serverDescriptor, err := sdk.NewINTLV1PublicKey("server-key", serverPub)
	if err != nil {
		t.Fatalf("NewINTLV1PublicKey server: %v", err)
	}

	tmp := t.TempDir()
	walPath := filepath.Join(tmp, "wal")
	writer, _, err := openWALWriterWithOptions(walPath, newBoundTestWALOptions(t, walPath, wal.Options{}))
	if err != nil {
		t.Fatalf("openWALWriterWithOptions: %v", err)
	}
	t.Cleanup(func() { _ = writer.Close() })

	_, metrics := observability.NewRegistry()
	engine := app.LocalEngine{
		ServerID:        "server-transport-e2e",
		LogID:           "server-transport-e2e",
		ServerKeyID:     "server-key",
		ClientPublicKey: trustcrypto.MustNewEd25519PublicKey("", clientPub),
		ServerSigner:    trustcrypto.MustNewEd25519Signer("server-key", serverPriv),
		WAL:             writer,
		Idempotency:     app.NewIdempotencyIndex(),
		Now:             func() time.Time { return time.Now().UTC() },
	}
	proofStore := newBoundTestLocalStore(t, filepath.Join(tmp, "proofs"))
	ingestSvc := ingest.New(engine, ingest.Options{QueueSize: 16, Workers: 2}, metrics)
	t.Cleanup(func() { ingestSvc.Shutdown(context.Background()) })

	anchorKey := model.STHAnchorScheduleKey{
		NodeID: engine.ServerID, LogID: engine.ServerID, SinkName: anchor.NoopSinkName,
	}
	anchorSvc, err := anchor.NewService(anchor.Config{
		Sink:         anchor.NewNoopSink(),
		Store:        proofStore,
		Key:          anchorKey,
		Metrics:      metrics,
		PollInterval: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("anchor.NewService: %v", err)
	}
	anchorSvc.Start(context.Background())
	t.Cleanup(anchorSvc.Stop)

	rt := &runtimeConfig{logger: silentLogger()}
	globalSvc, err := globallog.New(globallog.Options{
		Store:  proofStore,
		NodeID: engine.ServerID,
		LogID:  engine.ServerID,
		Signer: trustcrypto.MustNewEd25519Signer(engine.ServerKeyID, serverPriv),
	})
	if err != nil {
		t.Fatalf("globallog.New: %v", err)
	}
	globalOutbox := globallog.NewOutboxWorker(globallog.OutboxConfig{
		Store:          proofStore,
		Global:         globalSvc,
		AnchorKey:      &anchorKey,
		AnchorMaxDelay: 20 * time.Millisecond,
		OnAnchorReady:  anchorSvc.Trigger,
		PollInterval:   20 * time.Millisecond,
	})
	globalOutbox.Start(context.Background())
	t.Cleanup(globalOutbox.Stop)

	batchSvc := batch.New(engine, proofStore, batch.Options{CryptoSuite: cryptosuite.INTLV1,
		QueueSize:        16,
		MaxRecords:       1,
		MaxDelay:         20 * time.Millisecond,
		OnBatchCommitted: newGlobalLogEnqueueHook(rt, proofStore, globalOutbox),
	}, metrics)
	t.Cleanup(func() { _ = batchSvc.Shutdown(context.Background()) })

	anchorAPI := anchor.NewAPI(proofStore)
	httpServer := httptest.NewServer(httpapi.NewWithGlobalAndAnchors(ingestSvc, nil, batchSvc, globalSvc, anchorAPI))
	t.Cleanup(httpServer.Close)

	grpcListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen grpc: %v", err)
	}
	grpcServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(grpcapi.MaxMessageBytes),
		grpc.MaxSendMsgSize(grpcapi.MaxMessageBytes),
	)
	grpcapi.RegisterTrustDBServiceServer(grpcServer, grpcapi.NewServer(ingestSvc, batchSvc, globalSvc, anchorAPI, nil))
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- grpcServer.Serve(grpcListener)
	}()
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = grpcListener.Close()
		select {
		case err := <-serveErr:
			if err != nil && err != grpc.ErrServerStopped {
				t.Fatalf("grpc serve: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("grpc server did not stop")
		}
	})

	return transportE2EEnv{
		httpURL:    httpServer.URL,
		grpcTarget: grpcListener.Addr().String(),
		identity:   identity,
		clientPub:  clientDescriptor,
		serverPub:  serverDescriptor,
	}
}

func waitForProofArtifactsLevel(t *testing.T, client *sdk.Client, recordID, wantLevel string) sdk.ProofArtifacts {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var (
		lastArtifacts sdk.ProofArtifacts
		lastErr       error
	)
	for time.Now().Before(deadline) {
		bundle, err := client.GetProofBundle(context.Background(), recordID)
		if err != nil {
			lastErr = err
			time.Sleep(20 * time.Millisecond)
			continue
		}
		lastArtifacts.Bundle = bundle
		evidence, err := client.GetGlobalEvidence(context.Background(), bundle.CommittedReceipt.BatchID)
		if err != nil {
			lastErr = err
			time.Sleep(20 * time.Millisecond)
			continue
		}
		lastArtifacts.GlobalProof = &evidence.GlobalProof
		lastArtifacts.AnchorResult = evidence.AnchorResult
		if evidence.AnchorResult != nil && wantLevel == sdk.ProofLevelL5 {
			return lastArtifacts
		}
		if wantLevel != sdk.ProofLevelL5 {
			return lastArtifacts
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("proof artifacts for %s never reached %s; last_record=%q global=%v anchor=%v last_err=%v",
		recordID,
		wantLevel,
		lastArtifacts.Bundle.RecordID,
		lastArtifacts.GlobalProof != nil,
		lastArtifacts.AnchorResult != nil,
		lastErr,
	)
	return sdk.ProofArtifacts{}
}
